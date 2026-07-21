// Package hnsanchor supplies DS trust anchors read from the local Handshake
// root, for use as the AnchorFunc of internal/vdoh.
//
// The anchor is the root of all trust in that validator: it is what decides
// which zone keys may sign. If an attacker can influence the anchor, validating
// signatures against it proves nothing. So the constraints here are enforced by
// the type, not left to the caller to honour:
//
//   - There is no parameter for a recursive or DoH endpoint. The only address
//     this package will talk to is a loopback hnsd root socket, checked at
//     construction. It is structurally incapable of sourcing an anchor from the
//     network.
//   - It refuses to answer at all unless the local hnsd reports a synced chain,
//     so a partially-synced node cannot yield an anchor that merely looks
//     absent.
//   - It answers only for a single-label Handshake root such as "pirate.".
//     Deeper zones need a delegation chain walk, which the validator does not
//     do, so returning an anchor for one would invite an unsound proof.
//   - Nothing is cached. A cache would have to be invalidated on chain reorgs
//     and on sync-state transitions; getting that wrong means serving an anchor
//     from a chain state that no longer exists. Queries are to loopback and
//     cheap, so the safe choice costs little.
package hnsanchor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pirate-social-club/fingertipd/internal/netutil"

	"github.com/pirate-social-club/fingertipd/internal/vdoh"
)

// defaultTimeout bounds a single loopback query. The root server is local; a
// slow answer means something is wrong, not that we should wait longer.
const defaultTimeout = 3 * time.Second

// ErrNotSynced is returned while the local chain is still catching up. It is
// deliberately distinct from "no anchor": an unsynced node knows nothing, which
// is not the same as knowing a zone is unsigned.
var ErrNotSynced = errors.New("hnsanchor: local hnsd is not synced")

// Provider reads DS anchors from a loopback hnsd root server.
type Provider struct {
	rootAddr string
	timeout  time.Duration
}

// New returns a Provider bound to a loopback hnsd root address.
//
// There is deliberately no variant accepting a remote address. If a future
// caller needs one, that is a design conversation, not a parameter.
func New(rootAddr string) (*Provider, error) {
	if err := netutil.LoopbackHostPort(rootAddr); err != nil {
		return nil, fmt.Errorf("hnsanchor: root address %w", err)
	}
	return &Provider{rootAddr: rootAddr, timeout: defaultTimeout}, nil
}

func newID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// query performs one loopback exchange and checks that the reply answers the
// question that was asked. The root server is local and trusted to be ours, but
// a stray or replayed datagram must still not be able to substitute records.
func (p *Provider) query(ctx context.Context, name string, qclass, qtype uint16) (*dns.Msg, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	m.Id = id
	m.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: qclass}}
	m.RecursionDesired = false

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	exchange := func(network string) (*dns.Msg, error) {
		c := &dns.Client{Net: network, Timeout: p.timeout}
		r, _, err := c.ExchangeContext(ctx, m, p.rootAddr)
		return r, err
	}

	r, err := exchange("udp")
	if err != nil {
		return nil, fmt.Errorf("hnsanchor: query %s: %w", name, err)
	}
	if r.Truncated {
		if r, err = exchange("tcp"); err != nil {
			return nil, fmt.Errorf("hnsanchor: truncated query %s over tcp: %w", name, err)
		}
	}

	if !r.Response {
		return nil, errors.New("hnsanchor: message is not a response")
	}
	if r.Opcode != dns.OpcodeQuery {
		return nil, fmt.Errorf("hnsanchor: unexpected opcode %s", dns.OpcodeToString[r.Opcode])
	}
	if r.Id != m.Id {
		return nil, fmt.Errorf("hnsanchor: response id %d does not match query id %d", r.Id, m.Id)
	}
	if len(r.Question) != 1 {
		return nil, fmt.Errorf("hnsanchor: response carries %d questions, want 1", len(r.Question))
	}
	q, want := r.Question[0], m.Question[0]
	if !strings.EqualFold(q.Name, want.Name) || q.Qtype != want.Qtype || q.Qclass != want.Qclass {
		return nil, fmt.Errorf("hnsanchor: response answers %s/%d/%d, asked %s/%d/%d",
			q.Name, q.Qclass, q.Qtype, want.Name, want.Qclass, want.Qtype)
	}
	if r.Truncated {
		return nil, errors.New("hnsanchor: response still truncated over tcp")
	}
	return r, nil
}

// Synced reports whether the local hnsd considers its chain synced, via hnsd's
// Hesiod (HS class) status API, which the root server answers for local
// connections only.
func (p *Provider) Synced(ctx context.Context) (bool, error) {
	r, err := p.query(ctx, "synced.chain.hnsd.", dns.ClassHESIOD, dns.TypeTXT)
	if err != nil {
		return false, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return false, fmt.Errorf("hnsanchor: sync status query returned %s", dns.RcodeToString[r.Rcode])
	}
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok || txt.Hdr.Class != dns.ClassHESIOD {
			continue
		}
		for _, v := range txt.Txt {
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				return true, nil
			}
		}
	}
	return false, nil
}

// isSingleLabelRoot reports whether name is a Handshake root such as "pirate.".
func isSingleLabelRoot(name string) bool {
	fqdn := dns.Fqdn(strings.TrimSpace(name))
	if fqdn == "." {
		return false
	}
	return len(dns.SplitDomainName(fqdn)) == 1
}

// Anchor implements vdoh.AnchorFunc.
//
// It returns only IN DS records owned by exactly the requested root. A zone with
// no DS is reported as vdoh.ErrInsecure rather than as an empty success, so a
// caller cannot mistake "unsigned" for "nothing to check".
func (p *Provider) Anchor(ctx context.Context, zone string) ([]*dns.DS, error) {
	if !isSingleLabelRoot(zone) {
		// The validator anchors at the top level only. Handing back an anchor for
		// a deeper zone would let it build a proof it is not equipped to make.
		return nil, fmt.Errorf("%w: %q is not a single-label Handshake root", vdoh.ErrInsecure, zone)
	}
	root := dns.Fqdn(zone)

	synced, err := p.Synced(ctx)
	if err != nil {
		return nil, fmt.Errorf("hnsanchor: sync check: %w", err)
	}
	if !synced {
		// Failing here rather than returning no anchor keeps "still catching up"
		// distinguishable from "this root is unsigned".
		return nil, ErrNotSynced
	}

	r, err := p.query(ctx, root, dns.ClassINET, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("hnsanchor: DS query for %s returned %s", root, dns.RcodeToString[r.Rcode])
	}

	var out []*dns.DS
	// The root server answers DS from the chain in either section depending on
	// how it frames the delegation, so both are considered -- but only records
	// that are exactly an IN DS owned by the requested root are accepted.
	for _, rr := range append(append([]dns.RR{}, r.Answer...), r.Ns...) {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		if ds.Hdr.Rrtype != dns.TypeDS || ds.Hdr.Class != dns.ClassINET {
			continue
		}
		if !strings.EqualFold(dns.Fqdn(ds.Hdr.Name), root) {
			continue
		}
		out = append(out, ds)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no DS published on chain for %s", vdoh.ErrInsecure, root)
	}
	return out, nil
}
