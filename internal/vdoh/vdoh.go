// Package vdoh implements letsdane's resolver.Resolver over DNS-over-HTTPS with
// local, top-level anchored RRset validation.
//
// SCOPE, deliberately narrow: this is NOT full DNSSEC validation. It proves one
// thing well -- that an RRset was signed by a key the Handshake chain's DS
// anchor commits to, for a zone anchored at the top level. It does not walk a
// delegation chain, and it does not prove negative answers. Those are refused,
// not approximated, so the boundary stays honest until that work exists. Do not
// describe this as "DNSSEC validation" in configuration, docs or release notes.
//
// It exists because letsdane's own stub resolver cannot safely be pointed at a
// remote DoH endpoint:
//
//   - it sends EDNS with DO=false, so a resolver is not obliged to return the
//     RRSIG/NSEC material validation needs, yet it sets AuthenticatedData=true
//     on the query and then caches entries as `secure: r.AuthenticatedData` --
//     i.e. it trusts the resolver's AD bit;
//   - its Verify hook receives only the response message, with no question
//     context and no chain, so it cannot check response identity or build a
//     chain of trust;
//   - its DoH transport appends "/dns-query" to the configured value, so a
//     fully-qualified endpoint URL would be requested as "/dns-query/dns-query".
//
// Those are safe against a loopback hnsd, which validates for itself. They are
// not safe against a remote endpoint. This package therefore does the whole job
// locally and never consults the AD bit at all: `secure` is true only when this
// code has verified a signature chain from an anchor obtained from the local
// Handshake root.
//
// The DoH endpoint is untrusted encrypted transport. It is not an authority.
//
// ANCHOR PROVIDER CONTRACT: the AnchorFunc supplied at wiring time must read
// only synced loopback Handshake root state. It must never be sourced from
// recursive or DoH data -- that would make the endpoint the origin of its own
// trust anchor and defeat the entire package.
package vdoh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// maxResponseBytes bounds a DoH response body. A resolver we do not trust must
// not be able to make us buffer without limit.
const maxResponseBytes = 64 << 10

// ErrInsecure is returned when an answer cannot be proven with the local chain.
// Callers must treat it as fatal: there is no "use it anyway" path.
var ErrInsecure = errors.New("vdoh: answer could not be validated")

// AnchorFunc returns the DS records for a zone as published on the Handshake
// chain, obtained locally (hnsd). This is the trust anchor; it must never come
// from the DoH endpoint.
type AnchorFunc func(ctx context.Context, zone string) ([]*dns.DS, error)

// Resolver is a letsdane resolver.Resolver backed by a DoH endpoint.
type Resolver struct {
	// Endpoint is the complete DoH URL, used verbatim. Unlike letsdane's stub
	// this appends nothing: callers configure the real endpoint, including its
	// path, and get exactly that request.
	Endpoint string

	// Anchor supplies chain-derived DS records. Required.
	Anchor AnchorFunc

	// HTTP is the client used for endpoint requests. Optional.
	HTTP *http.Client

	// Now is overridable for tests; signature validity is checked against it.
	Now func() time.Time
}

// ValidateEndpoint checks a DoH endpoint URL without needing an anchor, so a
// misconfiguration can be rejected at flag-parse time rather than after the
// process has started subsystems.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("vdoh: invalid endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("vdoh: endpoint must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("vdoh: endpoint has no host")
	}
	// Require an explicit path. The common mistake this guards against is
	// configuring an origin and assuming "/dns-query" is appended, which is what
	// letsdane's stub does and this package deliberately does not.
	if u.Path == "" || u.Path == "/" {
		return errors.New("vdoh: endpoint must include the query path, e.g. https://host/dns-query")
	}
	return nil
}

// New validates configuration up front so a misconfigured endpoint fails at
// startup rather than silently on the first lookup.
func New(endpoint string, anchor AnchorFunc) (*Resolver, error) {
	if anchor == nil {
		return nil, errors.New("vdoh: anchor function is required")
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return &Resolver{Endpoint: endpoint, Anchor: anchor}, nil
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) httpClient() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// newID returns a cryptographically random message ID. A predictable ID would
// let an off-path attacker pre-craft a matching response.
func newID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// exchange performs one DoH query and checks that the response actually answers
// the question that was asked.
func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	m.Id = id
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	// DO=true: without it the endpoint is under no obligation to return the
	// RRSIG/NSEC records validation depends on.
	m.SetEdns0(4096, true)
	// Deliberately NOT setting AuthenticatedData: we neither ask for nor honour
	// the AD bit. Trust comes from signatures we verify ourselves.

	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	// POST keeps the question out of the request URI, so it does not land in
	// endpoint access or proxy error logs.
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vdoh: endpoint returned HTTP %d", resp.StatusCode)
	}
	// Require the DoH media type. A response of any other type is not a DNS
	// message we asked for, whatever its bytes happen to unpack as.
	ctype := resp.Header.Get("content-type")
	if mediaType, _, err := mime.ParseMediaType(ctype); err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("vdoh: endpoint returned content-type %q, want application/dns-message", ctype)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("vdoh: response exceeds maximum size")
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("vdoh: malformed response: %w", err)
	}

	// Message-level checks first: reject anything that is not a response to a
	// query before looking at any record it carries.
	if !out.Response {
		return nil, errors.New("vdoh: message is not a response")
	}
	if out.Opcode != dns.OpcodeQuery {
		return nil, fmt.Errorf("vdoh: unexpected opcode %s", dns.OpcodeToString[out.Opcode])
	}

	// Response identity. An endpoint that answers a different question, or
	// replays another exchange, must not be able to substitute records.
	if out.Id != m.Id {
		return nil, fmt.Errorf("vdoh: response id %d does not match query id %d", out.Id, m.Id)
	}
	if len(out.Question) != 1 {
		return nil, fmt.Errorf("vdoh: response carries %d questions, want 1", len(out.Question))
	}
	q, want := out.Question[0], m.Question[0]
	if !strings.EqualFold(q.Name, want.Name) || q.Qtype != want.Qtype || q.Qclass != want.Qclass {
		return nil, fmt.Errorf("vdoh: response answers %s/%d, asked %s/%d",
			q.Name, q.Qtype, want.Name, want.Qtype)
	}
	if out.Truncated {
		return nil, errors.New("vdoh: response truncated")
	}
	return out, nil
}

// rrset returns the records of one type from the answer section, and the RRSIGs
// covering that type.
func rrset(msg *dns.Msg, name string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var records []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		if !strings.EqualFold(rr.Header().Name, dns.Fqdn(name)) {
			continue
		}
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == qtype {
				sigs = append(sigs, v)
			}
		default:
			if rr.Header().Rrtype == qtype {
				records = append(records, rr)
			}
		}
	}
	return records, sigs
}

// zoneOf returns the signing zone this package can anchor: the last label.
// Deeper delegations need a full chain walk, which validateRRSet refuses rather
// than approximates.
func zoneOf(name string) string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	if len(labels) == 0 {
		return "."
	}
	return dns.Fqdn(labels[len(labels)-1])
}

// validatedKeys fetches the zone's DNSKEY set and proves it against the
// chain-supplied DS anchor.
func (r *Resolver) validatedKeys(ctx context.Context, zone string) (map[uint16]*dns.DNSKEY, error) {
	anchors, err := r.Anchor(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("vdoh: anchor lookup for %s: %w", zone, err)
	}
	if len(anchors) == 0 {
		// An unsigned or missing delegation is not an error to be tolerated: we
		// cannot prove anything about the zone, so nothing from it is usable.
		return nil, fmt.Errorf("%w: no DS anchor published for %s", ErrInsecure, zone)
	}
	// The anchor is the root of all trust here, so its shape is checked rather
	// than assumed. A DS for some other owner would otherwise let a provider bug
	// authorise keys for a zone the chain never delegated.
	for _, ds := range anchors {
		if ds == nil {
			return nil, fmt.Errorf("%w: anchor for %s contains a nil DS", ErrInsecure, zone)
		}
		if ds.Hdr.Rrtype != dns.TypeDS {
			return nil, fmt.Errorf("%w: anchor for %s contains record type %s, want DS", ErrInsecure, zone, dns.TypeToString[ds.Hdr.Rrtype])
		}
		if ds.Hdr.Class != dns.ClassINET {
			return nil, fmt.Errorf("%w: anchor for %s contains class %d, want IN", ErrInsecure, zone, ds.Hdr.Class)
		}
		if !strings.EqualFold(dns.Fqdn(ds.Hdr.Name), dns.Fqdn(zone)) {
			return nil, fmt.Errorf("%w: anchor returned DS owned by %q for zone %q", ErrInsecure, ds.Hdr.Name, zone)
		}
	}

	msg, err := r.exchange(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keysRR, sigs := rrset(msg, zone, dns.TypeDNSKEY)
	if len(keysRR) == 0 {
		return nil, fmt.Errorf("%w: no DNSKEY returned for %s", ErrInsecure, zone)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: DNSKEY set for %s carries no RRSIG", ErrInsecure, zone)
	}

	byTag := make(map[uint16]*dns.DNSKEY, len(keysRR))
	for _, rr := range keysRR {
		if k, ok := rr.(*dns.DNSKEY); ok {
			byTag[k.KeyTag()] = k
		}
	}

	// A key is only usable once some DS anchor commits to it.
	var anchored []*dns.DNSKEY
	for _, ds := range anchors {
		k, ok := byTag[ds.KeyTag]
		if !ok {
			continue
		}
		computed := k.ToDS(ds.DigestType)
		if computed == nil {
			continue
		}
		if strings.EqualFold(computed.Digest, ds.Digest) && computed.Algorithm == ds.Algorithm {
			anchored = append(anchored, k)
		}
	}
	if len(anchored) == 0 {
		return nil, fmt.Errorf("%w: no DNSKEY for %s matches the chain DS anchor", ErrInsecure, zone)
	}

	// The DNSKEY RRset must itself be signed by an anchored key, or an attacker
	// could append extra keys alongside the genuine anchored one.
	if err := r.verifySigs(keysRR, sigs, zone, anchoredMap(anchored)); err != nil {
		return nil, fmt.Errorf("%w: DNSKEY set for %s: %v", ErrInsecure, zone, err)
	}
	return byTag, nil
}

func anchoredMap(keys []*dns.DNSKEY) map[uint16]*dns.DNSKEY {
	m := make(map[uint16]*dns.DNSKEY, len(keys))
	for _, k := range keys {
		m[k.KeyTag()] = k
	}
	return m
}

// verifySigs requires at least one RRSIG over the RRset that is currently valid
// and verifies under one of the supplied keys.
func (r *Resolver) verifySigs(records []dns.RR, sigs []*dns.RRSIG, zone string, keys map[uint16]*dns.DNSKEY) error {
	now := r.now()
	var lastErr error
	for _, sig := range sigs {
		// The signer must be the zone we anchored. Accepting any signer would
		// let an unrelated zone sign records for this name.
		if !strings.EqualFold(dns.Fqdn(sig.SignerName), dns.Fqdn(zone)) {
			lastErr = fmt.Errorf("signer %q is not the anchored zone %q", sig.SignerName, zone)
			continue
		}
		if !sig.ValidityPeriod(now) {
			lastErr = fmt.Errorf("signature by key %d is outside its validity period", sig.KeyTag)
			continue
		}
		key, ok := keys[sig.KeyTag]
		if !ok {
			lastErr = fmt.Errorf("no validated key with tag %d", sig.KeyTag)
			continue
		}
		if err := sig.Verify(key, records); err != nil {
			lastErr = fmt.Errorf("signature by key %d does not verify: %v", sig.KeyTag, err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no RRSIG covering the record set")
	}
	return lastErr
}

// lookup fetches a type and returns it only if the chain proves it.
func (r *Resolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	zone := zoneOf(name)

	keys, err := r.validatedKeys(ctx, zone)
	if err != nil {
		return nil, err
	}

	msg, err := r.exchange(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	switch msg.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		// A negative answer needs NSEC/NSEC3 proof to be trustworthy. That is
		// not implemented, so it is reported as unvalidatable rather than
		// returned as a proven absence.
		return nil, fmt.Errorf("%w: negative answer for %s is not proven (NSEC validation unimplemented)", ErrInsecure, name)
	default:
		return nil, fmt.Errorf("vdoh: lookup for %s failed with rcode %s", name, dns.RcodeToString[msg.Rcode])
	}

	records, sigs := rrset(msg, name, qtype)
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: no records of the requested type for %s", ErrInsecure, name)
	}
	if err := r.verifySigs(records, sigs, zone, keys); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInsecure, name, err)
	}
	return records, nil
}

// LookupIP implements resolver.Resolver.
//
// The bool is letsdane's "secure" flag, which gates DANE enforcement. This
// implementation only ever returns true, because an unvalidated answer is
// returned as an error instead: there is no insecure-but-usable result.
func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	var qtypes []uint16
	switch network {
	case "ip4":
		qtypes = []uint16{dns.TypeA}
	case "ip6":
		qtypes = []uint16{dns.TypeAAAA}
	case "ip", "":
		qtypes = []uint16{dns.TypeA, dns.TypeAAAA}
	default:
		return nil, false, fmt.Errorf("vdoh: unsupported network %q", network)
	}

	var ips []net.IP
	var lastErr error
	for _, qtype := range qtypes {
		records, err := r.lookup(ctx, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range records {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
	}
	if len(ips) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("%w: no addresses for %s", ErrInsecure, host)
		}
		return nil, false, lastErr
	}
	return ips, true, nil
}

// LookupTLSA implements resolver.Resolver.
func (r *Resolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	qname, err := dns.TLSAName(dns.Fqdn(name), service, proto)
	if err != nil {
		return nil, false, err
	}
	records, err := r.lookup(ctx, qname, dns.TypeTLSA)
	if err != nil {
		return nil, false, err
	}
	var out []*dns.TLSA
	for _, rr := range records {
		if t, ok := rr.(*dns.TLSA); ok {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, false, fmt.Errorf("%w: no TLSA records for %s", ErrInsecure, qname)
	}
	return out, true, nil
}
