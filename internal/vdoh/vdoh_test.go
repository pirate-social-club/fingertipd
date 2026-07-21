package vdoh

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- test zone -------------------------------------------------------------

type zone struct {
	name string
	key  *dns.DNSKEY
	priv any
	ds   *dns.DS
}

func newZone(t *testing.T, name string) *zone {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &zone{name: dns.Fqdn(name), key: key, priv: priv, ds: key.ToDS(dns.SHA256)}
}

func (z *zone) sign(t *testing.T, rrs []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrs[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: rrs[0].Header().Rrtype,
		Algorithm:   z.key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrs[0].Header().Name)),
		OrigTtl:     rrs[0].Header().Ttl,
		SignerName:  z.name,
		KeyTag:      z.key.KeyTag(),
		Inception:   uint32(inception.Unix()),
		Expiration:  uint32(expiration.Unix()),
	}
	if err := sig.Sign(z.priv.(crypto.Signer), rrs); err != nil {
		t.Fatalf("sign %s: %v", rrs[0].Header().Name, err)
	}
	return sig
}

func (z *zone) anchor() AnchorFunc {
	return func(ctx context.Context, name string) ([]*dns.DS, error) {
		if strings.EqualFold(dns.Fqdn(name), z.name) {
			return []*dns.DS{z.ds}, nil
		}
		return nil, nil
	}
}

// --- fake endpoint ---------------------------------------------------------

// handler lets a test decide exactly what the untrusted endpoint returns.
type handler func(q dns.Question, req *dns.Msg) *dns.Msg

func newEndpoint(t *testing.T, h handler) (*httptest.Server, *Resolver) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		req := new(dns.Msg)
		if err := req.Unpack(body[:n]); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := h(req.Question[0], req)
		if resp == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		packed, err := resp.Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/dns-message")
		w.Write(packed)
	}))
	t.Cleanup(srv.Close)
	return srv, nil
}

// reply builds a well-formed response echoing the request identity.
func reply(req *dns.Msg, rcode int, answers ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = rcode
	m.Answer = answers
	return m
}

func testResolver(t *testing.T, endpoint string, z *zone) *Resolver {
	t.Helper()
	r := &Resolver{
		Endpoint: endpoint + "/dns-query",
		Anchor:   z.anchor(),
		HTTP:     &http.Client{Timeout: 5 * time.Second},
		Now:      func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	return r
}

func aRecord(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}
}

// --- endpoint construction -------------------------------------------------

func TestNewRejectsEndpointWithoutQueryPath(t *testing.T) {
	// letsdane's stub appends "/dns-query"; this package does not. Configuring
	// an origin here would otherwise silently POST to "/", so it is rejected.
	for _, bad := range []string{"https://dns.example", "https://dns.example/"} {
		if _, err := New(bad, func(context.Context, string) ([]*dns.DS, error) { return nil, nil }); err == nil {
			t.Fatalf("New(%q) accepted an endpoint with no query path", bad)
		}
	}
}

func TestNewRejectsNonHTTPSEndpoint(t *testing.T) {
	if _, err := New("http://dns.example/dns-query", func(context.Context, string) ([]*dns.DS, error) { return nil, nil }); err == nil {
		t.Fatal("New accepted a cleartext endpoint")
	}
}

func TestRequestUsesEndpointPathVerbatim(t *testing.T) {
	var gotPath string
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	_, _ = r.exchange(context.Background(), "app.pirate", dns.TypeA)

	if gotPath != "/dns-query" {
		t.Fatalf("requested %q, want /dns-query (no duplicated path)", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("used %s, want POST so the question stays out of the URI", gotMethod)
	}
}

func TestQuerySetsDOBit(t *testing.T) {
	var sawDO bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		req := new(dns.Msg)
		if err := req.Unpack(body[:n]); err == nil {
			if opt := req.IsEdns0(); opt != nil {
				sawDO = opt.Do()
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	_, _ = r.exchange(context.Background(), "app.pirate", dns.TypeA)

	if !sawDO {
		t.Fatal("query did not set the EDNS DO bit; the endpoint is not obliged to return RRSIGs")
	}
}

func TestQueryDoesNotRequestAuthenticatedData(t *testing.T) {
	var sawAD bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		req := new(dns.Msg)
		if err := req.Unpack(body[:n]); err == nil {
			sawAD = req.AuthenticatedData
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	_, _ = r.exchange(context.Background(), "app.pirate", dns.TypeA)

	if sawAD {
		t.Fatal("query set AuthenticatedData; this resolver must not rely on the AD bit at all")
	}
}

// --- response identity -----------------------------------------------------

func TestRejectsMismatchedMessageID(t *testing.T) {
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		m := reply(req, dns.RcodeSuccess)
		m.Id = req.Id ^ 0xFFFF
		return m
	})
	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}

	if _, err := r.exchange(context.Background(), "app.pirate", dns.TypeA); err == nil ||
		!strings.Contains(err.Error(), "does not match query id") {
		t.Fatalf("expected message-id rejection, got %v", err)
	}
}

func TestRejectsMismatchedQuestion(t *testing.T) {
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		m := reply(req, dns.RcodeSuccess)
		m.Question[0].Name = "evil.pirate."
		return m
	})
	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}

	if _, err := r.exchange(context.Background(), "app.pirate", dns.TypeA); err == nil ||
		!strings.Contains(err.Error(), "asked") {
		t.Fatalf("expected question-mismatch rejection, got %v", err)
	}
}

// --- validation ------------------------------------------------------------

func TestAcceptsProperlySignedAnswer(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	a := aRecord("app.pirate", "94.103.168.161")
	aSig := z.sign(t, []dns.RR{a}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		switch q.Qtype {
		case dns.TypeDNSKEY:
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		case dns.TypeA:
			return reply(req, dns.RcodeSuccess, a, aSig)
		}
		return reply(req, dns.RcodeSuccess)
	})

	r := testResolver(t, srv.URL, z)
	ips, secure, err := r.LookupIP(context.Background(), "ip4", "app.pirate")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if !secure {
		t.Fatal("validated answer not reported secure")
	}
	if len(ips) != 1 || ips[0].String() != "94.103.168.161" {
		t.Fatalf("got %v", ips)
	}
}

func TestRejectsAnswerWithNoRRSIG(t *testing.T) {
	// The forged-AD case: endpoint returns a bare answer and asserts AD=true.
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		var m *dns.Msg
		switch q.Qtype {
		case dns.TypeDNSKEY:
			m = reply(req, dns.RcodeSuccess, z.key, keySig)
		default:
			m = reply(req, dns.RcodeSuccess, aRecord("app.pirate", "203.0.113.9"))
		}
		m.AuthenticatedData = true // forged
		return m
	})

	r := testResolver(t, srv.URL, z)
	if _, _, err := r.LookupIP(context.Background(), "ip4", "app.pirate"); err == nil {
		t.Fatal("accepted an unsigned answer carrying a forged AD bit")
	} else if !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
}

func TestRejectsExpiredSignature(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	a := aRecord("app.pirate", "94.103.168.161")
	expired := z.sign(t, []dns.RR{a}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		return reply(req, dns.RcodeSuccess, a, expired)
	})

	r := testResolver(t, srv.URL, z)
	if _, _, err := r.LookupIP(context.Background(), "ip4", "app.pirate"); err == nil {
		t.Fatal("accepted an expired signature")
	}
}

func TestRejectsWhenDSAnchorDoesNotMatchDNSKEY(t *testing.T) {
	// Endpoint substitutes its own zone key; the chain anchor still commits to
	// the real one.
	real := newZone(t, "pirate")
	attacker := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	a := aRecord("app.pirate", "203.0.113.9")
	aSig := attacker.sign(t, []dns.RR{a}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := attacker.sign(t, []dns.RR{attacker.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, attacker.key, keySig)
		}
		return reply(req, dns.RcodeSuccess, a, aSig)
	})

	r := testResolver(t, srv.URL, real) // anchor = real zone
	_, _, err := r.LookupIP(context.Background(), "ip4", "app.pirate")
	if err == nil {
		t.Fatal("accepted a DNSKEY that no DS anchor commits to")
	}
	if !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
	// Assert WHY it failed, not just that it did. Removing the DS<->DNSKEY match
	// leaves an empty key set, so the downstream signature check would still
	// reject this -- but for the wrong reason. Pinning the reason is what makes
	// this test isolate the DS check rather than shadow it.
	if !strings.Contains(err.Error(), "matches the chain DS anchor") {
		t.Fatalf("rejected for the wrong reason; want DS-anchor mismatch, got: %v", err)
	}
}

func TestRejectsAnchorDSOwnedByAnotherZone(t *testing.T) {
	z := newZone(t, "pirate")
	// A provider bug that returns a DS for a different owner must not authorise
	// keys for the requested zone.
	wrong := *z.ds
	wrong.Hdr.Name = "evil.example."

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		return reply(req, dns.RcodeSuccess)
	})
	r := &Resolver{
		Endpoint: srv.URL + "/dns-query",
		Anchor:   func(context.Context, string) ([]*dns.DS, error) { return []*dns.DS{&wrong}, nil },
		Now:      func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	_, _, err := r.LookupIP(context.Background(), "ip4", "app.pirate")
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("expected anchor-owner rejection, got %v", err)
	}
}

func TestRejectsNonResponseMessage(t *testing.T) {
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		m := reply(req, dns.RcodeSuccess)
		m.Response = false
		return m
	})
	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	if _, err := r.exchange(context.Background(), "app.pirate", dns.TypeA); err == nil ||
		!strings.Contains(err.Error(), "not a response") {
		t.Fatalf("expected non-response rejection, got %v", err)
	}
}

func TestRejectsUnexpectedOpcode(t *testing.T) {
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		m := reply(req, dns.RcodeSuccess)
		m.Opcode = dns.OpcodeNotify
		return m
	})
	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	if _, err := r.exchange(context.Background(), "app.pirate", dns.TypeA); err == nil ||
		!strings.Contains(err.Error(), "opcode") {
		t.Fatalf("expected opcode rejection, got %v", err)
	}
}

func TestRejectsWrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html")
		w.Write([]byte("<html>not dns</html>"))
	}))
	defer srv.Close()
	r := &Resolver{Endpoint: srv.URL + "/dns-query", Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil }}
	if _, err := r.exchange(context.Background(), "app.pirate", dns.TypeA); err == nil ||
		!strings.Contains(err.Error(), "content-type") {
		t.Fatalf("expected content-type rejection, got %v", err)
	}
}

func TestRejectsUnsignedDelegation(t *testing.T) {
	z := newZone(t, "pirate")
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		return reply(req, dns.RcodeSuccess, aRecord("app.dankmeme", "203.0.113.9"))
	})

	r := &Resolver{
		Endpoint: srv.URL + "/dns-query",
		// No DS published for this root, as on an unsigned delegation.
		Anchor: func(context.Context, string) ([]*dns.DS, error) { return nil, nil },
		Now:    func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	_ = z
	if _, _, err := r.LookupIP(context.Background(), "ip4", "app.dankmeme"); err == nil {
		t.Fatal("accepted an answer from a zone with no DS anchor")
	} else if !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
}

func TestRejectsTLSAFromUnvalidatedZone(t *testing.T) {
	z := newZone(t, "pirate")
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		tlsa := &dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_443._tcp.app.pirate.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Certificate:  strings.Repeat("aa", 32),
		}
		return reply(req, dns.RcodeSuccess, tlsa)
	})

	r := testResolver(t, srv.URL, z) // anchor exists, but nothing is signed
	if _, _, err := r.LookupTLSA(context.Background(), "443", "tcp", "app.pirate"); err == nil {
		t.Fatal("accepted an unsigned TLSA record")
	}
}

func TestNegativeAnswerIsNotReportedAsProven(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		return reply(req, dns.RcodeNameError)
	})

	r := testResolver(t, srv.URL, z)
	_, _, err := r.LookupIP(context.Background(), "ip4", "absent.pirate")
	if err == nil {
		t.Fatal("negative answer treated as a result")
	}
	if !errors.Is(err, ErrInsecure) {
		t.Fatalf("NXDOMAIN without NSEC proof must be reported as unvalidatable, got %v", err)
	}
}

// --- CNAME ------------------------------------------------------------------

func cname(name, target string) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn(target),
	}
}

// zoneServer answers from a signed fixture, so tests describe zone contents
// rather than wire details.
func signedZone(t *testing.T, z *zone, now time.Time, rrs ...dns.RR) handler {
	t.Helper()
	byName := map[string][]dns.RR{}
	for _, rr := range rrs {
		k := strings.ToLower(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		byName[k] = append(byName[k], rr)
	}
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	return func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		var answers []dns.RR
		if set, ok := byName[strings.ToLower(q.Name)+"/"+dns.TypeToString[q.Qtype]]; ok {
			answers = append(answers, set...)
			answers = append(answers, z.sign(t, set, now.Add(-time.Hour), now.Add(24*time.Hour)))
		} else if set, ok := byName[strings.ToLower(q.Name)+"/CNAME"]; ok {
			answers = append(answers, set...)
			answers = append(answers, z.sign(t, set, now.Add(-time.Hour), now.Add(24*time.Hour)))
		}
		return reply(req, dns.RcodeSuccess, answers...)
	}
}

func TestFollowsValidatedCNAMEWithinZone(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, signedZone(t, z, now,
		cname("www.pirate", "app.pirate"),
		aRecord("app.pirate", "94.103.168.161"),
	))

	ips, secure, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "www.pirate")
	if err != nil || !secure {
		t.Fatalf("CNAME not followed: %v %v", secure, err)
	}
	if len(ips) != 1 || ips[0].String() != "94.103.168.161" {
		t.Fatalf("got %v", ips)
	}
}

func TestRejectsUnsignedCNAME(t *testing.T) {
	// An unsigned alias would let the endpoint redirect a lookup and have the
	// target validate cleanly.
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	a := aRecord("evil.pirate", "203.0.113.9")
	aSig := z.sign(t, []dns.RR{a}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeDNSKEY:
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		case strings.EqualFold(q.Name, "app.pirate."):
			return reply(req, dns.RcodeSuccess, cname("app.pirate", "evil.pirate")) // no RRSIG
		default:
			return reply(req, dns.RcodeSuccess, a, aSig)
		}
	})

	if _, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "app.pirate"); err == nil {
		t.Fatal("followed an unsigned CNAME")
	} else if !errors.Is(err, ErrInsecure) {
		t.Fatalf("want ErrInsecure, got %v", err)
	}
}

func TestRejectsCNAMELeavingAnchoredZone(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, signedZone(t, z, now, cname("app.pirate", "elsewhere.example")))

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "app.pirate")
	if err == nil || !strings.Contains(err.Error(), "outside the anchored zone") {
		t.Fatalf("expected out-of-zone rejection, got %v", err)
	}
}

func TestRejectsCNAMELoop(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, signedZone(t, z, now,
		cname("a.pirate", "b.pirate"),
		cname("b.pirate", "a.pirate"),
	))

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "a.pirate")
	if err == nil || !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected a bounded rejection of the loop, got %v", err)
	}
}

func TestRejectsMultipleCNAMEs(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))
	set := []dns.RR{cname("app.pirate", "one.pirate"), cname("app.pirate", "two.pirate")}
	setSig := z.sign(t, set, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		return reply(req, dns.RcodeSuccess, append(append([]dns.RR{}, set...), setSig)...)
	})

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "app.pirate")
	if err == nil || !strings.Contains(err.Error(), "CNAME records") {
		t.Fatalf("expected multi-CNAME rejection, got %v", err)
	}
}

// --- wildcard ---------------------------------------------------------------

func TestRejectsWildcardExpandedAnswer(t *testing.T) {
	// The signature is genuine; what is missing is proof that no closer name
	// exists. Without it an endpoint can serve the wildcard in place of a name
	// that has its own record.
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	a := aRecord("anyuser.pirate", "94.103.168.161")

	sig := z.sign(t, []dns.RR{a}, now.Add(-time.Hour), now.Add(24*time.Hour))
	sig.Labels = 1 // signed as *.pirate, expanded to anyuser.pirate
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		return reply(req, dns.RcodeSuccess, a, sig)
	})

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "anyuser.pirate")
	if err == nil {
		t.Fatal("accepted a wildcard-expanded answer without an NSEC proof")
	}
	if !strings.Contains(err.Error(), "no validated NSEC") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

func TestNSECCoverageUsesCanonicalOrderAndWrap(t *testing.T) {
	for _, tc := range []struct {
		name string
		rr   *dns.NSEC
		q    string
		want bool
	}{
		{"inside", nsec("aaa.pirate", "zzz.pirate"), "handle.pirate", true},
		{"lower boundary", nsec("aaa.pirate", "zzz.pirate"), "aaa.pirate", false},
		{"upper boundary", nsec("aaa.pirate", "zzz.pirate"), "zzz.pirate", false},
		{"outside", nsec("one.pirate", "two.pirate"), "handle.pirate", false},
		{"wrap high", nsec("zzz.pirate", "aaa.pirate"), "zzzz.pirate", true},
		{"wrap low", nsec("zzz.pirate", "aaa.pirate"), "0.pirate", true},
		{"wrap middle", nsec("zzz.pirate", "aaa.pirate"), "handle.pirate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nsecCovers(tc.rr, tc.q); got != tc.want {
				t.Fatalf("nsecCovers(%s -> %s, %s)=%v, want %v", tc.rr.Hdr.Name, tc.rr.NextDomain, tc.q, got, tc.want)
			}
		})
	}
}

func TestCanonicalNameOrderUsesWireLabels(t *testing.T) {
	if got, ok := canonicalNameCompare(`A.pirate.`, `a.pirate.`); !ok || got != 0 {
		t.Fatalf("ASCII case was not folded canonically: got=%d ok=%v", got, ok)
	}
	if got, ok := canonicalNameCompare(`\097.pirate.`, `a.pirate.`); !ok || got != 0 {
		t.Fatalf("escaped wire octet was not compared canonically: got=%d ok=%v", got, ok)
	}
	if _, ok := canonicalNameCompare(strings.Repeat("a", 64)+`.pirate.`, `a.pirate.`); ok {
		t.Fatal("overlong label was assigned a canonical order")
	}
}

func TestExactAnswerStillAcceptedAlongsideWildcardRule(t *testing.T) {
	// The wildcard check must not reject ordinary answers.
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, signedZone(t, z, now, aRecord("app.pirate", "94.103.168.161")))

	if _, secure, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "app.pirate"); err != nil || !secure {
		t.Fatalf("exact answer rejected: %v %v", secure, err)
	}
}

func validWildcardAnswer(t *testing.T, z *zone, now time.Time, expandedName string) (*dns.A, *dns.RRSIG) {
	t.Helper()
	wild := aRecord("*.pirate", "94.103.168.161")
	sig := z.sign(t, []dns.RR{wild}, now.Add(-time.Hour), now.Add(24*time.Hour))
	wild.Hdr.Name = dns.Fqdn(expandedName)
	sig.Hdr.Name = dns.Fqdn(expandedName)
	return wild, sig
}

func validWildcardTLSA(t *testing.T, z *zone, now time.Time, expandedName string) (*dns.TLSA, *dns.RRSIG) {
	t.Helper()
	wild := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "*.pirate.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  strings.Repeat("ab", 32),
	}
	sig := z.sign(t, []dns.RR{wild}, now.Add(-time.Hour), now.Add(24*time.Hour))
	wild.Hdr.Name = dns.Fqdn(expandedName)
	sig.Hdr.Name = dns.Fqdn(expandedName)
	return wild, sig
}

func nsec(owner, next string) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn(next),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
}

func TestAcceptsOneLabelWildcardWithValidatedNSECProof(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	name := "handle.pirate"
	a, aSig := validWildcardAnswer(t, z, now, name)
	denial := nsec("aaa.pirate", "zzz.pirate")
	denialSig := z.sign(t, []dns.RR{denial}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		switch q.Qtype {
		case dns.TypeDNSKEY:
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		case dns.TypeNSEC:
			m := reply(req, dns.RcodeSuccess)
			m.Ns = []dns.RR{denial, denialSig}
			return m
		default:
			return reply(req, dns.RcodeSuccess, a, aSig)
		}
	})

	ips, secure, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", name)
	if err != nil || !secure || len(ips) != 1 || ips[0].String() != "94.103.168.161" {
		t.Fatalf("validated wildcard rejected: ips=%v secure=%v err=%v", ips, secure, err)
	}
}

func TestRejectsWildcardWithUnsignedNSECProof(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	name := "handle.pirate"
	a, aSig := validWildcardAnswer(t, z, now, name)
	denial := nsec("aaa.pirate", "zzz.pirate")
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		switch q.Qtype {
		case dns.TypeDNSKEY:
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		case dns.TypeNSEC:
			m := reply(req, dns.RcodeSuccess)
			m.Ns = []dns.RR{denial} // endpoint assertion, not a proof
			return m
		default:
			return reply(req, dns.RcodeSuccess, a, aSig)
		}
	})

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", name)
	if err == nil || !strings.Contains(err.Error(), "no validated NSEC") {
		t.Fatalf("unsigned denial accepted or rejected for the wrong reason: %v", err)
	}
}

func TestRejectsWildcardWhenNSECDoesNotCoverName(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	name := "handle.pirate"
	a, aSig := validWildcardAnswer(t, z, now, name)
	denial := nsec("one.pirate", "two.pirate")
	denialSig := z.sign(t, []dns.RR{denial}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))

	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		if q.Qtype == dns.TypeNSEC {
			m := reply(req, dns.RcodeSuccess)
			m.Ns = []dns.RR{denial, denialSig}
			return m
		}
		return reply(req, dns.RcodeSuccess, a, aSig)
	})

	if _, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", name); err == nil {
		t.Fatal("accepted a denial interval that does not cover the expanded name")
	}
}

func TestAcceptsDANENameSynthesizedFromAnchoredWildcard(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	name := "_443._tcp.handle.pirate"
	tlsa, tlsaSig := validWildcardTLSA(t, z, now, name)
	// Covers next-closer handle.pirate, but not the full query name. This pins
	// the RFC next-closer derivation; checking the expanded owner directly would
	// reject this otherwise valid proof.
	denial := nsec("aaa.pirate", "!.handle.pirate")
	denialSig := z.sign(t, []dns.RR{denial}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		if q.Qtype == dns.TypeNSEC {
			m := reply(req, dns.RcodeSuccess)
			m.Ns = []dns.RR{denial, denialSig}
			return m
		}
		return reply(req, dns.RcodeSuccess, tlsa, tlsaSig)
	})

	records, secure, err := testResolver(t, srv.URL, z).LookupTLSA(context.Background(), "443", "tcp", "handle.pirate")
	if err != nil || !secure || len(records) != 1 {
		t.Fatalf("DANE name from *.pirate rejected: records=%v secure=%v err=%v", records, secure, err)
	}
}

func TestRejectsWildcardSourceAboveAnchoredZone(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	name := "handle.pirate"
	rootWildcard, aSig := validWildcardAnswer(t, z, now, name)
	aSig.Labels = 0 // claims a wildcard source above the anchored .pirate zone

	denial := nsec("aaa.pirate", "zzz.pirate")
	denialSig := z.sign(t, []dns.RR{denial}, now.Add(-time.Hour), now.Add(24*time.Hour))
	keySig := z.sign(t, []dns.RR{z.key}, now.Add(-time.Hour), now.Add(24*time.Hour))
	srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
		if q.Qtype == dns.TypeDNSKEY {
			return reply(req, dns.RcodeSuccess, z.key, keySig)
		}
		if q.Qtype == dns.TypeNSEC {
			m := reply(req, dns.RcodeSuccess)
			m.Ns = []dns.RR{denial, denialSig}
			return m
		}
		return reply(req, dns.RcodeSuccess, rootWildcard, aSig)
	})

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", name)
	if err == nil || !strings.Contains(err.Error(), "anchored source") {
		t.Fatalf("wildcard source above the anchor was accepted or rejected for the wrong reason: %v", err)
	}
}

// chainZone builds n aliases c0 -> c1 -> ... -> cn, with cn holding the address.
// n is therefore the exact number of aliases that must be followed.
func chainZone(t *testing.T, z *zone, now time.Time, n int) handler {
	t.Helper()
	var rrs []dns.RR
	for i := 0; i < n; i++ {
		rrs = append(rrs, cname(fmt.Sprintf("c%d.pirate", i), fmt.Sprintf("c%d.pirate", i+1)))
	}
	rrs = append(rrs, aRecord(fmt.Sprintf("c%d.pirate", n), "94.103.168.161"))
	return signedZone(t, z, now, rrs...)
}

func TestFollowsExactlyMaxCNAMEDepth(t *testing.T) {
	// The bound must name the number of aliases actually permitted.
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, chainZone(t, z, now, maxCNAMEDepth))

	ips, secure, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "c0.pirate")
	if err != nil || !secure {
		t.Fatalf("a chain of exactly %d aliases was rejected: %v %v", maxCNAMEDepth, secure, err)
	}
	if len(ips) != 1 || ips[0].String() != "94.103.168.161" {
		t.Fatalf("got %v", ips)
	}
}

func TestRejectsOneMoreThanMaxCNAMEDepth(t *testing.T) {
	z := newZone(t, "pirate")
	now := time.Unix(1_800_000_000, 0)
	srv, _ := newEndpoint(t, chainZone(t, z, now, maxCNAMEDepth+1))

	_, _, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip4", "c0.pirate")
	if err == nil {
		t.Fatalf("followed %d aliases despite a stated bound of %d", maxCNAMEDepth+1, maxCNAMEDepth)
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}
