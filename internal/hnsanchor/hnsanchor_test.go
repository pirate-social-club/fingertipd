package hnsanchor

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pirate-social-club/fingertipd/internal/vdoh"
)

// fakeRoot stands in for hnsd's root server on loopback.
type fakeRoot struct {
	synced  string // value returned for synced.chain.hnsd
	ds      []dns.RR
	dsRcode int
	mangle  func(req, resp *dns.Msg)
}

func startRoot(t *testing.T, f *fakeRoot) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc}
	srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]

		switch {
		case q.Qclass == dns.ClassHESIOD && q.Qtype == dns.TypeTXT:
			if f.synced != "" {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassHESIOD, Ttl: 0},
					Txt: []string{f.synced},
				})
			}
		case q.Qtype == dns.TypeDS:
			resp.Rcode = f.dsRcode
			resp.Answer = append(resp.Answer, f.ds...)
		}

		if f.mangle != nil {
			f.mangle(req, resp)
		}
		_ = w.WriteMsg(resp)
	})
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func dsRecord(owner string, tag uint16) *dns.DS {
	return &dns.DS{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
		KeyTag:     tag,
		Algorithm:  dns.ECDSAP256SHA256,
		DigestType: dns.SHA256,
		Digest:     strings.Repeat("ab", 32),
	}
}

func provider(t *testing.T, addr string) *Provider {
	t.Helper()
	p, err := New(addr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.timeout = 2 * time.Second
	return p
}

// --- construction: loopback is enforced by the type ------------------------

func TestNewRejectsNonLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:53", "94.103.168.161:53", "0.0.0.0:53"} {
		if _, err := New(addr); err == nil {
			t.Fatalf("New(%q) accepted a non-loopback address", addr)
		}
	}
}

func TestNewRejectsHostname(t *testing.T) {
	// A hostname could resolve anywhere, and resolving it would itself depend on
	// DNS. Only a loopback IP literal is acceptable.
	for _, addr := range []string{"localhost:53", "dns.pirate.sc:443"} {
		if _, err := New(addr); err == nil {
			t.Fatalf("New(%q) accepted a hostname", addr)
		}
	}
}

func TestNewAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:5349", "[::1]:5349"} {
		if _, err := New(addr); err != nil {
			t.Fatalf("New(%q): %v", addr, err)
		}
	}
}

// --- sync gate -------------------------------------------------------------

func TestRefusesWhenNotSynced(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "false", ds: []dns.RR{dsRecord("pirate", 34383)}})
	p := provider(t, addr)

	_, err := p.Anchor(context.Background(), "pirate.")
	if !errors.Is(err, ErrNotSynced) {
		t.Fatalf("want ErrNotSynced, got %v", err)
	}
}

func TestNotSyncedIsDistinctFromUnsigned(t *testing.T) {
	// An unsynced node knows nothing; that must not look like "this root is
	// unsigned", which is a claim about the chain.
	addr := startRoot(t, &fakeRoot{synced: "false"})
	p := provider(t, addr)

	_, err := p.Anchor(context.Background(), "pirate.")
	if errors.Is(err, vdoh.ErrInsecure) {
		t.Fatal("unsynced state was reported as an insecure/unsigned zone")
	}
	if !errors.Is(err, ErrNotSynced) {
		t.Fatalf("want ErrNotSynced, got %v", err)
	}
}

func TestRefusesWhenSyncStatusMissing(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "", ds: []dns.RR{dsRecord("pirate", 1)}})
	p := provider(t, addr)

	if _, err := p.Anchor(context.Background(), "pirate."); !errors.Is(err, ErrNotSynced) {
		t.Fatalf("absent sync status must not be treated as synced, got %v", err)
	}
}

// --- zone depth ------------------------------------------------------------

func TestRejectsDeeperZones(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "true", ds: []dns.RR{dsRecord("app.pirate", 1)}})
	p := provider(t, addr)

	for _, zone := range []string{"app.pirate.", "a.b.pirate.", "."} {
		_, err := p.Anchor(context.Background(), zone)
		if err == nil {
			t.Fatalf("Anchor(%q) returned an anchor for a zone the validator cannot chain-walk", zone)
		}
		if !errors.Is(err, vdoh.ErrInsecure) {
			t.Fatalf("Anchor(%q): want ErrInsecure, got %v", zone, err)
		}
	}
}

// --- record filtering ------------------------------------------------------

func TestReturnsOnlyExactOwnerINDS(t *testing.T) {
	addr := startRoot(t, &fakeRoot{
		synced: "true",
		ds: []dns.RR{
			dsRecord("pirate", 34383),  // wanted
			dsRecord("evil", 999),      // wrong owner
			dsRecord("notpirate", 998), // wrong owner, shares a suffix-ish name
			&dns.A{Hdr: dns.RR_Header{Name: "pirate.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("127.0.0.1")},
		},
	})
	p := provider(t, addr)

	got, err := p.Anchor(context.Background(), "pirate.")
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if len(got) != 1 || got[0].KeyTag != 34383 {
		t.Fatalf("got %d records %v, want exactly the pirate. DS", len(got), got)
	}
}

func TestMissingDSIsErrInsecure(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "true"})
	p := provider(t, addr)

	_, err := p.Anchor(context.Background(), "dankmeme.")
	if !errors.Is(err, vdoh.ErrInsecure) {
		t.Fatalf("missing DS must be ErrInsecure, got %v", err)
	}
}

func TestDSRecordsForAnotherOwnerAreNotReturned(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "true", ds: []dns.RR{dsRecord("evil", 1)}})
	p := provider(t, addr)

	if _, err := p.Anchor(context.Background(), "pirate."); !errors.Is(err, vdoh.ErrInsecure) {
		t.Fatalf("a DS owned by another zone must not satisfy the anchor, got %v", err)
	}
}

// --- response identity -----------------------------------------------------

func TestRejectsMismatchedResponseID(t *testing.T) {
	addr := startRoot(t, &fakeRoot{
		synced: "true",
		ds:     []dns.RR{dsRecord("pirate", 1)},
		mangle: func(req, resp *dns.Msg) {
			if req.Question[0].Qtype == dns.TypeDS {
				resp.Id = req.Id ^ 0xFFFF
			}
		},
	})
	p := provider(t, addr)

	// The client library drops a reply whose id does not match, so this surfaces
	// as a timeout rather than our own check -- either way no anchor is returned.
	if _, err := p.Anchor(context.Background(), "pirate."); err == nil {
		t.Fatal("accepted a response whose message id did not match")
	}
}

func TestRejectsAnsweredDifferentQuestion(t *testing.T) {
	addr := startRoot(t, &fakeRoot{
		synced: "true",
		ds:     []dns.RR{dsRecord("pirate", 1)},
		mangle: func(req, resp *dns.Msg) {
			if req.Question[0].Qtype == dns.TypeDS {
				resp.Question[0].Name = "evil."
			}
		},
	})
	p := provider(t, addr)

	if _, err := p.Anchor(context.Background(), "pirate."); err == nil {
		t.Fatal("accepted a response answering a different question")
	}
}

func TestRejectsNonResponseMessage(t *testing.T) {
	addr := startRoot(t, &fakeRoot{
		synced: "true",
		ds:     []dns.RR{dsRecord("pirate", 1)},
		mangle: func(req, resp *dns.Msg) {
			if req.Question[0].Qtype == dns.TypeDS {
				resp.Response = false
			}
		},
	})
	p := provider(t, addr)

	if _, err := p.Anchor(context.Background(), "pirate."); err == nil ||
		!strings.Contains(err.Error(), "not a response") {
		t.Fatalf("expected non-response rejection, got %v", err)
	}
}

// --- timeouts and caching --------------------------------------------------

func TestQueryRespectsContextDeadline(t *testing.T) {
	// A root server that never answers must not hang the caller.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	p := provider(t, pc.LocalAddr().String())
	p.timeout = 200 * time.Millisecond

	start := time.Now()
	if _, err := p.Anchor(context.Background(), "pirate."); err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("query took %v; timeout not enforced", elapsed)
	}
}

func TestNoCachingAcrossSyncStateChange(t *testing.T) {
	// A cache would have to be invalidated on reorg and on sync-state changes.
	// There is none, so a root that stops being synced must stop yielding an
	// anchor immediately.
	root := &fakeRoot{synced: "true", ds: []dns.RR{dsRecord("pirate", 34383)}}
	addr := startRoot(t, root)
	p := provider(t, addr)

	if _, err := p.Anchor(context.Background(), "pirate."); err != nil {
		t.Fatalf("first Anchor: %v", err)
	}

	root.synced = "false"
	if _, err := p.Anchor(context.Background(), "pirate."); !errors.Is(err, ErrNotSynced) {
		t.Fatalf("anchor served from cache after sync state changed, got %v", err)
	}

	root.synced = "true"
	root.ds = nil
	if _, err := p.Anchor(context.Background(), "pirate."); !errors.Is(err, vdoh.ErrInsecure) {
		t.Fatalf("anchor served from cache after the chain no longer publishes a DS, got %v", err)
	}
}

// --- contract: it satisfies vdoh.AnchorFunc --------------------------------

func TestSatisfiesAnchorFunc(t *testing.T) {
	addr := startRoot(t, &fakeRoot{synced: "true", ds: []dns.RR{dsRecord("pirate", 34383)}})
	p := provider(t, addr)

	var fn vdoh.AnchorFunc = p.Anchor
	got, err := fn(context.Background(), "pirate.")
	if err != nil || len(got) != 1 {
		t.Fatalf("provider does not satisfy vdoh.AnchorFunc usefully: %v %v", got, err)
	}
}
