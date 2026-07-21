package main

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]string{"-data-dir", "/tmp/data", "-hnsd-path", "/bin/hnsd", "-root-addr", "127.0.0.1:1", "-recursive-addr", "[::1]:2"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.dataDir != "/tmp/data" || cfg.hnsdPath != "/bin/hnsd" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestQuerySyncUsesRootForHeightAndRecursiveForReadiness(t *testing.T) {
	rootAddr := startDNSTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		if request.Question[0].Qclass != dns.ClassHESIOD {
			t.Errorf("height query class = %d, want HESIOD", request.Question[0].Qclass)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: "height.tip.chain.hnsd.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{"123456"},
		}}
		_ = w.WriteMsg(response)
	}))
	recursiveAddr := startDNSTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		if request.Question[0].Name != readinessName || request.Question[0].Qtype != dns.TypeTLSA {
			t.Errorf("readiness query = %s/%d, want %s/TLSA", request.Question[0].Name, request.Question[0].Qtype, readinessName)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.AuthenticatedData = true
		response.Answer = []dns.RR{&dns.TLSA{
			Hdr:          dns.RR_Header{Name: readinessName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Certificate:  "00",
		}}
		_ = w.WriteMsg(response)
	}))
	height, synced := querySync(rootAddr, recursiveAddr)
	if height != 123456 || !synced {
		t.Fatalf("querySync returned height=%d synced=%v", height, synced)
	}
}

func TestQuerySyncRejectsUnauthenticatedTLSA(t *testing.T) {
	rootAddr := startDNSTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}))
	recursiveAddr := startDNSTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.TLSA{
			Hdr: dns.RR_Header{Name: readinessName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		}}
		_ = w.WriteMsg(response)
	}))
	_, synced := querySync(rootAddr, recursiveAddr)
	if synced {
		t.Fatal("unauthenticated TLSA must not report synced")
	}
}

func startDNSTestServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: connection, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return connection.LocalAddr().String()
}

func TestParseConfigRejectsNonLoopback(t *testing.T) {
	_, err := parseConfig([]string{"-data-dir", "/tmp/data", "-hnsd-path", "/bin/hnsd", "-root-addr", "0.0.0.0:53"})
	if err == nil {
		t.Fatal("expected non-loopback address to be rejected")
	}
}

func TestParseConfigAcceptsOnlyLoopbackHnsdSeed(t *testing.T) {
	cfg, err := parseConfig([]string{"-data-dir", "/tmp/data", "-hnsd-path", "/bin/hnsd", "-hnsd-seed", "127.0.0.1:10000"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hnsdSeed != "127.0.0.1:10000" {
		t.Fatalf("unexpected seed: %q", cfg.hnsdSeed)
	}
	_, err = parseConfig([]string{"-data-dir", "/tmp/data", "-hnsd-path", "/bin/hnsd", "-hnsd-seed", "8.8.8.8:53"})
	if err == nil {
		t.Fatal("expected non-loopback seed to be rejected")
	}
}

func TestLoadOrCreateCAPersistsPrivatePair(t *testing.T) {
	dir := t.TempDir()
	cert, key, path, err := loadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	assertPair(t, cert, key)
	if path != filepath.Join(dir, caFileName) {
		t.Fatalf("unexpected CA path: %s", path)
	}
	for _, name := range []string{caFileName, caKeyFileName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode is %o, want 600", name, info.Mode().Perm())
		}
	}
	cert2, key2, _, err := loadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	assertPair(t, cert2, key2)
	if cert.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Fatal("CA was not reused")
	}
}

func assertPair(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 {
		t.Fatal("certificate and key do not match")
	}
}

func TestParseConfigRejectsBadDoHEndpointAtParseTime(t *testing.T) {
	// A configuration error must not cost an hnsd launch to discover.
	for _, bad := range []string{
		"http://dns.pirate.sc/dns-query", // not https
		"https://dns.pirate.sc",          // no query path
		"https://dns.pirate.sc/",         // no query path
	} {
		_, err := parseConfig([]string{
			"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true",
			"-doh-fallback-endpoint", bad,
		})
		if err == nil {
			t.Fatalf("parseConfig accepted %q", bad)
		}
	}
}

func TestParseConfigAcceptsValidDoHEndpoint(t *testing.T) {
	cfg, err := parseConfig([]string{
		"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true",
		"-doh-fallback-endpoint", "https://dns.pirate.sc/dns-query",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.dohEndpoint != "https://dns.pirate.sc/dns-query" {
		t.Fatalf("endpoint not recorded: %q", cfg.dohEndpoint)
	}
}

func TestDoHFallbackIsOffByDefault(t *testing.T) {
	// The fallback must never be enabled implicitly.
	cfg, err := parseConfig([]string{"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.dohEndpoint != "" {
		t.Fatalf("DoH fallback defaulted to %q; it must be opt-in", cfg.dohEndpoint)
	}
}

func TestImplicitDoHDefaultRequiresDelegatedZoneCapability(t *testing.T) {
	_, err := parseConfigWithDOHDefault(
		[]string{"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true"},
		"https://dns.pirate.sc/dns-query",
	)
	if err == nil || !strings.Contains(err.Error(), "requires delegated-zone validation") {
		t.Fatalf("implicit fallback was accepted without delegated-zone support: %v", err)
	}
}

func TestExplicitDoHFallbackRemainsAvailableForControlledTesting(t *testing.T) {
	cfg, err := parseConfigWithDOHDefault(
		[]string{
			"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true",
			"-doh-fallback-endpoint", "https://test-resolver.example/dns-query",
		},
		"https://dns.pirate.sc/dns-query",
	)
	if err != nil {
		t.Fatalf("explicit controlled fallback rejected: %v", err)
	}
	if cfg.dohEndpoint != "https://test-resolver.example/dns-query" {
		t.Fatalf("explicit endpoint not retained: %q", cfg.dohEndpoint)
	}
}

func TestParseConfigRejectsUnusablePorts(t *testing.T) {
	// net.SplitHostPort accepts every one of these. Without a numeric check the
	// mistake surfaces later as an hnsd bind or dial failure, not as a config
	// error the operator can act on.
	bad := []string{"127.0.0.1:abc", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:"}

	for _, addr := range bad {
		if _, err := parseConfig([]string{
			"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true", "-root-addr", addr,
		}); err == nil {
			t.Fatalf("parseConfig accepted -root-addr %q", addr)
		}
		if _, err := parseConfig([]string{
			"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true", "-recursive-addr", addr,
		}); err == nil {
			t.Fatalf("parseConfig accepted -recursive-addr %q", addr)
		}
		if _, err := parseConfig([]string{
			"-data-dir", t.TempDir(), "-hnsd-path", "/bin/true", "-hnsd-seed", addr,
		}); err == nil {
			t.Fatalf("parseConfig accepted -hnsd-seed %q", addr)
		}
	}
}
