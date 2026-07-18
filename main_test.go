package main

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
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
