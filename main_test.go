package main

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
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

func TestParseConfigRejectsNonLoopback(t *testing.T) {
	_, err := parseConfig([]string{"-data-dir", "/tmp/data", "-hnsd-path", "/bin/hnsd", "-root-addr", "0.0.0.0:53"})
	if err == nil {
		t.Fatal("expected non-loopback address to be rejected")
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
