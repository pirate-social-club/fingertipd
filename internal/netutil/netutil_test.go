package netutil

import "testing"

func TestAcceptsLoopbackWithValidPort(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:53", "127.0.0.1:1", "127.0.0.1:65535", "[::1]:5349"} {
		if err := LoopbackHostPort(addr); err != nil {
			t.Fatalf("LoopbackHostPort(%q): %v", addr, err)
		}
	}
}

func TestRejectsNonNumericAndOutOfRangePorts(t *testing.T) {
	// net.SplitHostPort accepts every one of these, which is the whole point of
	// this helper: they would otherwise fail later, at bind or dial time.
	for _, addr := range []string{
		"127.0.0.1:abc",
		"127.0.0.1:0",
		"127.0.0.1:-1",
		"127.0.0.1:65536",
		"127.0.0.1:99999",
		"127.0.0.1:",
	} {
		if err := LoopbackHostPort(addr); err == nil {
			t.Fatalf("LoopbackHostPort(%q) accepted an unusable port", addr)
		}
	}
}

func TestRejectsNonLoopbackAndHostnames(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:53", "0.0.0.0:53", "localhost:53", "dns.pirate.sc:443"} {
		if err := LoopbackHostPort(addr); err == nil {
			t.Fatalf("LoopbackHostPort(%q) accepted a non-loopback address", addr)
		}
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1", ":53"} {
		if err := LoopbackHostPort(addr); err == nil {
			t.Fatalf("LoopbackHostPort(%q) accepted a malformed address", addr)
		}
	}
}
