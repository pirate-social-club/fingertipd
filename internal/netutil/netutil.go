// Package netutil holds address checks shared by the daemon and the anchor
// provider.
//
// It exists so the loopback-and-port rule is written once. Duplicating a
// security check invites the copies to drift, and this one decides whether a
// trust anchor may be read from an address at all.
package netutil

import (
	"fmt"
	"net"
	"strconv"
)

// LoopbackHostPort verifies that addr is a loopback IP literal with a usable
// port.
//
// net.SplitHostPort alone is not enough: it happily accepts "127.0.0.1:abc",
// ":0", ":-1" and ":99999", because it only splits on the last colon and never
// interprets the port. Left unchecked those turn a configuration mistake into a
// confusing runtime failure later, once a subsystem tries to bind or dial.
//
// A hostname is rejected even if it would resolve to loopback: resolving it
// would itself depend on DNS, which is precisely what the caller is trying to
// establish.
func LoopbackHostPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host must be an IP literal, got %q", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host must be loopback, got %q", host)
	}
	if port == "" {
		return fmt.Errorf("port is required in %q", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric, got %q", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", n)
	}
	return nil
}
