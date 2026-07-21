package failover

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

type stub struct {
	name    string
	ips     []net.IP
	tlsa    []*dns.TLSA
	secure  bool
	err     error
	ipCalls int
	tlCalls int
}

func (s *stub) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	s.ipCalls++
	return s.ips, s.secure, s.err
}

func (s *stub) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	s.tlCalls++
	return s.tlsa, s.secure, s.err
}

func mustNew(t *testing.T, primary, fallback Resolver) Resolver {
	t.Helper()
	r, err := New(primary, fallback, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestPrimaryIsUsedFirstAndFallbackNotConsulted(t *testing.T) {
	primary := &stub{ips: []net.IP{net.ParseIP("94.103.168.161")}, secure: true}
	fallback := &stub{ips: []net.IP{net.ParseIP("203.0.113.9")}, secure: true}

	ips, secure, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip4", "app.pirate")
	if err != nil || !secure {
		t.Fatalf("unexpected result: %v %v", secure, err)
	}
	if len(ips) != 1 || ips[0].String() != "94.103.168.161" {
		t.Fatalf("answer did not come from the primary: %v", ips)
	}
	if fallback.ipCalls != 0 {
		t.Fatalf("fallback consulted %d times despite a working primary", fallback.ipCalls)
	}
}

func TestFallbackOnlyOnPrimaryError(t *testing.T) {
	primary := &stub{err: errors.New("no route to local resolver")}
	fallback := &stub{ips: []net.IP{net.ParseIP("203.0.113.9")}, secure: true}

	ips, secure, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip4", "app.pirate")
	if err != nil {
		t.Fatalf("fallback not used: %v", err)
	}
	if !secure || len(ips) != 1 {
		t.Fatalf("unexpected fallback result: %v %v", ips, secure)
	}
	if fallback.ipCalls != 1 {
		t.Fatalf("fallback called %d times, want 1", fallback.ipCalls)
	}
}

func TestInsecurePrimaryAnswerDoesNotTriggerFallback(t *testing.T) {
	// Re-asking elsewhere when the primary answered insecurely would let anyone
	// who can degrade the local node choose which resolver we believe.
	primary := &stub{ips: []net.IP{net.ParseIP("94.103.168.161")}, secure: false}
	fallback := &stub{ips: []net.IP{net.ParseIP("203.0.113.9")}, secure: true}

	ips, secure, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip4", "app.pirate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secure {
		t.Fatal("insecure primary answer was reported secure")
	}
	if ips[0].String() != "94.103.168.161" {
		t.Fatalf("answer was substituted from the fallback: %v", ips)
	}
	if fallback.ipCalls != 0 {
		t.Fatal("fallback consulted after an insecure but successful primary answer")
	}
}

func TestFallbackErrorsAreNotSoftened(t *testing.T) {
	// The fallback validates for itself and fails closed. Nothing here may
	// convert its refusal into a usable answer.
	wantErr := errors.New("vdoh: answer could not be validated")
	primary := &stub{err: errors.New("local down")}
	fallback := &stub{err: wantErr}

	ips, secure, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip4", "app.pirate")
	if !errors.Is(err, wantErr) {
		t.Fatalf("fallback error was altered: %v", err)
	}
	if ips != nil || secure {
		t.Fatalf("failed lookup produced a usable result: %v %v", ips, secure)
	}
}

func TestNoFallbackConfiguredReturnsPrimaryError(t *testing.T) {
	wantErr := errors.New("local down")
	primary := &stub{err: wantErr}

	if _, _, err := mustNew(t, primary, nil).LookupIP(context.Background(), "ip4", "app.pirate"); !errors.Is(err, wantErr) {
		t.Fatalf("want the primary error, got %v", err)
	}
}

func TestPrimaryIsRequired(t *testing.T) {
	if _, err := New(nil, &stub{}, nil); err == nil {
		t.Fatal("New accepted a nil primary, which would make the fallback the only resolver")
	}
}

func TestTLSAFollowsTheSameOrdering(t *testing.T) {
	rec := &dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1}
	primary := &stub{tlsa: []*dns.TLSA{rec}, secure: true}
	fallback := &stub{tlsa: []*dns.TLSA{{Usage: 0}}, secure: true}

	got, secure, err := mustNew(t, primary, fallback).LookupTLSA(context.Background(), "443", "tcp", "app.pirate")
	if err != nil || !secure {
		t.Fatalf("unexpected: %v %v", secure, err)
	}
	if len(got) != 1 || got[0].Usage != 3 {
		t.Fatalf("TLSA did not come from the primary: %v", got)
	}
	if fallback.tlCalls != 0 {
		t.Fatal("fallback consulted for TLSA despite a working primary")
	}

	primary.err = errors.New("local down")
	if _, _, err := mustNew(t, primary, fallback).LookupTLSA(context.Background(), "443", "tcp", "app.pirate"); err != nil {
		t.Fatalf("TLSA fallback not used: %v", err)
	}
	if fallback.tlCalls != 1 {
		t.Fatalf("TLSA fallback called %d times, want 1", fallback.tlCalls)
	}
}
