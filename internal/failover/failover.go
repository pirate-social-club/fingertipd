// Package failover composes a primary and an optional fallback
// letsdane resolver.
//
// The roles are fixed by construction. New takes the primary first and the
// fallback second, there is no configuration that swaps them, and the fallback
// is nil unless an operator explicitly configured one. This exists so that
// "prefer the local node, and only reach for the network when the local node
// cannot answer at all" is a property of the type rather than a convention that
// a later config change can quietly invert into DoH-first.
package failover

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
	"github.com/pirate-social-club/fingertipd/internal/strictaddr"
)

// Resolver is the subset of letsdane's resolver.Resolver that this package
// composes. Declaring it here keeps the dependency one-way.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error)
	LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error)
}

// Logf receives one line whenever the fallback is consulted, so a host that has
// quietly stopped resolving locally is visible rather than silently degraded.
type Logf func(format string, args ...any)

type resolver struct {
	primary  Resolver
	fallback Resolver
	logf     Logf
}

// New returns a Resolver that consults primary first.
//
// fallback may be nil, in which case this is exactly primary. The fallback must validate
// for itself; LookupIP additionally rejects an insecure or empty success.
// Fallback errors remain refusals, never usable addresses.
func New(primary, fallback Resolver, logf Logf) (Resolver, error) {
	if primary == nil {
		return nil, errors.New("failover: primary resolver is required")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &resolver{primary: primary, fallback: fallback, logf: logf}, nil
}

func (r *resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	ips, secure, err := r.primary.LookupIP(ctx, network, host)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if errors.Is(err, strictaddr.ErrAddressValidation) {
		return nil, false, err
	}
	// Only a failure to answer sends us to the fallback. A primary that answered
	// is authoritative for this lookup, including when it answered insecurely:
	// re-asking elsewhere on an insecure answer would let anyone who can degrade
	// the local node choose which resolver we believe.
	if err == nil {
		return ips, secure, nil
	}
	if r.fallback == nil {
		return ips, secure, err
	}
	r.logf("local resolver could not answer %s (%v); trying validated fallback", host, err)
	ips, secure, err = r.fallback.LookupIP(ctx, network, host)
	if err != nil {
		return nil, false, err
	}
	if !secure || len(ips) == 0 {
		return nil, false, strictaddr.ErrAddressValidation
	}
	return ips, true, nil
}

func (r *resolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	recs, secure, err := r.primary.LookupTLSA(ctx, service, proto, name)
	if err == nil {
		return recs, secure, nil
	}
	if r.fallback == nil {
		return recs, secure, err
	}
	r.logf("local resolver could not answer TLSA for %s (%v); trying validated fallback", name, err)
	return r.fallback.LookupTLSA(ctx, service, proto, name)
}
