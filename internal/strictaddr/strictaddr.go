// Package strictaddr requires authenticated results for every requested address
// family before letsdane can use any address. The helper is an HNS sidecar;
// ordinary browser HTTPS does not use this resolver.
package strictaddr

import (
	"context"
	"errors"
	"fmt"
	"net"

	letsresolver "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
)

// ErrAddressValidation is terminal, including when an underlying DNS error is
// ambiguous about validation. An alternate resolver must not route around it.
var ErrAddressValidation = errors.New("HNS address validation failed")

type Query func(context.Context, string, uint16) *letsresolver.DNSResult

type Resolver struct {
	query Query
	tlsa  letsresolver.DefaultResolver
}

func New(query Query) (*Resolver, error) {
	if query == nil {
		return nil, errors.New("strictaddr: query is required")
	}
	return &Resolver{query: query, tlsa: letsresolver.DefaultResolver{Query: query}}, nil
}

type answer struct {
	qtype  uint16
	result *letsresolver.DNSResult
}

func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch network {
	case "ip":
	case "ip4":
		qtypes = []uint16{dns.TypeA}
	case "ip6":
		qtypes = []uint16{dns.TypeAAAA}
	default:
		return nil, false, fmt.Errorf("%w: unsupported network %q", ErrAddressValidation, network)
	}
	if host == "" {
		return nil, false, fmt.Errorf("%w: empty hostname", ErrAddressValidation)
	}

	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Buffer every result so early refusal cannot leave a sender blocked.
	answers := make(chan answer, len(qtypes))
	for _, qtype := range qtypes {
		go func(qtype uint16) {
			answers <- answer{qtype, r.query(lookupCtx, host, qtype)}
		}(qtype)
	}
	var ips []net.IP
	for range qtypes {
		var a answer
		select {
		case <-ctx.Done():
			return nil, false, fmt.Errorf("%w: %w", ErrAddressValidation, ctx.Err())
		case a = <-answers:
		}
		if a.result == nil {
			return nil, false, fmt.Errorf("%w: %s %s returned no result", ErrAddressValidation, host, dns.TypeToString[a.qtype])
		}
		if a.result.Err != nil {
			return nil, false, fmt.Errorf("%w: %s %s: %w", ErrAddressValidation, host, dns.TypeToString[a.qtype], a.result.Err)
		}
		if !a.result.Secure {
			return nil, false, fmt.Errorf("%w: %s %s is unauthenticated", ErrAddressValidation, host, dns.TypeToString[a.qtype])
		}
		// An authenticated empty result represents proven absence for this
		// family. It must neither invalidate a good other family nor clear an
		// error from it. Only records of the requested family are usable.
		for _, rr := range a.result.Records {
			switch record := rr.(type) {
			case *dns.A:
				if a.qtype == dns.TypeA {
					ips = append(ips, record.A)
				}
			case *dns.AAAA:
				if a.qtype == dns.TypeAAAA {
					ips = append(ips, record.AAAA)
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, false, fmt.Errorf("%w: %s has no authenticated address", ErrAddressValidation, host)
	}
	return ips, true, nil
}

// Keep letsdane's TLSA security result and error semantics unchanged. Address
// validation is additional to its existing DANE certificate authentication.
func (r *Resolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	return r.tlsa.LookupTLSA(ctx, service, proto, name)
}
