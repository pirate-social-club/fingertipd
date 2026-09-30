package strictaddr

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	letsresolver "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
)

func addressResult(qtype uint16) *letsresolver.DNSResult {
	var record dns.RR = &dns.A{A: net.ParseIP("127.0.0.1")}
	if qtype == dns.TypeAAAA {
		record = &dns.AAAA{AAAA: net.ParseIP("::1")}
	}
	return &letsresolver.DNSResult{Secure: true, Records: []dns.RR{record}}
}

func TestEveryFamilyMustValidateInEitherOrder(t *testing.T) {
	for _, badType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, badFirst := range []bool{true, false} {
			for _, failure := range []string{"insecure-data", "servfail"} {
				name := dns.TypeToString[badType] + "/" + failure
				if badFirst {
					name += "/failure-first"
				} else {
					name += "/success-first"
				}
				t.Run(name, func(t *testing.T) {
					release := map[uint16]chan struct{}{dns.TypeA: make(chan struct{}), dns.TypeAAAA: make(chan struct{})}
					started := make(chan uint16, 2)
					query := func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
						started <- qtype
						select {
						case <-ctx.Done():
							return &letsresolver.DNSResult{Err: ctx.Err()}
						case <-release[qtype]:
						}
						if qtype != badType {
							// Signed absence of the other family must not hide a failure.
							return &letsresolver.DNSResult{Secure: true}
						}
						result := addressResult(qtype)
						if failure == "servfail" {
							result.Err = letsresolver.ErrServFail
						} else {
							result.Secure = false
						}
						return result
					}
					r, err := New(query)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					done := make(chan error, 1)
					go func() {
						ips, secure, err := r.LookupIP(ctx, "ip", "test.hns")
						if len(ips) != 0 || secure {
							err = errors.New("failed family produced usable addresses")
						}
						done <- err
					}()
					for range 2 {
						select {
						case <-started:
						case <-ctx.Done():
							t.Fatal("family queries did not start")
						}
					}
					otherType := uint16(dns.TypeA)
					if badType == dns.TypeA {
						otherType = dns.TypeAAAA
					}
					if badFirst {
						close(release[badType])
					} else {
						close(release[otherType])
						select {
						case <-done:
							t.Fatal("returned before the other family validated")
						case <-time.After(10 * time.Millisecond):
						}
						close(release[badType])
					}
					select {
					case err := <-done:
						if !errors.Is(err, ErrAddressValidation) {
							t.Fatalf("want terminal validation error, got %v", err)
						}
					case <-ctx.Done():
						t.Fatal("failure did not stop resolution")
					}
				})
			}
		}
	}
}

func TestAuthenticatedAddressesAndNODATA(t *testing.T) {
	for _, network := range []string{"ip", "ip4", "ip6"} {
		t.Run(network, func(t *testing.T) {
			r, _ := New(func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
				if network == "ip" && qtype == dns.TypeAAAA {
					return &letsresolver.DNSResult{Secure: true}
				}
				return addressResult(qtype)
			})
			ips, secure, err := r.LookupIP(context.Background(), network, "test.hns")
			if err != nil || !secure || len(ips) != 1 {
				t.Fatalf("valid address with signed absence rejected: %v %v %v", ips, secure, err)
			}
		})
	}
}

func TestNoUsableAddressFailsClosed(t *testing.T) {
	for _, result := range []*letsresolver.DNSResult{nil, {Secure: true}, {Secure: false}} {
		r, _ := New(func(context.Context, string, uint16) *letsresolver.DNSResult { return result })
		ips, secure, err := r.LookupIP(context.Background(), "ip", "test.hns")
		if len(ips) != 0 || secure || !errors.Is(err, ErrAddressValidation) {
			t.Fatalf("invalid empty result accepted: %v %v %v", ips, secure, err)
		}
	}
}

func TestQueryRequired(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("accepted missing query")
	}
}
