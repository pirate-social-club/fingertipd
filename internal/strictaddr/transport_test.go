package strictaddr

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	letsresolver "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
)

func TestSocketFailuresRemainRetryableWithoutPartialAddresses(t *testing.T) {
	for _, socketErr := range []error{syscall.ECONNREFUSED, syscall.ETIMEDOUT} {
		for _, failedType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r, _ := New(func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
				if qtype == failedType {
					return &letsresolver.DNSResult{Err: &net.OpError{Op: "read", Net: "udp", Err: socketErr}}
				}
				return addressResult(qtype)
			})
			ips, secure, err := r.LookupIP(context.Background(), "ip", "test.hns")
			if !errors.Is(err, socketErr) || errors.Is(err, ErrAddressValidation) || len(ips) != 0 || secure {
				t.Fatalf("socket failure misclassified or returned partial addresses: %v %v %v", ips, secure, err)
			}
		}
	}
}

func TestCancellationIsPreserved(t *testing.T) {
	r, _ := New(func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
		<-ctx.Done()
		return &letsresolver.DNSResult{Err: ctx.Err()}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ips, secure, err := r.LookupIP(ctx, "ip", "test.hns")
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAddressValidation) || len(ips) != 0 || secure {
		t.Fatalf("cancellation changed: %v %v %v", ips, secure, err)
	}
}
