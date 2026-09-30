package failover

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	letsresolver "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"github.com/pirate-social-club/fingertipd/internal/strictaddr"
)

func TestStrictSocketFailureUsesAuthenticatedFallback(t *testing.T) {
	primary, _ := strictaddr.New(func(context.Context, string, uint16) *letsresolver.DNSResult {
		return &letsresolver.DNSResult{Err: &net.OpError{Op: "dial", Net: "udp", Err: syscall.ECONNREFUSED}}
	})
	for _, secure := range []bool{true, false} {
		for _, hasAddress := range []bool{true, false} {
			fallback := &stub{secure: secure}
			if hasAddress {
				fallback.ips = []net.IP{net.ParseIP("127.0.0.1")}
			}
			ips, validated, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip", "test.hns")
			if fallback.ipCalls != 1 {
				t.Fatal("socket failure did not consult fallback")
			}
			if secure && hasAddress {
				if err != nil || !validated || len(ips) != 1 {
					t.Fatalf("authenticated fallback rejected: %v", err)
				}
			} else if !errors.Is(err, strictaddr.ErrAddressValidation) || validated || len(ips) != 0 {
				t.Fatalf("invalid fallback accepted: %v %v %v", ips, validated, err)
			}
		}
	}
}

func TestTransportCannotHideAnotherFamilyValidationFailure(t *testing.T) {
	for _, badType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		primary, _ := strictaddr.New(func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
			if qtype == badType {
				return &letsresolver.DNSResult{Secure: false}
			}
			return &letsresolver.DNSResult{Err: &net.OpError{Op: "read", Net: "udp", Err: syscall.ETIMEDOUT}}
		})
		fallback := &stub{ips: []net.IP{net.ParseIP("127.0.0.1")}, secure: true}
		ips, secure, err := mustNew(t, primary, fallback).LookupIP(context.Background(), "ip", "test.hns")
		if !errors.Is(err, strictaddr.ErrAddressValidation) || len(ips) != 0 || secure || fallback.ipCalls != 0 {
			t.Fatalf("transport hid invalid answer: %v %v %v fallback=%d", ips, secure, err, fallback.ipCalls)
		}
	}
}

func TestCanceledCallerNeverUsesFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	primary := &stub{err: errors.New("local unavailable")}
	fallback := &stub{secure: true, ips: []net.IP{net.ParseIP("127.0.0.1")}}
	_, _, err := mustNew(t, primary, fallback).LookupIP(ctx, "ip", "test.hns")
	if !errors.Is(err, context.Canceled) || primary.ipCalls != 0 || fallback.ipCalls != 0 {
		t.Fatalf("canceled caller caused lookup: %v primary=%d fallback=%d", err, primary.ipCalls, fallback.ipCalls)
	}
}
