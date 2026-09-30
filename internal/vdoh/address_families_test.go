package vdoh

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAddressFamiliesCannotConcealFailedValidation(t *testing.T) {
	for _, mode := range []string{"bad-A", "bad-AAAA", "signed-AAAA-absence"} {
		t.Run(mode, func(t *testing.T) {
			z := newZone(t, "pirate")
			now := time.Unix(1_800_000_000, 0)
			sign := func(rr dns.RR) *dns.RRSIG {
				return z.sign(t, []dns.RR{rr}, now.Add(-time.Hour), now.Add(24*time.Hour))
			}
			a := aRecord("app.pirate", "127.0.0.1")
			aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: "app.pirate.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("::1")}
			aSig, aaaaSig, keySig := sign(a), sign(aaaa), sign(z.key)
			if mode != "signed-AAAA-absence" {
				sig := aSig
				if mode == "bad-AAAA" {
					sig = aaaaSig
				}
				bytes, err := base64.StdEncoding.DecodeString(sig.Signature)
				if err != nil {
					t.Fatal(err)
				}
				bytes[0] ^= 1
				sig.Signature = base64.StdEncoding.EncodeToString(bytes)
			}
			proof := nsec("app.pirate", "zzz.pirate")
			proofSig := sign(proof)
			srv, _ := newEndpoint(t, func(q dns.Question, req *dns.Msg) *dns.Msg {
				switch q.Qtype {
				case dns.TypeDNSKEY:
					return reply(req, dns.RcodeSuccess, z.key, keySig)
				case dns.TypeA:
					return reply(req, dns.RcodeSuccess, a, aSig)
				case dns.TypeAAAA:
					if mode == "signed-AAAA-absence" {
						m := reply(req, dns.RcodeSuccess)
						m.Ns = []dns.RR{proof, proofSig}
						return m
					}
					return reply(req, dns.RcodeSuccess, aaaa, aaaaSig)
				}
				return reply(req, dns.RcodeServerFailure)
			})
			ips, secure, err := testResolver(t, srv.URL, z).LookupIP(context.Background(), "ip", "app.pirate")
			if mode == "signed-AAAA-absence" {
				if err != nil || !secure || len(ips) != 1 || !ips[0].Equal(a.A) {
					t.Fatalf("signed absence rejected: %v %v %v", ips, secure, err)
				}
			} else if err == nil || secure || len(ips) != 0 {
				t.Fatalf("bad family hidden: %v %v %v", ips, secure, err)
			}
		})
	}
}
