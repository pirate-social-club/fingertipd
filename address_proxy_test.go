package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	letsresolver "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"github.com/pirate-social-club/fingertipd/internal/failover"
	"github.com/pirate-social-club/fingertipd/internal/strictaddr"
)

type countingListener struct {
	net.Listener
	connections atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.connections.Add(1)
	}
	return connection, err
}

func TestProxyRequiresAuthenticatedAddressesBeforeConnecting(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	for _, mode := range []string{"valid", "A-insecure", "AAAA-insecure", "A-servfail", "AAAA-servfail", "wrong-dane", "missing-tlsa", "insecure-tlsa"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int64
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "authenticated gateway")
			}))
			listener := &countingListener{Listener: upstream.Listener}
			upstream.Listener = listener
			upstream.StartTLS()
			defer upstream.Close()
			pin := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
			if mode == "wrong-dane" {
				pin[0] ^= 1
			}
			query := func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
				result := &letsresolver.DNSResult{Secure: true}
				switch qtype {
				case dns.TypeA:
					result.Records = []dns.RR{&dns.A{A: net.ParseIP("127.0.0.1")}}
					if mode == "A-insecure" {
						result.Secure = false
					}
					if mode == "A-servfail" {
						result.Err = letsresolver.ErrServFail
					}
				case dns.TypeAAAA:
					// Signed NODATA is the valid IPv4-only control. Even with a
					// usable A, an unauthenticated or failed AAAA must be terminal.
					if mode == "AAAA-insecure" {
						result.Secure = false
						result.Records = []dns.RR{&dns.AAAA{AAAA: net.ParseIP("::1")}}
					}
					if mode == "AAAA-servfail" {
						result.Err = letsresolver.ErrServFail
					}
				case dns.TypeTLSA:
					if mode != "missing-tlsa" {
						result.Records = []dns.RR{&dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(pin[:])}}
					}
					if mode == "insecure-tlsa" {
						result.Secure = false
					}
				}
				return result
			}
			strict, err := strictaddr.New(query)
			if err != nil {
				t.Fatal(err)
			}
			// A working fallback must not conceal either kind of address
			// failure. The real failover and letsdane handlers are exercised.
			var fallbackCalls atomic.Int64
			fallback, err := strictaddr.New(func(ctx context.Context, host string, qtype uint16) *letsresolver.DNSResult {
				fallbackCalls.Add(1)
				return &letsresolver.DNSResult{Secure: true, Records: []dns.RR{&dns.A{A: net.ParseIP("127.0.0.1")}}}
			})
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := failover.New(strict, fallback, nil)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := newLetsDANEConfig(ca, key, resolver).NewHandler()
			if err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewServer(handler)
			defer proxy.Close()
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			_, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			response, requestErr := client.Get("https://test.hns:" + port + "/")
			if response != nil {
				defer response.Body.Close()
			}
			if mode == "valid" {
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				body, err := io.ReadAll(response.Body)
				if err != nil || response.StatusCode != 200 || string(body) != "authenticated gateway" || requests.Load() != 1 {
					t.Fatalf("valid DANE control failed: status=%d body=%q requests=%d err=%v", response.StatusCode, body, requests.Load(), err)
				}
				return
			}
			if requestErr == nil || requests.Load() != 0 {
				t.Fatalf("negative reached application: error=%v requests=%d", requestErr, requests.Load())
			}
			if mode == "A-insecure" || mode == "AAAA-insecure" || mode == "A-servfail" || mode == "AAAA-servfail" {
				if listener.connections.Load() != 0 || fallbackCalls.Load() != 0 {
					t.Fatalf("address refusal opened a connection: upstream=%d fallback=%d", listener.connections.Load(), fallbackCalls.Load())
				}
			}
		})
	}
}
