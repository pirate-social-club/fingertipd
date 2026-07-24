package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/buffrr/letsdane"
	letsresolver "github.com/buffrr/letsdane/resolver"

	"github.com/miekg/dns"
	"github.com/pirate-social-club/fingertipd/internal/failover"
	"github.com/pirate-social-club/fingertipd/internal/hnsanchor"
	"github.com/pirate-social-club/fingertipd/internal/netutil"
	"github.com/pirate-social-club/fingertipd/internal/vdoh"
)

const (
	caFileName       = "ca.pem"
	caKeyFileName    = "ca-key.pem"
	readinessName    = "_443._tcp.app.pirate."
	shutdownDeadline = 4 * time.Second
	pollInterval     = 2 * time.Second
	dnsStartDeadline = 20 * time.Second
)

type config struct {
	dataDir       string
	hnsdPath      string
	rootAddr      string
	recursiveAddr string
	hnsdSeed      string
	dohEndpoint   string
}

type eventWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *eventWriter) emit(v any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(v); err != nil {
		log.Printf("write event: %v", err)
	}
}

const defaultDOHFallbackEndpoint = ""

func parseConfig(args []string) (config, error) {
	return parseConfigWithDOHDefault(args, defaultDOHFallbackEndpoint)
}

func parseConfigWithDOHDefault(args []string, defaultDOHEndpoint string) (config, error) {
	fs := flag.NewFlagSet("fingertipd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg config
	fs.StringVar(&cfg.dataDir, "data-dir", "", "persistent data directory")
	fs.StringVar(&cfg.hnsdPath, "hnsd-path", "", "path to hnsd")
	fs.StringVar(&cfg.rootAddr, "root-addr", "127.0.0.1:15349", "hnsd authoritative DNS listen address")
	fs.StringVar(&cfg.recursiveAddr, "recursive-addr", "127.0.0.1:15350", "hnsd recursive DNS listen address")
	fs.StringVar(&cfg.hnsdSeed, "hnsd-seed", "", "optional loopback hnsd peer for hermetic tests")
	// Off unless explicitly configured. When set, this is a FALLBACK consulted
	// only when the local node cannot answer; it never becomes the primary.
	// Answers from it are validated locally against the chain's DS anchor, so
	// the endpoint is untrusted encrypted transport, not an authority. This is
	// NOT full DNSSEC validation: see internal/vdoh for the exact scope.
	fs.StringVar(&cfg.dohEndpoint, "doh-fallback-endpoint", defaultDOHEndpoint,
		"optional https DoH URL (including its query path) used only when the local node cannot answer")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	explicitDOH := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "doh-fallback-endpoint" {
			explicitDOH = true
		}
	})
	if cfg.dohEndpoint != "" && !explicitDOH && !vdoh.SupportsDelegatedZones() {
		return config{}, errors.New("implicit DoH fallback requires delegated-zone validation; use explicit -doh-fallback-endpoint only for controlled top-level testing")
	}
	// Reject a malformed endpoint here rather than after hnsd has been started:
	// a configuration error should not cost a subsystem launch to discover.
	if cfg.dohEndpoint != "" {
		if err := vdoh.ValidateEndpoint(cfg.dohEndpoint); err != nil {
			return config{}, err
		}
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.dataDir == "" || cfg.hnsdPath == "" {
		return config{}, errors.New("-data-dir and -hnsd-path are required")
	}
	for name, addr := range map[string]string{"root": cfg.rootAddr, "recursive": cfg.recursiveAddr} {
		if err := netutil.LoopbackHostPort(addr); err != nil {
			return config{}, fmt.Errorf("%s address %w", name, err)
		}
	}
	if cfg.hnsdSeed != "" {
		if err := netutil.LoopbackHostPort(cfg.hnsdSeed); err != nil {
			return config{}, fmt.Errorf("hnsd seed %w", err)
		}
	}
	return cfg, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Printf("configuration: %v", err)
		os.Exit(2)
	}
	if err := run(cfg, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "error", "error": err.Error()})
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(cfg config, stdout *os.File) error {
	if err := os.MkdirAll(cfg.dataDir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	prefix := filepath.Join(cfg.dataDir, "hnsd")
	if err := os.MkdirAll(prefix, 0700); err != nil {
		return fmt.Errorf("create hnsd prefix: %w", err)
	}

	ca, key, caPath, err := loadOrCreateCA(cfg.dataDir)
	if err != nil {
		return err
	}

	hnsdArgs := []string{"-n", cfg.rootAddr, "-r", cfg.recursiveAddr, "-x", prefix, "-t"}
	if cfg.hnsdSeed != "" {
		hnsdArgs = append([]string{"-s", cfg.hnsdSeed}, hnsdArgs...)
	}
	child := exec.Command(cfg.hnsdPath, hnsdArgs...)
	child.Stdout = os.Stderr
	child.Stderr = os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start hnsd: %w", err)
	}

	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	defer stopChild(child, childDone)
	if err := waitForDNS(cfg.rootAddr, cfg.recursiveAddr, dnsStartDeadline); err != nil {
		return err
	}

	localResolver, err := letsresolver.NewStub(cfg.recursiveAddr)
	if err != nil {
		return fmt.Errorf("create resolver: %w", err)
	}

	// The DoH fallback is opt-in and strictly secondary. Its trust anchor comes
	// from the loopback hnsd root socket -- never from the endpoint itself, and
	// never from recursive data -- which internal/hnsanchor enforces by refusing
	// any non-loopback address.
	var dohFallback failover.Resolver
	if cfg.dohEndpoint != "" {
		anchors, err := hnsanchor.New(cfg.rootAddr)
		if err != nil {
			return fmt.Errorf("create anchor provider: %w", err)
		}
		validating, err := vdoh.New(cfg.dohEndpoint, anchors.Anchor)
		if err != nil {
			return fmt.Errorf("create validating doh resolver: %w", err)
		}
		dohFallback = validating
		log.Printf("validated DoH fallback enabled: %s (anchored on %s)", cfg.dohEndpoint, cfg.rootAddr)
	}

	resolver, err := failover.New(localResolver, dohFallback, log.Printf)
	if err != nil {
		return fmt.Errorf("compose resolver: %w", err)
	}
	handler, err := newLetsDANEConfig(ca, key, resolver).NewHandler()
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()

	events := &eventWriter{enc: json.NewEncoder(stdout)}
	events.emit(map[string]any{"type": "ready", "proxyAddr": listener.Addr().String(), "caPath": caPath})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go reportSync(ctx, cfg.rootAddr, cfg.recursiveAddr, events)

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownDeadline)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown proxy: %w", err)
		}
		return nil
	case err := <-childDone:
		return fmt.Errorf("hnsd exited: %w", err)
	case err := <-serverDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("proxy exited: %w", err)
	}
}

func newLetsDANEConfig(ca *x509.Certificate, key *rsa.PrivateKey, resolver letsresolver.Resolver) *letsdane.Config {
	return &letsdane.Config{
		Certificate: ca,
		PrivateKey:  key,
		Validity:    24 * time.Hour,
		Resolver:    resolver,
		// RFC 7671 section 5.1 binds a DANE-EE server identity through
		// its DNSSEC-authenticated TLSA association. Certificate name
		// checks do not apply and would reject legitimate shared DANE
		// gateways whose leaf certificate intentionally has no SAN.
		SkipNameChecks: true,
	}
}

func waitForDNS(rootAddr, recursiveAddr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &dns.Client{Timeout: 250 * time.Millisecond}
	for time.Now().Before(deadline) {
		if dnsResponds(client, rootAddr, ".", dns.TypeNS) &&
			dnsResponds(client, recursiveAddr, "height.tip.chain.hnsd.", dns.TypeTXT) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("hnsd DNS sockets did not become ready")
}

func dnsResponds(client *dns.Client, addr, name string, queryType uint16) bool {
	msg := new(dns.Msg)
	msg.SetQuestion(name, queryType)
	response, _, err := client.Exchange(msg, addr)
	return err == nil && response != nil
}

func stopChild(child *exec.Cmd, done <-chan error) {
	if child == nil || child.Process == nil {
		return
	}
	if child.ProcessState != nil && child.ProcessState.Exited() {
		return
	}
	_ = syscall.Kill(-child.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
		return
	case <-time.After(shutdownDeadline):
		_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func reportSync(ctx context.Context, rootAddr, recursiveAddr string, events *eventWriter) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	last := ""
	for {
		height, synced := querySync(rootAddr, recursiveAddr)
		key := strconv.FormatUint(uint64(height), 10) + ":" + strconv.FormatBool(synced)
		if key != last {
			events.emit(map[string]any{"type": "sync", "height": height, "synced": synced})
			last = key
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func querySync(rootAddr, recursiveAddr string) (uint32, bool) {
	client := &dns.Client{Timeout: time.Second}
	height := queryHeight(client, rootAddr)
	msg := new(dns.Msg)
	msg.SetQuestion(readinessName, dns.TypeTLSA)
	msg.SetEdns0(1232, true)
	response, _, err := client.Exchange(msg, recursiveAddr)
	if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || !response.AuthenticatedData {
		return height, false
	}
	for _, answer := range response.Answer {
		if answer.Header().Rrtype == dns.TypeTLSA {
			return height, true
		}
	}
	return height, false
}

func queryHeight(client *dns.Client, addr string) uint32 {
	msg := new(dns.Msg)
	msg.SetQuestion("height.tip.chain.hnsd.", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassHESIOD
	response, _, err := client.Exchange(msg, addr)
	if err != nil || response == nil {
		return 0
	}
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok && len(txt.Txt) > 0 {
			value, err := strconv.ParseUint(strings.TrimSpace(txt.Txt[0]), 10, 32)
			if err == nil {
				return uint32(value)
			}
		}
	}
	return 0
}

func loadOrCreateCA(dir string) (*x509.Certificate, *rsa.PrivateKey, string, error) {
	certPath := filepath.Join(dir, caFileName)
	keyPath := filepath.Join(dir, caKeyFileName)
	certBytes, certErr := os.ReadFile(certPath)
	keyBytes, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, key, err := parseCA(certBytes, keyBytes)
		return cert, key, certPath, err
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, nil, "", errors.New("CA certificate and key must both exist or both be absent")
	}
	cert, key, err := letsdane.NewAuthority("Fingertip Local CA", "Pirate Social Club", 10*365*24*time.Hour, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writePrivateFile(certPath, certPEM); err != nil {
		return nil, nil, "", err
	}
	if err := writePrivateFile(keyPath, keyPEM); err != nil {
		_ = os.Remove(certPath)
		return nil, nil, "", err
	}
	return cert, key, certPath, nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return os.Chmod(path, 0600)
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || len(rest) != 0 || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA {
		return nil, nil, errors.New("invalid CA certificate")
	}
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || len(rest) != 0 || keyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, errors.New("invalid CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if err != nil || !ok || publicKey.N.Cmp(key.N) != 0 {
		return nil, nil, errors.New("CA key does not match certificate")
	}
	return cert, key, nil
}
