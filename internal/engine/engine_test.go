package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"go/parser"
	"go/token"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/ca"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/testsupport"
)

func testStore(t *testing.T) *ca.Store {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testsupport.CATemplate(serial, "pf-engine-test-ca")
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...,
	)
	s, err := ca.LoadPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startEngine(t *testing.T, sock string, orig netip.AddrPort, origErr error) (addr string, store *ca.Store, logs *syncBuf, stop func()) {
	t.Helper()
	return startEngineWith(t, sock, orig, origErr, nil)
}

// syncBuf is the test log sink. The engine logs from its per-connection
// goroutines while the test reads. So a plain bytes.Buffer here is a data
// race, and the race detector is correct about it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startEngineWith(t *testing.T, sock string, orig netip.AddrPort, origErr error, tweak func(*Engine)) (addr string, store *ca.Store, logs *syncBuf, stop func()) {
	t.Helper()
	store = testStore(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs = &syncBuf{}
	e := &Engine{
		Sock: sock,
		CA:   store,
		OrigDst: func(net.Conn) (netip.AddrPort, error) {
			if origErr != nil {
				return netip.AddrPort{}, origErr
			}
			return orig, nil
		},
		Handshake: 3 * time.Second,
		Idle:      3 * time.Second,
		MaxConns:  32,
		Log:       log.New(logs, "", 0),
	}
	if tweak != nil {
		tweak(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, ln) }()
	stop = func() {
		cancel()
		ln.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	}
	t.Cleanup(stop)
	return ln.Addr().String(), store, logs, stop
}

func clientTLS(t *testing.T, addr, sni string, store *ca.Store, alpns []string) *tls.Conn {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(store.Root())
	if len(alpns) == 0 {
		alpns = []string{"http/1.1"}
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		NextProtos: alpns,
		MinVersion: tls.VersionTLS12,
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	return tc
}

func startEchoBroker(t *testing.T) (string, <-chan preamble.Preamble) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan preamble.Preamble, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				p, err := preamble.Decode(br)
				if err != nil {
					return
				}
				ch <- *p
				_, _ = io.Copy(c, br)
			}(c)
		}
	}()
	return sock, ch
}

func TestEchoPreamble(t *testing.T) {
	sock, ch := startEchoBroker(t)
	orig := netip.MustParseAddrPort("192.0.2.20:443")
	addr, store, _, _ := startEngine(t, sock, orig, nil)
	tc := clientTLS(t, addr, "example.com", store, nil)
	defer tc.Close()
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := tc.Write(req); err != nil {
		t.Fatal(err)
	}
	_ = tc.CloseWrite()
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(tc)
	if err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("GET / HTTP/1.1")) {
		t.Fatalf("echo=%q", got)
	}
	select {
	case p := <-ch:
		if p.SNI != "example.com" {
			t.Fatalf("sni=%q", p.SNI)
		}
		if p.OrigDst != orig {
			t.Fatalf("orig=%s", p.OrigDst)
		}
		if p.ConnID == "" {
			t.Fatal("empty conn id")
		}
		if p.ALPN != "http/1.1" {
			t.Fatalf("alpn=%q", p.ALPN)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no preamble")
	}
}

func TestSockMissing502(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.26:443")
	addr, store, _, _ := startEngine(t, filepath.Join(t.TempDir(), "missing.sock"), orig, nil)
	tc := clientTLS(t, addr, "example.com", store, nil)
	defer tc.Close()
	_, _ = tc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := tc.Read(buf)
	if n == 0 || !strings.Contains(string(buf[:n]), "502") {
		t.Fatalf("want 502 after the handshake, got %q", buf[:n])
	}
}

func TestOrigDstError(t *testing.T) {
	addr, store, _, _ := startEngine(t, "", netip.AddrPort{}, io.EOF)
	pool := x509.NewCertPool()
	pool.AddCert(store.Root())
	_, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("expected handshake fail")
	}
}

func TestBadClientHello(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.22:443")
	sock := filepath.Join(t.TempDir(), "broker.sock")
	bl, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	var dials sync.WaitGroup
	forwarded := make(chan struct{}, 1)
	dials.Add(1)
	go func() {
		defer dials.Done()
		if c, err := bl.Accept(); err == nil {
			forwarded <- struct{}{}
			c.Close()
		}
	}()
	var eng *Engine
	addr, _, logs, _ := startEngineWith(t, sock, orig, nil, func(e *Engine) { eng = e })
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || len(got) != 0 {
		t.Fatalf("want a bare FIN (no alert, no response), got %q err=%v", got, err)
	}
	want := "peek src=" + c.LocalAddr().String() + " dst=192.0.2.22:443 err=hello: malformed"
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("missing %q; log=%q", want, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for len(eng.sem) != 0 || eng.perSrc.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("slot not released: sem=%d perSrc=%d", len(eng.sem), eng.perSrc.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := strings.Count(logs.String(), "\n"); n != 1 {
		t.Fatalf("want exactly one log line, got %d: %q", n, logs.String())
	}
	bl.Close()
	dials.Wait()
	select {
	case <-forwarded:
		t.Fatal("malformed hello reached the broker")
	default:
	}
}

func TestH2OnlyLog(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.23:443")
	addr, store, logs, _ := startEngine(t, "", orig, nil)
	pool := x509.NewCertPool()
	pool.AddCert(store.Root())
	_, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("expected alpn fail")
	}
	if !strings.Contains(err.Error(), "no application protocol") {
		t.Fatalf("want no_application_protocol alert, got %v", err)
	}
	want := "alpn_h2_only refused: engine speaks http/1.1 only sni=example.com"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log=%q err=%v", logs.String(), err)
}

func TestHalfClose(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := preamble.Decode(br); err != nil {
			return
		}
		uc := c.(*net.UnixConn)
		_, _ = uc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nABCD"))
		_ = uc.CloseWrite()
		_, _ = io.Copy(io.Discard, br)
	}()
	orig := netip.MustParseAddrPort("192.0.2.25:443")
	addr, store, _, _ := startEngine(t, sock, orig, nil)
	tc := clientTLS(t, addr, "example.com", store, nil)
	defer tc.Close()
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = tc.CloseWrite()
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	body, err := io.ReadAll(tc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("ABCD")) {
		t.Fatalf("body=%q", body)
	}
}

func TestImportBoundary(t *testing.T) {
	forbidden := []string{
		"net/http",
		"pi-fortress/internal/fence",
		"pi-fortress/internal/secrets",
		"pi-fortress/internal/corepolicy",
		"pi-fortress/internal/dest",
		"pi-fortress/internal/broker",
		"pi-fortress/internal/httpwire",
	}
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports %s", name, path)
				}
			}
		}
	}
}
