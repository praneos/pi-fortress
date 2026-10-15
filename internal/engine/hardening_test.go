package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/netip"
	"pi-fortress/internal/blocklist"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/ca"
)

func certPool(store *ca.Store) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(store.Root())
	return pool
}

func waitLog(t *testing.T, logs *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log=%q want %q", logs.String(), want)
}

func TestEmptySNIRefused(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	addr, _, logs, _ := startEngine(t, "", orig, nil)
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake without sni succeeded")
	}
	waitLog(t, logs, "sni empty refused")
}

// The sinkhole fires only for a client that asks the resolver. A client
// that brings its own address for a listed name (curl --resolve,
// /etc/hosts) reaches the engine with a well-formed SNI. This is the only
// place left that can refuse it. Refused before a leaf is minted.
func TestBlockedSNIRefused(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	leaves := countLeaves(t)
	addr, _, logs, _ := startEngineWith(t, "", orig, nil, func(e *Engine) {
		e.Blocked = blocklist.New("phish.example")
	})
	for _, sni := range []string{"phish.example", "login.phish.example", "PHISH.example."} {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
			NextProtos:         []string{"http/1.1"},
			MinVersion:         tls.VersionTLS12,
		})
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err == nil {
			t.Fatalf("handshake with blocked sni %q succeeded", sni)
		}
		raw.Close()
	}
	waitLog(t, logs, "sni blocked refused sni=phish.example")
	for _, sni := range []string{"phish.example", "login.phish.example"} {
		if n := leaves.count(sni); n != 0 {
			t.Fatalf("%d leaves were minted for blocked %q", n, sni)
		}
	}
}

// A nil list is the state before the first apply has compiled anything.
// It must behave exactly like no list at all.
func TestNilBlockedListIsOpen(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	addr, store, logs, _ := startEngineWith(t, "", orig, nil, func(e *Engine) { e.Blocked = nil })
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: "example.com", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = tc.Handshake()
	if strings.Contains(logs.String(), "blocked refused") {
		t.Fatal("nil list refused a name")
	}
}

func TestOrigDstPort80Refused(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:80")
	addr, store, logs, _ := startEngine(t, "", orig, nil)
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: "example.com", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake toward port 80 succeeded")
	}
	waitLog(t, logs, "not port 443")
}

func TestMaxConnsDropLogged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	e := &Engine{
		CA:        testStore(t),
		OrigDst:   func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.0.2.24:443"), nil },
		Handshake: 2 * time.Second,
		Idle:      time.Second,
		MaxConns:  1,
		Log:       log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, ln) }()
	first, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("second connection was served: n=%d err=%v", n, err)
	}
	waitLog(t, logs, "max_conns=1 drop")
}

func TestPanicInHandlerFreesSlot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	var calls atomic.Int32
	store := testStore(t)
	e := &Engine{
		CA: store,
		OrigDst: func(net.Conn) (netip.AddrPort, error) {
			if calls.Add(1) == 1 {
				panic("boom")
			}
			return netip.MustParseAddrPort("192.0.2.24:443"), nil
		},
		Handshake: 2 * time.Second,
		Idle:      time.Second,
		MaxConns:  1,
		Log:       log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, ln) }()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	c.Close()
	waitLog(t, logs, "panic src=")
	tc := clientTLS(t, ln.Addr().String(), "example.com", store, nil)
	tc.Close()
	if calls.Load() != 2 {
		t.Fatalf("origdst calls=%d", calls.Load())
	}
}
