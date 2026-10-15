package engine

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/corepolicy"
)

func testForward(t *testing.T) *corepolicy.Forward {
	t.Helper()
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.domains")
	core := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(allow, []byte("github.com\npf-core-echo.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("api.x.ai XAI_API_KEY\npf-core-echo.test *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := corepolicy.LoadForward(allow, core)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Paranoid refuses at the SNI, before a leaf exists. The handshake of
// the client fails in the same way as for a blocked name.
func TestParanoidSNIRefusedBeforeLeaf(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	leaves := countLeaves(t)
	addr, store, logs, _ := startEngineWith(t, "", orig, nil, func(e *Engine) {
		e.Forward = testForward(t)
	})
	for _, sni := range []string{"evil.example", "evil.api.x.ai", "pf-core-echo.test"} {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(raw, &tls.Config{
			RootCAs:    certPool(store),
			ServerName: sni,
			NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS12,
		})
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err == nil {
			t.Fatalf("handshake with unlisted sni %q succeeded", sni)
		}
		raw.Close()
		waitLog(t, logs, "sni paranoid refused sni="+sni)
		if n := leaves.count(sni); n != 0 {
			t.Fatalf("%d leaves were minted for unlisted %q", n, sni)
		}
	}
}

// A listed name, and the open echo, still get their leaf. The core echo
// needs the lab marker, although both policy files name it.
func TestParanoidListedSNIProceeds(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	for _, tc := range []struct {
		sni string
		lab bool
	}{
		{sni: "api.github.com"},
		{sni: "api.x.ai"},
		{sni: corepolicy.OpenEcho},
		{sni: corepolicy.CoreEcho, lab: true},
	} {
		addr, store, logs, _ := startEngineWith(t, "", orig, nil, func(e *Engine) {
			e.Forward = testForward(t)
			e.LabEcho = tc.lab
		})
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		conn := tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: tc.sni, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake for %q: %v", tc.sni, err)
		}
		raw.Close()
		if strings.Contains(logs.String(), "paranoid refused") {
			t.Fatalf("%q was refused: %s", tc.sni, logs.String())
		}
	}
}

// When off, the oracle is nil, and each well-formed SNI still gets a leaf.
func TestParanoidOffMintsForUnlistedSNI(t *testing.T) {
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	addr, store, logs, _ := startEngine(t, "", orig, nil)
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: "evil.example", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "paranoid refused") {
		t.Fatal("paranoid fired with no forward set")
	}
}

// Paranoid is the posture of the agent network. A desk on an inspect
// listener gets a leaf for a name outside the forward set. The same name
// on the agent listener does not.
func TestParanoidHoldsOnlyTheAgentListener(t *testing.T) {
	agent, desk := twoListeners(t)
	store := testStore(t)
	logs := &syncBuf{}
	leaves := countLeaves(t)
	e := &Engine{
		CA:        store,
		OrigDst:   func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.0.2.24:443"), nil },
		Handshake: 3 * time.Second,
		Forward:   testForward(t),
		Log:       log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, agent, desk) }()
	hs := func(addr, sni string) {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: sni, NextProtos: []string{"http/1.1"}}).Handshake()
	}
	hs(agent.Addr().String(), "agent-side.example")
	waitLog(t, logs, "sni paranoid refused sni=agent-side.example")
	hs(desk.Addr().String(), "desk-side.example")
	if n := leaves.count("desk-side.example"); n == 0 {
		t.Fatalf("the desk got no leaf for a name outside the agent forward set; log:\n%s", logs)
	}
	if n := leaves.count("agent-side.example"); n != 0 {
		t.Fatalf("%d leaves for an unlisted name on the agent listener", n)
	}
}
