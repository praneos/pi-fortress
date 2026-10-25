package engine

import (
	"crypto/tls"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/fence"
	"pi-fortress/internal/keyshape"
	"pi-fortress/internal/testsupport"
)

// The engine mints no leaf for an SNI that holds a key or a placeholder,
// and its log does not hold the key. A clean name still gets its leaf.
func TestKeyShapedSNIGetsNoLeaf(t *testing.T) {
	tr, err := fence.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	all := tr.All()
	heads, _ := keyshape.Heads(tr.Rules)
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	key := "ghp_" + strings.Repeat("A1b2", 9)
	leaves := countLeaves(t)
	addr, store, logs, _ := startEngineWith(t, "", orig, nil, func(e *Engine) {
		e.KeyShape = func(name string) string { return keyshape.Match(all, heads, name) }
	})
	for _, sni := range []string{
		key + ".evil.example",
		key[:20] + "." + key[20:] + ".evil.example",
		"pf_0123456789abcdef_GITHUB_TOKEN.evil.example",
	} {
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
			t.Fatalf("handshake with key-shaped sni %q succeeded", sni)
		}
		raw.Close()
		waitLog(t, logs, "sni key_shape refused")
		if n := leaves.count(sni); n != 0 {
			t.Fatalf("%d leaves were minted for %q", n, sni)
		}
	}
	tc := clientTLS(t, addr, "api.github.com", store, nil)
	tc.Close()
	if leaves.count("api.github.com") != 1 {
		t.Fatal("a clean name got no leaf")
	}
	if l := strings.ToLower(logs.String()); strings.Contains(l, strings.ToLower(key[:20])) || strings.Contains(l, "0123456789abcdef") {
		t.Fatalf("key in the engine log: %s", logs.String())
	}
}
