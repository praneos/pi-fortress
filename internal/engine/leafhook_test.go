package engine

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// leafCounter counts the leaves the engine asks the CA for, by name, for
// the length of the test.
type leafCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func countLeaves(t *testing.T) *leafCounter {
	t.Helper()
	c := &leafCounter{n: map[string]int{}}
	hook := func(sni string) {
		c.mu.Lock()
		c.n[strings.ToLower(strings.TrimSuffix(sni, "."))]++
		c.mu.Unlock()
	}
	testHookLeaf.Store(&hook)
	t.Cleanup(func() { testHookLeaf.Store(nil) })
	return c
}

func (c *leafCounter) count(sni string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[strings.ToLower(strings.TrimSuffix(sni, "."))]
}

// The counter that the no-leaf assertions depend on does see a leaf when
// one is minted. Without this, a counter that never fired would also pass them.
func TestLeafCounterSeesAMintedLeaf(t *testing.T) {
	leaves := countLeaves(t)
	addr, store, _, _ := startEngine(t, "", netip.MustParseAddrPort("192.0.2.24:443"), nil)
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{RootCAs: certPool(store), ServerName: "listed.example", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if n := leaves.count("listed.example"); n != 1 {
		t.Fatalf("leaves for listed.example: %d", n)
	}
}
