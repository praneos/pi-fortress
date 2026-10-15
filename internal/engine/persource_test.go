package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// dialFrom opens a TCP connection to addr from a chosen loopback source, so
// one test can act as two agents. Linux routes all of 127/8 to lo.
func dialFrom(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skipf("dial from %s: %v (no 127/8 source on this host)", src, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// held reports whether the engine kept c open. A refused connection is
// closed at accept and reads EOF immediately. An admitted connection stays
// in the ClientHello peek, and times out on our short deadline.
func held(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// One agent at its cap is refused with a close, and a different agent
// still gets in. A closed connection gives its slot back. The global cap
// is much higher, so only the per-source rule can explain a refusal.
func TestPerSourceCapRefusesOverflowNotOtherAgents(t *testing.T) {
	var eng *Engine
	addr, _, logs, _ := startEngineWith(t, "/nonexistent", netip.MustParseAddrPort("192.0.2.1:443"), nil, func(e *Engine) {
		e.MaxPerSource = 2
		eng = e
	})

	a1 := dialFrom(t, "127.0.0.1", addr)
	a2 := dialFrom(t, "127.0.0.1", addr)
	if !held(a1) || !held(a2) {
		t.Fatalf("connections under the per-source cap were closed; log:\n%s", logs)
	}
	if held(dialFrom(t, "127.0.0.1", addr)) {
		t.Fatal("third connection from one address admitted over MaxPerSource=2")
	}
	if !strings.Contains(logs.String(), "max_conns_per_ip=2 drop src=127.0.0.1:") {
		t.Fatalf("refusal not logged; log:\n%s", logs)
	}
	if !held(dialFrom(t, "127.0.0.2", addr)) {
		t.Fatal("another agent address refused while the first was at its cap")
	}

	a1.Close()
	src := netip.MustParseAddr("127.0.0.1")
	deadline := time.Now().Add(5 * time.Second)
	for eng.perSrc.Count(src) > 1 {
		if time.Now().After(deadline) {
			t.Fatalf("count stuck at %d after a close", eng.perSrc.Count(src))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !held(dialFrom(t, "127.0.0.1", addr)) {
		t.Fatal("slot not returned to the address after its connection closed")
	}
}

func TestPerSourceDefaultAndOff(t *testing.T) {
	for _, tc := range []struct {
		set, want int
	}{{0, DefaultMaxPerSource}, {-1, 0}} {
		e := &Engine{MaxPerSource: tc.set}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		e.Serve(ctx, ln)
		if got := e.perSrc.Max(); got != tc.want {
			t.Fatalf("MaxPerSource %d: cap = %d, want %d", tc.set, got, tc.want)
		}
	}
}
