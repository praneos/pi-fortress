package broker

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"pi-fortress/internal/preamble"
)

// Handle runs on all connections at the same time. Thus it reads the Idle
// default and never stores it. Before, a write from one handler raced the
// reads of the other handlers. This was a data race on every broker that
// the CLI built, because the CLI never set Idle. The test asserts on the
// field itself, so it holds without -race also.
func TestHandleNeverWritesIdle(t *testing.T) {
	b, _ := testBroker(t)
	b.Idle = 0
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("192.168.1.1:443")}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c1, c2 := net.Pipe()
			defer c1.Close()
			done := make(chan struct{})
			go func() { _ = b.Handle(context.Background(), c2); close(done) }()
			_ = preamble.Encode(c1, &p)
			buf := make([]byte, 256)
			_, _ = c1.Read(buf)
			c1.Close()
			<-done
		}()
	}
	wg.Wait()
	if b.Idle != 0 {
		t.Fatalf("Handle stored Idle=%v", b.Idle)
	}
	if b.idle() != defaultIdle {
		t.Fatalf("idle()=%v want %v", b.idle(), defaultIdle)
	}
}
