package engine

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestCancelEndsEstablishedRelay keeps a relay busy with traffic the full
// time, so the idle deadlines never fire, and then cancels Serve. The idle
// bound is much longer than the test will wait. So if Serve returns, the
// cause is that cancellation reached the copy, not that the relay went
// quiet.
func TestCancelEndsEstablishedRelay(t *testing.T) {
	sock, _ := startEchoBroker(t)
	store := testStore(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	orig := netip.MustParseAddrPort("192.0.2.30:443")
	e := &Engine{
		Sock: sock,
		CA:   store,
		OrigDst: func(net.Conn) (netip.AddrPort, error) {
			return orig, nil
		},
		Handshake: 3 * time.Second,
		Idle:      10 * time.Minute,
		MaxConns:  8,
		Log:       log.New(&bytes.Buffer{}, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, ln) }()

	tc := clientTLS(t, ln.Addr().String(), "example.com", store, nil)
	defer tc.Close()

	// A first round trip before the cancel, so the relay is actually
	// established and not still inside the handshake. The handshake already
	// takes the context.
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil {
		t.Fatal(err)
	}

	busy := make(chan struct{})
	go func() {
		defer close(busy)
		b := make([]byte, 4)
		for {
			if _, err := tc.Write([]byte("ping")); err != nil {
				return
			}
			if _, err := io.ReadFull(tc, b); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel: a busy relay outlived it")
	}
	<-busy
}
