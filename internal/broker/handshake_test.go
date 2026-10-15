package broker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
)

// silentOrigin is the host that the handshake leak needs. It accepts TCP
// and never sends a byte. It gives each accepted connection to the test,
// so that the test can see when the broker closes its end.
func silentOrigin(t *testing.T) (net.Listener, chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			accepted <- c
		}
	}()
	return ln, accepted
}

// realDialTo keeps the dial of the broker, with its TLS handshake. It only
// points the TCP connect at ln. DialTLS would replace the handshake that
// has the deadline.
func realDialTo(b *Broker, ln net.Listener, budget time.Duration) {
	b.dialTimeout = budget
	b.dialTCP = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
}

// closedByBroker waits until the broker closes its end of an accepted
// connection. The descriptor must be gone, not only idle.
func closedByBroker(t *testing.T, accepted chan net.Conn, within time.Duration) {
	t.Helper()
	var c net.Conn
	select {
	case c = <-accepted:
	case <-time.After(within):
		t.Fatal("the broker never connected to the origin")
	}
	_ = c.SetReadDeadline(time.Now().Add(within))
	var b [1]byte
	// The ClientHello arrives first. Only the data after it is important.
	for {
		if _, err := c.Read(b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the broker still holds the origin connection %v later", within)
			}
			return
		}
	}
}

// goroutinesBack waits until the goroutine count is at most n. The predial
// runs on its own goroutine. A predial goroutine that stays in a handshake
// is the leak that this file is about.
func goroutinesBack(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines: %d, want at most %d", runtime.NumGoroutine(), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStalledHandshakeGivesUp tests the dial alone: an origin server that
// accepts TCP and never sends a ServerHello. Before the deadline, this dial
// returned only when the kernel stopped the socket. Because of keepalives,
// that never occurred.
func TestStalledHandshakeGivesUp(t *testing.T) {
	b, _ := testBroker(t)
	ln, accepted := silentOrigin(t)
	realDialTo(b, ln, 200*time.Millisecond)
	start := time.Now()
	c, err := b.dial(context.Background(), netip.MustParseAddrPort("8.8.8.8:443"), "api.anthropic.com")
	if err == nil {
		c.Close()
		t.Fatal("a handshake with a silent origin succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the handshake gave up after %v; the budget was 200ms", d)
	}
	closedByBroker(t, accepted, 2*time.Second)
}

// TestStalledHandshakeReleasesSlot sends the same origin server through
// Handle. The request waits on the predial, and the predial stops. The
// agent gets the 502. The connection, its goroutines and the origin socket
// are all released.
func TestStalledHandshakeReleasesSlot(t *testing.T) {
	b, _ := testBroker(t)
	ln, accepted := silentOrigin(t)
	realDialTo(b, ln, 200*time.Millisecond)
	base := runtime.NumGoroutine()
	s := open(t, b, anthropic)
	s.send("GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	resp := s.read()
	if resp.Code != 502 {
		t.Fatalf("code %d, want 502", resp.Code)
	}
	select {
	case <-s.errc:
	case <-time.After(3 * time.Second):
		t.Fatal("Handle still holds the slot 3s after the handshake deadline")
	}
	closedByBroker(t, accepted, 2*time.Second)
	s.c.Close()
	goroutinesBack(t, base)
}

// TestCloseCancelsPredial uses a client that leaves before its first
// request, while the predial is still in the handshake. Before, close
// waited for the predial for all of the time that it took. With a budget
// of one minute, close must still return immediately, because it cancels
// the dial.
func TestCloseCancelsPredial(t *testing.T) {
	b, _ := testBroker(t)
	ln, accepted := silentOrigin(t)
	realDialTo(b, ln, time.Minute)
	s := open(t, b, anthropic)
	// Wait until the predial is in the handshake, then leave.
	var c net.Conn
	select {
	case c = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no predial")
	}
	start := time.Now()
	s.c.Close()
	select {
	case <-s.errc:
	case <-time.After(time.Second):
		<-s.errc
		t.Fatalf("Handle is waiting out a predial the client no longer needs; returned after %v", time.Since(start))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("close took %v", d)
	}
	accepted <- c
	closedByBroker(t, accepted, 2*time.Second)
}

// TestCloseBoundedWhenDialIgnoresContext is the other half of the bound on
// close. A dial that ignores cancellation (a DialTLS hook can be anything)
// still releases the slot within predialCloseWait.
func TestCloseBoundedWhenDialIgnoresContext(t *testing.T) {
	b, _ := testBroker(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{}, 1)
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		entered <- struct{}{}
		<-release
		return nil, errors.New("released")
	}
	s := open(t, b, anthropic)
	<-entered
	s.c.Close()
	select {
	case <-s.errc:
	case <-time.After(predialCloseWait + 2*time.Second):
		t.Fatal("close waited on a dial that ignores its context")
	}
}

// TestTrickledHeadCut is the same shape one step later. The origin server
// completes the handshake and takes the request. Then it sends its response
// head one byte at a time, and each byte comes within Idle. Idle alone
// never fired. The absolute deadline of the head (originHeadIdles x Idle)
// fires.
func TestTrickledHeadCut(t *testing.T) {
	b, _ := testBroker(t)
	b.Idle = 300 * time.Millisecond
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n")
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-hang:
				return false
			case <-tick.C:
				if _, err := io.WriteString(c, "X"); err != nil {
					return false
				}
			}
		}
	})
	s := open(t, b, anthropic)
	s.send("GET /slow HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	select {
	case <-s.errc:
	case <-time.After(3 * time.Second):
		t.Fatal("a trickled response head held the slot past its deadline")
	}
}
