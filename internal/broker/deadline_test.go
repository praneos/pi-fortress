package broker

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
)

// TestSlowStreamOutlivesIdle is the streaming completion: an origin that
// continues to send, in small pieces, for longer than the idle budget.
// Each piece is progress, so the client must get the full body. A budget
// measured from the arrival of the request cuts it midway instead.
func TestSlowStreamOutlivesIdle(t *testing.T) {
	b, _ := testBroker(t)
	b.Idle = 300 * time.Millisecond
	const chunks = 6
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		for k := 0; k < chunks; k++ {
			time.Sleep(150 * time.Millisecond)
			_, _ = io.WriteString(c, "5\r\ndata \r\n")
		}
		_, _ = io.WriteString(c, "0\r\n\r\n")
		return false
	})
	s := open(t, b, anthropic)
	s.send("GET /stream HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	resp, err := httpwire.ReadResponse(s.br, 1<<20, false)
	if err != nil {
		t.Fatalf("the stream was cut while bytes were still flowing: %v", err)
	}
	if want := strings.Repeat("data ", chunks); string(resp.Body) != want {
		t.Fatalf("body=%q want %q", resp.Body, want)
	}
	if err := s.close(); err != nil {
		t.Fatalf("handle: %v", err)
	}
}

// TestStalledOriginReleasesSlot is the other half of the same bound: an
// origin that completes the handshake, takes the request and then says
// nothing. Nothing on the origin leg watched the clock. Thus the
// connection stayed in a read until the kernel stopped it, hours later,
// and its slot was in use all that time.
func TestStalledOriginReleasesSlot(t *testing.T) {
	b, _ := testBroker(t)
	b.Idle = 300 * time.Millisecond
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		<-hang
		return false
	})
	s := open(t, b, anthropic)
	s.send("GET /silent HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	select {
	case <-s.errc:
	case <-time.After(3 * time.Second):
		t.Fatal("the broker still holds the connection 3s after the origin went silent; the slot is never given back")
	}
}
