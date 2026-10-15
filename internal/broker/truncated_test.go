package broker

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

// A client that disconnects mid-upload leaves a body that is shorter than
// its framing. The buffered path read the short body without an error and
// rewrote Content-Length to fit. So the origin got a whole request that
// the client did not send completely.
func TestTruncatedRequestNotForwarded(t *testing.T) {
	for name, raw := range map[string]string{
		"content_length": "POST /v1/upload HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 10\r\n\r\nabc",
		"chunked":        "POST /v1/upload HTTP/1.1\r\nHost: api.anthropic.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := testBroker(t)
			var whole atomic.Bool
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.ReadAll(r.Body); err == nil {
					whole.Store(true)
				}
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			drive(t, b, p, raw)
			if whole.Load() {
				t.Fatal("the origin read a complete body the client never finished sending")
			}
		})
	}
}

// An origin closes before it sends all of its Content-Length. On the
// buffered path, the short body went to the client with the length
// rewritten to fit. On the streamed path, it ended in a terminating chunk.
// On both paths, the client read the body as whole.
func TestTruncatedResponseNotPassedOn(t *testing.T) {
	for name, n := range map[string]int{"buffered": 3, "streamed": maxRespBuf + 1} {
		t.Run(name, func(t *testing.T) {
			b, _ := testBroker(t)
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(n+10)+"\r\n\r\n"+strings.Repeat("a", n))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			c1, c2 := net.Pipe()
			defer c1.Close()
			errc := make(chan error, 1)
			go func() { errc <- b.Handle(context.Background(), c2) }()
			go func() {
				_ = preamble.Encode(c1, &p)
				_, _ = io.WriteString(c1, "GET /x HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
			}()
			_ = c1.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, err := httpwire.ReadResponseHead(bufio.NewReader(c1), false)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Code == 200 {
				if _, err := io.ReadAll(resp.Stream); err == nil {
					t.Fatal("a truncated origin body reached the client as a complete one")
				}
			}
			c1.Close()
			<-errc
		})
	}
}
