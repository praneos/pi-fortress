package broker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

// benchOrigin is an origin on a net.Pipe. It reads each request and sends
// a 2 KiB JSON answer. auth keeps the last Authorization that it got.
func benchOrigin(auth *atomic.Value) DialTLSFunc {
	body := `{"id":"msg_1","content":[{"type":"text","text":"` + strings.Repeat("lorem ipsum ", 170) + `"}]}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	return func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			br := bufio.NewReader(c2)
			for {
				req, err := httpwire.ReadRequest(br)
				if err != nil {
					return
				}
				auth.Store(req.Get("Authorization"))
				if req.Body != nil {
					_, _ = io.Copy(io.Discard, req.Body)
				}
				if _, err := io.WriteString(c2, resp); err != nil {
					return
				}
			}
		}()
		return c1, nil
	}
}

// handleOnce is one agent connection with one request: the preamble, the
// parse, the fence with the substitution of the placeholder, the forward,
// and the scrub of the answer.
func handleOnce(b *Broker, p *preamble.Preamble, raw string) error {
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, p); err != nil {
		return err
	}
	if _, err := io.WriteString(c1, raw); err != nil {
		return err
	}
	resp, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, false)
	c1.Close()
	<-errc
	if err == nil && resp.Code != 200 {
		err = errors.New("status " + resp.Status + ": " + string(resp.Body))
	}
	return err
}

func benchHandleSetup(bm *testing.B) (*Broker, *preamble.Preamble, string) {
	b := benchBroker(bm)
	var auth atomic.Value
	b.DialTLS = benchOrigin(&auth)
	p := &preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	msg := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\n\r\n" + msg
	if err := handleOnce(b, p, raw); err != nil {
		bm.Fatal(err)
	}
	if got, _ := auth.Load().(string); got != "Bearer sk-ant-oat01-"+strings.Repeat("A", 64) {
		bm.Fatalf("origin got Authorization %q, want the substituted credential", got)
	}
	return b, p, raw
}

// BenchmarkHandle is one agent request end to end through the broker.
func BenchmarkHandle(bm *testing.B) {
	b, p, raw := benchHandleSetup(bm)
	bm.ReportAllocs()
	for bm.Loop() {
		if err := handleOnce(b, p, raw); err != nil {
			bm.Fatal(err)
		}
	}
}

// BenchmarkHandleParallel is BenchmarkHandle with many agent connections
// at the same time on one broker.
func BenchmarkHandleParallel(bm *testing.B) {
	b, p, raw := benchHandleSetup(bm)
	bm.ReportAllocs()
	bm.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := handleOnce(b, p, raw); err != nil {
				bm.Error(err)
				return
			}
		}
	})
}
