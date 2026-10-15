package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

func countingUpstream(t *testing.T, b *Broker, h http.HandlerFunc) *int32 {
	t.Helper()
	var newConns int32
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	b.DialTLS = dialTLSTo(srv)
	return &newConns
}

func TestUpstreamReusedAcrossRequests(t *testing.T) {
	b, _ := testBroker(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), (maxRespBuf+4096)/16)
	newConns := countingUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(big)
			return
		}
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, "GET /big HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	}()
	resp1, err := httpwire.ReadResponseHead(br, false)
	if err != nil {
		t.Fatal(err)
	}
	body1, err := io.ReadAll(resp1.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.Code != 200 || !bytes.Equal(body1, big) {
		t.Fatalf("big resp code=%d len=%d want=%d", resp1.Code, len(body1), len(big))
	}
	go func() { _, _ = io.WriteString(c1, "GET /small HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n") }()
	resp2, err := httpwire.ReadResponseHead(br, false)
	if err != nil {
		t.Fatal(err)
	}
	body2, err := io.ReadAll(resp2.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Code != 200 || string(body2) != "ok" {
		t.Fatalf("small resp code=%d body=%q", resp2.Code, body2)
	}
	c1.Close()
	<-errc
	if n := atomic.LoadInt32(newConns); n != 1 {
		t.Fatalf("upstream connections=%d, want 1", n)
	}
}

func TestPreDialOverlapsClientRequest(t *testing.T) {
	b, _ := testBroker(t)
	var dialAt atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		dialAt.CompareAndSwap(0, time.Now().UnixNano())
		raw, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	writeAt := time.Now().UnixNano()
	if _, err := io.WriteString(c1, "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, false); err != nil {
		t.Fatal(err)
	}
	c1.Close()
	<-errc
	d := dialAt.Load()
	if d == 0 {
		t.Fatal("origin never dialed")
	}
	if d >= writeAt {
		t.Fatalf("dial at %d not before request write at %d (%.0f ms after)", d, writeAt, float64(d-writeAt)/1e6)
	}
}

func TestPreDialFailureIs502(t *testing.T) {
	b, _ := testBroker(t)
	b.AllowHosts = map[string]struct{}{"example.com": {}}
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		return nil, errors.New("tls: handshake failure")
	}
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, false)
	c1.Close()
	<-errc
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 502 || string(resp.Body) != "origin\n" {
		t.Fatalf("code=%d body=%q", resp.Code, resp.Body)
	}
}

func TestNoPreDialForEcho(t *testing.T) {
	for _, p := range []preamble.Preamble{
		{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")},
		{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.3:443")},
		{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")},
	} {
		b, _ := testBroker(t)
		var called atomic.Bool
		b.DialTLS = noDial(&called)
		_ = roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: "+p.SNI+"\r\n\r\n")
		if called.Load() {
			t.Fatalf("dialed for echo sni=%s dst=%s", p.SNI, p.OrigDst)
		}
	}
}

func TestStaleUpstreamRedialed(t *testing.T) {
	b, _ := testBroker(t)
	var reqs int32
	newConns := countingUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&reqs, 1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("no hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("second"))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, "GET /one HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	}()
	resp1, err := httpwire.ReadResponse(br, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.Code != 200 || string(resp1.Body) != "first" {
		t.Fatalf("first resp code=%d body=%q", resp1.Code, resp1.Body)
	}
	go func() { _, _ = io.WriteString(c1, "GET /two HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n") }()
	resp2, err := httpwire.ReadResponse(br, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Code != 200 || string(resp2.Body) != "second" {
		t.Fatalf("second resp code=%d body=%q", resp2.Code, resp2.Body)
	}
	c1.Close()
	<-errc
	if n := atomic.LoadInt32(newConns); n != 2 {
		t.Fatalf("upstream connections=%d, want 2 (stale redial)", n)
	}
}

// The origin read the POST from a reused connection and then died
// without an answer. It may have applied the mutation, so the request
// cannot be sent again. The retry checked only that the body was
// replayable, and sent the request twice.
func TestAmbiguousPOSTNotReplayed(t *testing.T) {
	b, _ := testBroker(t)
	var posts int32
	newConns := countingUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write([]byte("ok"))
			return
		}
		atomic.AddInt32(&posts, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("no hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, "GET /one HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	}()
	resp1, err := httpwire.ReadResponse(br, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.Code != 200 {
		t.Fatalf("first resp code=%d", resp1.Code)
	}
	body := "mutate=1"
	go func() {
		_, _ = io.WriteString(c1, "POST /v1/mutate HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: text/plain\r\nContent-Length: "+
			strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}()
	resp2, err := httpwire.ReadResponse(br, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	<-errc
	if n := atomic.LoadInt32(&posts); n != 1 {
		t.Fatalf("origin saw the POST %d times, want 1", n)
	}
	if resp2.Code != 502 {
		t.Fatalf("second resp code=%d, want 502", resp2.Code)
	}
	if n := atomic.LoadInt32(newConns); n != 1 {
		t.Fatalf("upstream connections=%d, want 1 (no redial of a POST)", n)
	}
}

func TestCloseDelimitedNotReused(t *testing.T) {
	b, _ := testBroker(t)
	payload := bytes.Repeat([]byte("0123456789abcdef"), (maxRespBuf+4096)/16)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, "GET /big HTTP/1.0\r\nHost: api.anthropic.com\r\n\r\n")
	}()
	resp, err := httpwire.ReadResponseHead(br, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(resp.Get("Connection"), "close") {
		t.Fatalf("connection %q", resp.Get("Connection"))
	}
	body, err := io.ReadAll(resp.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body %d want %d", len(body), len(payload))
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected client EOF after close-delimited body, got %v", err)
	}
	<-errc
}
