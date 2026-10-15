package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/testsupport"
)

func testBroker(t *testing.T) (*Broker, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	oat := "b0b1b2b3b4b5b6b7"
	oatB := "c0c1c2c3c4c5c6c7"
	body := strings.Join([]string{
		secrets.EnvKey(slot, "GITHUB_TOKEN") + "=lab_fence_github",
		secrets.EnvKey(oat, "CLAUDE_OAT") + "=sk-ant-oat01-" + strings.Repeat("A", 64),
		secrets.EnvKey(oat, "CLAUDE_ORT") + "=sk-ant-ort01-" + strings.Repeat("B", 64),
		secrets.EnvKey(oatB, "CLAUDE_OAT") + "=sk-ant-oat01-" + strings.Repeat("C", 64),
		secrets.EnvKey(oatB, "CLAUDE_ORT") + "=sk-ant-ort01-" + strings.Repeat("D", 64),
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	pol, err := corepolicy.Load(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	re, err := fence.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	return &Broker{
		Policy:  pol,
		Store:   secrets.Open(path),
		TokenRE: re,
		Idle:    5 * time.Second,
		LabEcho: true,
	}, path
}

func roundtrip(t *testing.T, b *Broker, p preamble.Preamble, raw string) string {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, raw); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c1)
	resp, err := httpwire.ReadResponse(br, 1<<20, false)
	c1.Close()
	<-errc
	if err != nil {
		t.Fatal(err)
	}
	return string(resp.Body)
}

func drive(t *testing.T, b *Broker, p preamble.Preamble, raw string) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, raw); err != nil {
		t.Fatal(err)
	}
	c1.Close()
	<-errc
}

// noDial refuses every dial and records that one was attempted. No test
// asserts on the error text.
func noDial(dialed *atomic.Bool) DialTLSFunc {
	return func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("should not dial")
	}
}

// dialTo points every broker dial at ln.
func dialTo(ln net.Listener) DialTLSFunc {
	return func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
}

// dialTLSTo points every broker dial at srv. Verification is off because
// httptest mints its own certificate.
func dialTLSTo(srv *httptest.Server) DialTLSFunc {
	return func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
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
}

func fakeUpstream(t *testing.T, b *Broker, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	b.DialTLS = dialTLSTo(srv)
	return srv
}

func roundtripStream(t *testing.T, b *Broker, p preamble.Preamble, raw string) (*httpwire.Response, []byte) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	go func() {
		if err := preamble.Encode(c1, &p); err != nil {
			return
		}
		_, _ = io.WriteString(c1, raw)
	}()
	_ = c1.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c1)
	resp, err := httpwire.ReadResponseHead(br, false)
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	if resp.Stream != nil {
		body, err = io.ReadAll(resp.Stream)
		if err != nil {
			t.Fatal(err)
		}
	}
	c1.Close()
	<-errc
	return resp, body
}

func TestSSRFNoDial(t *testing.T) {
	b, _ := testBroker(t)
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	p := preamble.Preamble{
		SNI:     "api.anthropic.com",
		OrigDst: netip.MustParseAddrPort("192.168.1.1:443"),
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = preamble.Encode(c1, &p)
	_, _ = io.WriteString(c1, "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	c1.Close()
	err := <-errc
	if !errors.Is(err, ErrSSRF) {
		t.Fatalf("err=%v", err)
	}
	if dialed.Load() {
		t.Fatal("dialed RFC1918")
	}
}

func TestDoH403NoDial(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	// The pre-dial opens the origin connection on the preamble, before the
	// broker parses the request. Thus the important guarantee is that the
	// broker never forwards the DoH query. The TLS handshake alone does not
	// run the handler.
	var forwarded int32
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&forwarded, 1)
	})
	p := preamble.Preamble{
		SNI:     "dns.google",
		OrigDst: netip.MustParseAddrPort("8.8.8.8:443"),
		Src:     netip.MustParseAddrPort("10.77.0.10:51000"),
	}
	got := roundtrip(t, b, p, "GET /dns-query HTTP/1.1\r\nHost: dns.google\r\n\r\n")
	if !strings.Contains(got, "dns_pin") {
		t.Fatal(got)
	}
	if atomic.LoadInt32(&forwarded) != 0 {
		t.Fatal("doh query forwarded to origin")
	}
	// The strip row names the client, from the preamble, without its port.
	row, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(row), `"rule":"dns_pin","client_ip":"10.77.0.10"}`) {
		t.Fatalf("strip row %q", row)
	}
}

func TestSourceOutsideAgentNetRefused(t *testing.T) {
	b, _ := testBroker(t)
	b.AgentNet = netip.MustParsePrefix("10.77.0.0/24")
	b.FenceNets = []netip.Prefix{netip.MustParsePrefix("10.79.0.0/30")}
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	for _, tc := range []struct {
		src  string
		want error
	}{
		{"10.78.0.20:51000", ErrSrc},
		{"10.79.0.4:51000", ErrSrc},
		{"10.77.0.10:51000", nil},
		{"10.79.0.2:51000", nil},
	} {
		p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443"), Src: netip.MustParseAddrPort(tc.src)}
		c1, c2 := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- b.Handle(context.Background(), c2) }()
		// net.Pipe is synchronous. Write from a goroutine, so a broker that
		// answers on the preamble alone does not deadlock against the test.
		go func() {
			_ = preamble.Encode(c1, &p)
			_, _ = io.WriteString(c1, "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
		}()
		buf := make([]byte, 64)
		_ = c1.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c1.Read(buf)
		c1.Close()
		err := <-errc
		if tc.want != nil {
			if !errors.Is(err, tc.want) || !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 403") {
				t.Fatalf("src %s: err=%v resp=%q", tc.src, err, buf[:n])
			}
			if dialed.Load() {
				t.Fatal("dialed for a refused source")
			}
		} else if errors.Is(err, ErrSrc) {
			t.Fatalf("src %s inside a fenced net was refused", tc.src)
		}
	}
}

func TestOriginHEAD(t *testing.T) {
	seen := make(chan string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method
		w.Header().Set("Content-Length", "12")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	b, _ := testBroker(t)
	b.AllowHosts = map[string]struct{}{"example.com": {}}
	b.DialTLS = dialTLSTo(srv)
	p := preamble.Preamble{
		SNI:     "example.com",
		OrigDst: netip.MustParseAddrPort("93.184.216.34:443"),
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, true)
	c1.Close()
	<-errc
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 200 {
		t.Fatalf("%d", resp.Code)
	}
	select {
	case m := <-seen:
		if m != "HEAD" {
			t.Fatal(m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin got no HEAD")
	}
}

func TestUpstreamSeesInjectedToken(t *testing.T) {
	seen := make(chan string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	b, _ := testBroker(t)
	b.DialTLS = dialTLSTo(srv)
	p := preamble.Preamble{
		SNI:     "api.anthropic.com",
		OrigDst: netip.MustParseAddrPort("8.8.8.8:443"),
	}
	raw := "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"
	_ = roundtrip(t, b, p, raw)
	select {
	case auth := <-seen:
		if !strings.Contains(auth, "sk-ant-oat01-") || strings.Contains(auth, "pf_") {
			t.Fatal(auth)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream got no request")
	}
}

// A body that is too big to buffer streams after the head goes out.
// Thus the broker cannot refuse a placeholder in it before the send. The
// copy stops at the placeholder. The origin never sees the placeholder
// or a live value, and the request never completes there. The agent gets
// the one refusal, and the log names the cause.
func TestStreamedBodyPlaceholderNeverCompletes(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	ph := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	var completed, leaked atomic.Bool
	done := make(chan struct{}, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			completed.Store(true)
		}
		if strings.Contains(string(body), "pf_") || strings.Contains(string(body), live) {
			leaked.Store(true)
		}
		done <- struct{}{}
	})
	body := strings.Repeat("z", 600<<10) + " " + ph + " " + strings.Repeat("z", 600<<10)
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	resp, rb := roundtripStream(t, b, p, raw)
	if resp.Code != 503 || string(rb) != RefusedBody {
		t.Fatalf("%d %q", resp.Code, rb)
	}
	// The handler can still read when the client has its answer. Give it
	// time until the dropped origin connection ends its read.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	if completed.Load() || leaked.Load() {
		t.Fatalf("origin completed=%v saw placeholder or live=%v", completed.Load(), leaked.Load())
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(rows), `"cause":"placeholder_in_streamed_body"`) || !strings.Contains(string(rows), `"where":"body"`) {
		t.Fatalf("log %q", rows)
	}
}

// A chunked body streams at any size, and the broker substitutes into
// it. The broker does not substitute a placeholder of a kind that this
// host must not carry, and the buffered path would refuse it. The stream
// must not forward it either.
func TestChunkedBodyForeignPlaceholderNeverCompletes(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	ph := secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN")
	live := "lab_fence_github"
	var completed, leaked atomic.Bool
	done := make(chan struct{}, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			completed.Store(true)
		}
		if strings.Contains(string(body), "pf_") || strings.Contains(string(body), live) {
			leaked.Store(true)
		}
		done <- struct{}{}
	})
	body := strings.Repeat("z", 200<<10) + " " + ph + " " + strings.Repeat("z", 200<<10)
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunkWire(body)
	resp, rb := roundtripStream(t, b, p, raw)
	if resp.Code != 503 || string(rb) != RefusedBody {
		t.Fatalf("%d %q", resp.Code, rb)
	}
	// The handler can still read when the client has its answer. Give it
	// time until the dropped origin connection ends its read.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	if completed.Load() || leaked.Load() {
		t.Fatalf("origin completed=%v saw placeholder or live=%v", completed.Load(), leaked.Load())
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(rows), `"cause":"placeholder_in_streamed_body"`) || !strings.Contains(string(rows), `"where":"body"`) {
		t.Fatalf("log %q", rows)
	}
}

func chunkWire(s string) string {
	var out strings.Builder
	for len(s) > 0 {
		n := min(len(s), 4096)
		fmt.Fprintf(&out, "%x\r\n%s\r\n", n, s[:n])
		s = s[n:]
	}
	out.WriteString("0\r\n\r\n")
	return out.String()
}
