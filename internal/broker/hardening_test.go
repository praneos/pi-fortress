package broker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"pi-fortress/internal/blocklist"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/preamble"
)

// rawUpstream serves the origin leg from a script over plain TCP. For each
// request that it reads from a connection, the script writes the reply. The
// script also reports whether the connection stays open. rawUpstream returns
// the count of connections that the broker opened.
func rawUpstream(t *testing.T, b *Broker, script func(i int, req *httpwire.Request, conn net.Conn) bool) *int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&conns, 1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for i := 0; ; i++ {
					req, err := httpwire.ReadRequest(br)
					if err != nil {
						return
					}
					if req.Body != nil {
						_, _ = io.Copy(io.Discard, req.Body)
					}
					if !script(i, req, c) {
						return
					}
				}
			}(c)
		}
	}()
	b.DialTLS = dialTo(ln)
	return &conns
}

// session is one client connection to the broker.
type session struct {
	t    *testing.T
	c    net.Conn
	br   *bufio.Reader
	errc chan error
}

func open(t *testing.T, b *Broker, p preamble.Preamble) *session {
	t.Helper()
	c1, c2 := net.Pipe()
	s := &session{t: t, c: c1, br: bufio.NewReader(c1), errc: make(chan error, 1)}
	go func() { s.errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c1.Close() })
	// Handle reads the preamble first, so this synchronous pipe write
	// completes. A goroutine writes the request later.
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *session) send(raw string) {
	go func() { _, _ = io.WriteString(s.c, raw) }()
}

func (s *session) read() *httpwire.Response {
	s.t.Helper()
	resp, err := httpwire.ReadResponse(s.br, 1<<20, false)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

func (s *session) close() error {
	s.c.Close()
	return <-s.errc
}

var anthropic = preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}

func TestDuplicateHostAuthorizationCookieRejected(t *testing.T) {
	b, _ := testBroker(t)
	conns := rawUpstream(t, b, func(int, *httpwire.Request, net.Conn) bool { return false })
	for _, dup := range []string{
		"Host: api.anthropic.com\r\nHost: evil.example\r\n",
		"Host: api.anthropic.com\r\nAuthorization: Bearer x\r\nAuthorization: Bearer y\r\n",
		"Host: api.anthropic.com\r\nCookie: a=1\r\nCookie: b=2\r\n",
	} {
		s := open(t, b, anthropic)
		s.send("GET / HTTP/1.1\r\n" + dup + "\r\n")
		if resp := s.read(); resp.Code != 400 {
			t.Fatalf("%q: code %d", dup, resp.Code)
		}
		if err := s.close(); !errors.Is(err, httpwire.ErrDupHeader) {
			t.Fatalf("%q: err=%v", dup, err)
		}
	}
	// The pre-dial can open a connection. A request must not get to it.
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(conns); n > 3 {
		t.Fatalf("upstream connections=%d", n)
	}
}

func TestEarlyHintsSkippedAndUpstreamReused(t *testing.T) {
	b, _ := testBroker(t)
	conns := rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		switch i {
		case 0:
			_, _ = io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
		default:
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
		}
		return true
	})
	s := open(t, b, anthropic)
	s.send("GET /one HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 200 || string(resp.Body) != "first" {
		t.Fatalf("first: %d %q", resp.Code, resp.Body)
	}
	s.send("GET /two HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 200 || string(resp.Body) != "second" {
		t.Fatalf("second: %d %q", resp.Code, resp.Body)
	}
	s.close()
	if n := atomic.LoadInt32(conns); n != 1 {
		t.Fatalf("upstream connections=%d, want 1", n)
	}
}

func TestBytesPastFramedResponseAre502(t *testing.T) {
	b, _ := testBroker(t)
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirstHTTP/1.1 103 Early Hints\r\n\r\n")
		return true
	})
	s := open(t, b, anthropic)
	s.send("GET /one HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 502 {
		t.Fatalf("code %d body %q", resp.Code, resp.Body)
	}
	if err := s.close(); !errors.Is(err, ErrLeftover) {
		t.Fatalf("err=%v", err)
	}
}

func TestResponseTransferEncodingNotChunkedIs502(t *testing.T) {
	b, _ := testBroker(t)
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nGET /next HTTP/1.1\r\n\r\n")
		return true
	})
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 502 {
		t.Fatalf("code %d", resp.Code)
	}
	if err := s.close(); !errors.Is(err, httpwire.ErrTransferEnc) {
		t.Fatalf("err=%v", err)
	}
}

func TestAcceptEncodingCollapsedToOneGzip(t *testing.T) {
	b, _ := testBroker(t)
	var seen atomic.Value
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		seen.Store(req.Values("Accept-Encoding"))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		return true
	})
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept-Encoding: gzip\r\nAccept-Encoding: br, zstd\r\n\r\n")
	if resp := s.read(); resp.Code != 200 {
		t.Fatalf("code %d", resp.Code)
	}
	s.close()
	if got, _ := seen.Load().([]string); len(got) != 1 || got[0] != "gzip" {
		t.Fatalf("origin saw Accept-Encoding %v", got)
	}
}

func refreshReq(ort string) string {
	body := `{"grant_type":"refresh_token","refresh_token":"` + ort + `"}`
	return "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func tokenJSON(oat, ort string) string {
	body := `{"access_token":"` + oat + `","refresh_token":"` + ort + `","token_type":"Bearer","expires_in":3600}`
	return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func TestConcurrentRefreshLoserGets429(t *testing.T) {
	b, path := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	newORT := "sk-ant-ort01-" + strings.Repeat("R", 64)
	arrived := make(chan struct{}, 4)
	release := make(chan struct{})
	var refreshes int32
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		atomic.AddInt32(&refreshes, 1)
		arrived <- struct{}{}
		<-release
		_, _ = io.WriteString(c, tokenJSON(newOAT, newORT))
		return true
	})
	ort := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	winner := open(t, b, anthropic)
	winner.send(refreshReq(ort))
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("first refresh never reached the origin")
	}
	loser := open(t, b, anthropic)
	loser.send(refreshReq(ort))
	if resp := loser.read(); resp.Code != 429 {
		t.Fatalf("loser code %d body %q", resp.Code, resp.Body)
	}
	if err := loser.close(); !errors.Is(err, ErrBusy) {
		t.Fatalf("loser err=%v", err)
	}
	close(release)
	resp := winner.read()
	if resp.Code != 200 || !strings.Contains(string(resp.Body), "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT") || strings.Contains(string(resp.Body), newOAT) {
		t.Fatalf("winner code %d body %q", resp.Code, resp.Body)
	}
	winner.close()
	if n := atomic.LoadInt32(&refreshes); n != 1 {
		t.Fatalf("origin saw %d refreshes, want 1", n)
	}
	env, _ := os.ReadFile(path)
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT="+newOAT) || !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_ORT="+newORT) {
		t.Fatalf("harvest missing:\n%s", env)
	}
	// The slot is free again after the rewrite is complete.
	if !b.Store.Acquire("b0b1b2b3b4b5b6b7") {
		t.Fatal("slot still busy after the refresh finished")
	}
	b.Store.Release("b0b1b2b3b4b5b6b7")
}

func TestHarvestBoundToRefreshTokenUsed(t *testing.T) {
	b, path := testBroker(t)
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	// Use the live value of the other slot, not its placeholder. The fence
	// refuses a placeholder in all locations other than the refresh_token
	// value, before the request gets to the harvest
	// (TestRefreshTokenPlacedOnlyAsTheRefreshField).
	other := "sk-ant-ort01-" + strings.Repeat("B", 64)
	used := "pf_c0c1c2c3c4c5c6c7_CLAUDE_ORT"
	body := `{"note":"` + other + `","grant_type":"refresh_token","refresh_token":"` + used + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	got := roundtrip(t, b, p, raw)
	if !strings.Contains(got, "pf_c0c1c2c3c4c5c6c7_CLAUDE_OAT") {
		t.Fatal(got)
	}
	env, _ := os.ReadFile(path)
	if !strings.Contains(string(env), "c0c1c2c3c4c5c6c7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("N", 64)) {
		t.Fatalf("slot c not harvested:\n%s", env)
	}
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("A", 64)) {
		t.Fatalf("slot b was rewritten by a body that merely mentioned it:\n%s", env)
	}
}

func TestRefreshWithORTOutsideCredentialRefused(t *testing.T) {
	b, path := testBroker(t)
	conns := rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		t.Errorf("origin saw %s %s", req.Method, req.Target)
		return false
	})
	ort := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	liveORT := "sk-ant-ort01-" + strings.Repeat("B", 64)
	form := func(v string) string {
		return "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
			strconv.Itoa(len("grant_type=refresh_token&refresh_token="+v)) + "\r\n\r\ngrant_type=refresh_token&refresh_token=" + v
	}
	cases := []struct {
		raw  string
		code int
		body string
	}{
		// The fence does not substitute a placeholder outside the refresh_token
		// value. The fence refuses it with the one refusal.
		{form(ort), 503, RefusedBody},
		{"POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(`{"refresh_token":"junk","note":"`+ort+`"}`)) + "\r\n\r\n" + `{"refresh_token":"junk","note":"` + ort + `"}`, 503, RefusedBody},
		// A live value that the fence does not change still gets to the bind of
		// the harvest. The bind cannot read a form, and it refuses.
		{form(liveORT), 403, "harvest\n"},
	}
	for _, tc := range cases {
		s := open(t, b, anthropic)
		s.send(tc.raw)
		if resp := s.read(); resp.Code != tc.code || string(resp.Body) != tc.body {
			t.Fatalf("code %d body %q, want %d %q", resp.Code, resp.Body, tc.code, tc.body)
		}
		s.close()
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(conns); n > 3 {
		t.Fatalf("upstream connections=%d", n)
	}
	env, _ := os.ReadFile(path)
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("A", 64)) {
		t.Fatalf("slot changed:\n%s", env)
	}
}

func TestRefreshNonJSON200Is502(t *testing.T) {
	b, path := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		body := `{"access_token":"` + newOAT + `"}`
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		return true
	})
	s := open(t, b, anthropic)
	s.send(refreshReq("pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"))
	if resp := s.read(); resp.Code != 502 || strings.Contains(string(resp.Body), newOAT) {
		t.Fatalf("code %d body %q", resp.Code, resp.Body)
	}
	if err := s.close(); !errors.Is(err, ErrHarvest) {
		t.Fatalf("err=%v", err)
	}
	env, _ := os.ReadFile(path)
	if strings.Contains(string(env), newOAT) {
		t.Fatalf("harvested from a non-json reply:\n%s", env)
	}
}

func TestOAuthLookalikePathNotHarvested(t *testing.T) {
	b, path := testBroker(t)
	newOAT := "sk-ant-oat01-" + strings.Repeat("N", 64)
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, tokenJSON(newOAT, "sk-ant-ort01-"+strings.Repeat("R", 64)))
		return true
	})
	s := open(t, b, anthropic)
	body := `{"grant_type":"refresh_token"}`
	s.send("POST /v1/oauth/token-status HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	if resp := s.read(); resp.Code != 200 {
		t.Fatalf("code %d", resp.Code)
	}
	s.close()
	env, _ := os.ReadFile(path)
	if strings.Contains(string(env), newOAT) {
		t.Fatalf("lookalike path harvested:\n%s", env)
	}
}

func TestMissingSrcRefusedWhenAgentNetSet(t *testing.T) {
	b, _ := testBroker(t)
	b.AgentNet = netip.MustParsePrefix("10.77.0.0/24")
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 403 || !strings.Contains(string(resp.Body), "src") {
		t.Fatalf("code %d body %q", resp.Code, resp.Body)
	}
	if err := s.close(); !errors.Is(err, ErrSrc) {
		t.Fatalf("err=%v", err)
	}
	if dialed.Load() {
		t.Fatal("dialed for a preamble with no source")
	}
}

func TestExpectNotAnsweredBeforeRefusal(t *testing.T) {
	b, _ := testBroker(t)
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\nExpect: 100-continue\r\nContent-Length: 10\r\n\r\n")
	line, err := s.br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 501") {
		t.Fatalf("first line %q err=%v", line, err)
	}
	if err := s.close(); err != nil {
		t.Fatalf("handle err=%v", err)
	}
}

// The engine refuses a listed SNI. The broker is the second line, and it
// is the only line that sees Host. For the origin server, a listed Host
// behind an unlisted SNI is still a listed destination.
func TestBlockedHostOrSNIRefused(t *testing.T) {
	cases := []struct {
		name string
		p    preamble.Preamble
		host string
	}{
		{"host listed, sni innocent", preamble.Preamble{SNI: "cdn.example", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}, "phish.example"},
		{"subdomain of a listed name", preamble.Preamble{SNI: "cdn.example", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}, "login.phish.example"},
		{"sni listed, host innocent", preamble.Preamble{SNI: "phish.example", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}, "cdn.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := testBroker(t)
			b.Blocked = blocklist.New("phish.example")
			s := open(t, b, c.p)
			s.send("GET / HTTP/1.1\r\nHost: " + c.host + "\r\nContent-Length: 0\r\n\r\n")
			line, err := s.br.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "HTTP/1.1 403") {
				t.Fatalf("first line %q err=%v", line, err)
			}
			if err := s.close(); err != nil {
				t.Fatalf("handle err=%v", err)
			}
		})
	}
}

// The blocklist walks the labels of the Host. A Host that is not a host
// and port, such as "x@blocked.example", has no label that the list holds.
// An origin that reads it loosely can still route it to the listed name.
// So the broker refuses such a Host before the blocklist, and the origin
// never sees it. What real clients send still goes through.
func TestHostMustBeHostAndPort(t *testing.T) {
	cdn := preamble.Preamble{SNI: "cdn.example", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	cases := []struct {
		host string
		code int
	}{
		{"x@blocked.example", 400},
		{"[blocked.example]", 400},
		{"[blocked.example]:443", 400},
		{"cdn.example", 204},
		{"cdn.example:443", 204},
		{"CDN.Example", 204},
		{"cdn.example.", 204},
		{"[2001:db8::1]", 204},
		{"[2001:db8::1]:443", 204},
		// A valid form, but not the port that the broker dialled.
		{"[2001:db8::1]:8443", 400},
		{"192.0.2.1:443", 204},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			b, _ := testBroker(t)
			b.Blocked = blocklist.New("blocked.example")
			var seen atomic.Int32
			rawUpstream(t, b, func(_ int, req *httpwire.Request, conn net.Conn) bool {
				seen.Add(1)
				_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
				return false
			})
			s := open(t, b, cdn)
			s.send("GET / HTTP/1.1\r\nHost: " + c.host + "\r\n\r\n")
			if resp := s.read(); resp.Code != c.code {
				t.Fatalf("Host %q: code %d, want %d", c.host, resp.Code, c.code)
			}
			s.close()
			if c.code == 400 && seen.Load() != 0 {
				t.Fatalf("Host %q reached the origin", c.host)
			}
		})
	}
}

func TestValidHost(t *testing.T) {
	long := strings.Repeat("a", 64)
	for h, want := range map[string]bool{
		"api.anthropic.com": true, "API.Anthropic.COM:443": true, "localhost": true, "_dmarc.example": true,
		"a.example.": true, "192.0.2.1": true, "[::1]": true, "[::ffff:192.0.2.1]:443": true, "x:65535": true,
		"": false, ".": false, "a..b": false, ".a": false, "a.example..": false, long + ".example": false,
		"x@blocked.example": false, "[blocked.example]": false, "[192.0.2.1]": false, "::1": false,
		"[::1%25eth0]": false, "[fe80::1%eth0]": false, "a%2eb": false, "a b": false, "é.example": false,
		"x:": false, "x:0": false, "x:65536": false, "x:+1": false, "x:1:2": false, "x:4430000": false,
	} {
		if got := validHost(h); got != want {
			t.Errorf("validHost(%q) = %v, want %v", h, got, want)
		}
	}
}

// A 100-continue in a second Expect field, or later in a list, still shows
// a client that holds its body back. If the broker reads the body instead,
// both sides stall until one side stops.
func TestExpectContinueInAnyField(t *testing.T) {
	for name, fields := range map[string]string{
		"one field":    "Expect: 100-continue\r\n",
		"second field": "Expect: x-other\r\nExpect: 100-continue\r\n",
		"in a list":    "Expect: x-other, 100-Continue\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := testBroker(t)
			rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				return true
			})
			s := open(t, b, anthropic)
			_ = s.c.SetDeadline(time.Now().Add(2 * time.Second))
			s.send("POST /x HTTP/1.1\r\nHost: api.anthropic.com\r\n" + fields + "Content-Length: 3\r\n\r\n")
			line, err := s.br.ReadString('\n')
			if err != nil || !strings.Contains(line, "100 Continue") {
				t.Fatalf("continue=%q err=%v", line, err)
			}
			if _, err := s.br.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			s.send("abc")
			if resp := s.read(); resp.Code != 200 || string(resp.Body) != "ok" {
				t.Fatalf("%d %q", resp.Code, resp.Body)
			}
			s.close()
		})
	}
}

// The fence does not scan request trailers. Thus the broker does not
// announce them to the origin (Trailer), and the trailer fields after the
// last chunk do not reach the origin. The test reads the raw bytes that
// the origin gets, because an httpwire parser on the origin side also
// drops trailer fields.
func TestRequestTrailerNeverReachesOrigin(t *testing.T) {
	b, _ := testBroker(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	raw := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var got strings.Builder
		br := bufio.NewReader(io.TeeReader(c, &got))
		req, err := httpwire.ReadRequest(br)
		if err != nil {
			raw <- "read: " + err.Error()
			return
		}
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
		}
		raw <- got.String()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	b.DialTLS = dialTo(ln)
	s := open(t, b, anthropic)
	s.send("POST / HTTP/1.1\r\nHost: api.anthropic.com\r\nTrailer: X-Secret\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"2\r\nhi\r\n0\r\nX-Secret: trailer-value\r\n\r\n")
	if resp := s.read(); resp.Code != 200 || string(resp.Body) != "ok" {
		t.Fatalf("%d %q", resp.Code, resp.Body)
	}
	s.close()
	got := <-raw
	if strings.Contains(strings.ToLower(got), "trailer") || strings.Contains(got, "X-Secret") {
		t.Fatalf("origin saw a trailer: %q", got)
	}
	if !strings.Contains(got, "hi") {
		t.Fatalf("origin did not get the body: %q", got)
	}
}

// TE, Trailer and Keep-Alive describe one hop. The broker drops them in both
// directions, on the buffered response path and on the streamed one.
func TestHopByHopFieldsDropped(t *testing.T) {
	for name, reply := range map[string]string{
		"buffered": "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5, max=100\r\nTE: trailers\r\nContent-Length: 2\r\n\r\nok",
		"streamed": "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5, max=100\r\nTE: trailers\r\nTrailer: X-T\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := testBroker(t)
			var seen atomic.Value
			rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
				seen.Store(append(req.Values("TE"), req.Values("Keep-Alive")...))
				_, _ = io.WriteString(c, reply)
				return true
			})
			s := open(t, b, anthropic)
			s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nTE: trailers\r\nConnection: TE, keep-alive\r\nKeep-Alive: timeout=30\r\n\r\n")
			resp := s.read()
			if resp.Code != 200 || string(resp.Body) != "ok" {
				t.Fatalf("%d %q", resp.Code, resp.Body)
			}
			if v := resp.Values("Keep-Alive"); len(v) != 0 {
				t.Fatalf("client saw Keep-Alive %v", v)
			}
			if v := resp.Values("TE"); len(v) != 0 {
				t.Fatalf("client saw TE %v", v)
			}
			if v := resp.Values("Trailer"); len(v) != 0 {
				t.Fatalf("client saw Trailer %v", v)
			}
			s.close()
			if got, _ := seen.Load().([]string); len(got) != 0 {
				t.Fatalf("origin saw %v", got)
			}
		})
	}
}
