package broker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

func bigBody(live string) []byte {
	buf := bytes.Repeat([]byte("0123456789abcdef"), 3*1024*1024/16)
	copy(buf[32*1024-10:], live)
	copy(buf[2*1024*1024+7:], live)
	return buf
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLargeResponseStreamsAndScrubs(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	dummy := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	for _, chunked := range []bool{false, true} {
		b, _ := testBroker(t)
		dir := t.TempDir()
		b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
		payload := bigBody(live)
		fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
			if !chunked {
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(payload)
		})
		p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
		resp, body := roundtripStream(t, b, p, "GET /big HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
		if resp.Code != 200 || !resp.Chunked {
			t.Fatalf("chunked=%v code=%d resp.Chunked=%v", chunked, resp.Code, resp.Chunked)
		}
		want := bytes.ReplaceAll(payload, []byte(live), []byte(dummy))
		if !bytes.Equal(body, want) {
			t.Fatalf("chunked=%v len=%d want=%d live=%v dummies=%d", chunked, len(body), len(want), bytes.Contains(body, []byte(live)), bytes.Count(body, []byte(dummy)))
		}
		raw, _ := os.ReadFile(b.Logs.StripPath)
		if !strings.Contains(string(raw), `"where":"response"`) {
			t.Fatal(string(raw))
		}
	}
}

func TestLargeRequestBodyForwarded(t *testing.T) {
	b, _ := testBroker(t)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte(strconv.Itoa(len(got)) + " " + string(got[:16]) + " " + string(got[len(got)-16:])))
	})
	payload := bytes.Repeat([]byte("0123456789abcdef"), 2*1024*1024/16+1)
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	raw := "POST /v1/upload HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\n\r\n" + string(payload)
	got := roundtrip(t, b, p, raw)
	want := strconv.Itoa(len(payload)) + " 0123456789abcdef 0123456789abcdef"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	var chunkedRaw strings.Builder
	chunkedRaw.WriteString("POST /v1/upload HTTP/1.1\r\nHost: api.anthropic.com\r\nTransfer-Encoding: chunked\r\n\r\n")
	body := bytes.Repeat([]byte("abcdefgh"), 100*1024/8)
	for i := 0; i < len(body); i += 7000 {
		end := i + 7000
		if end > len(body) {
			end = len(body)
		}
		chunkedRaw.WriteString(strconv.FormatInt(int64(end-i), 16) + "\r\n")
		chunkedRaw.Write(body[i:end])
		chunkedRaw.WriteString("\r\n")
	}
	chunkedRaw.WriteString("0\r\n\r\n")
	got = roundtrip(t, b, p, chunkedRaw.String())
	want = strconv.Itoa(len(body)) + " abcdefghabcdefgh abcdefghabcdefgh"
	if got != want {
		t.Fatalf("chunked: got %q want %q", got, want)
	}
}

func TestHTTP10StreamIsNotChunked(t *testing.T) {
	b, _ := testBroker(t)
	payload := bytes.Repeat([]byte("0123456789abcdef"), (maxRespBuf+4096)/16)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /big HTTP/1.0\r\nHost: api.anthropic.com\r\n\r\n")
	if resp.Code != 200 || resp.Chunked || resp.Get("Transfer-Encoding") != "" {
		t.Fatalf("code=%d chunked=%v te=%q", resp.Code, resp.Chunked, resp.Get("Transfer-Encoding"))
	}
	if !strings.EqualFold(resp.Get("Connection"), "close") {
		t.Fatalf("connection %q", resp.Get("Connection"))
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body %d want %d", len(body), len(payload))
	}
}

// The mirror of the case above: an HTTP/1.0 origin answers an HTTP/1.1
// agent. The broker chooses chunking from the version of the request. An
// old version copied the status line from the origin. Thus the agent got
// an HTTP/1.0 response framed in chunks. Readers of HTTP/1.0 are entitled
// to take the end of the body to be at the close instead. Now a chunked
// response has an HTTP/1.1 status line.
func TestHTTP10OriginStreamedChunkedIsAnnouncedAs11(t *testing.T) {
	b, _ := testBroker(t)
	payload := "one chunked body"
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"+payload)
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /x HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if string(body) != payload {
		t.Fatalf("body %q", body)
	}
	if resp.Chunked && resp.Proto != "HTTP/1.1" {
		t.Fatalf("chunked body under a %s status line", resp.Proto)
	}
}

func TestOriginOfferedGzipOnlyAndOpaqueEncodingLogged(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	var seen string
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("opaque brotli bytes"))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /x HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept-Encoding: gzip, br\r\n\r\n")
	if seen != "gzip" {
		t.Fatalf("origin saw Accept-Encoding %q, want gzip only", seen)
	}
	if resp.Code != 200 || resp.Get("Content-Encoding") != "br" || string(body) != "opaque brotli bytes" {
		t.Fatalf("code %d enc %q body %q", resp.Code, resp.Get("Content-Encoding"), body)
	}
	raw, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(raw), `"rule":"encoded:br"`) {
		t.Fatalf("no encoded log: %s", raw)
	}
}

func TestOpaqueEncodingRefusedAfterSubstitution(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	b, _ := testBroker(t)
	var auth string
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("opaque " + live))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /v1/x HTTP/1.1\r\nHost: api.anthropic.com\r\n"+
		"Authorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n")
	if auth != "Bearer "+live {
		t.Fatalf("the request was not substituted: origin saw %q", auth)
	}
	if resp.Code != 502 || strings.Contains(string(body), "opaque") {
		t.Fatalf("code %d body %q: an unreadable reply to a substituted request reached the agent", resp.Code, body)
	}
}

func TestGzipResponseInflatedScrubbedRecompressed(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	dummy := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	b, _ := testBroker(t)
	b.Recompress = true
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	plain := []byte(`{"echo":"` + live + `","pad":"` + strings.Repeat("x", 5000) + `"}`)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("origin saw %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(gz(t, plain))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /v1/x HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n")
	if resp.Code != 200 || resp.Get("Content-Encoding") != "gzip" || resp.Get("Content-Length") != "" {
		t.Fatalf("code %d enc %q cl %q", resp.Code, resp.Get("Content-Encoding"), resp.Get("Content-Length"))
	}
	got := gunzip(t, body)
	if bytes.Contains(got, []byte(live)) || !bytes.Contains(got, []byte(dummy)) {
		t.Fatalf("scrub through gzip failed: %q", got[:80])
	}
	if !bytes.Equal(got, bytes.ReplaceAll(plain, []byte(live), []byte(dummy))) {
		t.Fatal("recompressed body differs beyond the scrub")
	}
	raw, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(raw), `"where":"response"`) {
		t.Fatal(string(raw))
	}
}

func TestGzipResponseIdentityWhenClientDidNotAccept(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	b, _ := testBroker(t)
	b.Recompress = true
	plain := []byte("hello " + live + " world")
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz(t, plain))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /v1/x HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp.Code != 200 || resp.Get("Content-Encoding") != "" {
		t.Fatalf("code %d enc %q", resp.Code, resp.Get("Content-Encoding"))
	}
	if string(body) != "hello pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT world" {
		t.Fatalf("%q", body)
	}
}

func TestGzipBombCapped(t *testing.T) {
	b, _ := testBroker(t)
	b.MaxDecoded = 1 << 20
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		zeros := make([]byte, 1<<20)
		for i := 0; i < 64; i++ {
			if _, err := gw.Write(zeros); err != nil {
				return
			}
		}
		_ = gw.Close()
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, "GET /big HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	}()
	_ = c1.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(c1)
	resp, err := httpwire.ReadResponseHead(br, false)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Stream)
	c1.Close()
	herr := <-errc
	if n > (1<<20)+(64<<10) {
		t.Fatalf("delivered %d decoded bytes past a 1 MiB cap", n)
	}
	if herr == nil || !errors.Is(herr, httpwire.ErrBodyLimit) {
		t.Fatalf("handler error %v, want body limit", herr)
	}
}

// The broker reads the coding across all Content-Encoding fields. An
// identity field before a gzip field, or gzip two times, gives a body that
// the scrub cannot read. So the broker refuses the reply to a substituted
// request. It does not forward that reply as plain.
func TestStackedContentEncodingRefusedAfterSubstitution(t *testing.T) {
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	for _, tc := range []struct {
		name string
		encs []string
		body func(t *testing.T) []byte
	}{
		{"identity then gzip", []string{"identity", "gzip"}, func(t *testing.T) []byte { return gz(t, []byte("echo "+live)) }},
		{"gzip twice in two fields", []string{"gzip", "gzip"}, func(t *testing.T) []byte { return gz(t, gz(t, []byte("echo "+live))) }},
		{"gzip twice in one field", []string{"gzip, gzip"}, func(t *testing.T) []byte { return gz(t, gz(t, []byte("echo "+live))) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir := t.TempDir()
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
			fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Content-Encoding"] = tc.encs
				_, _ = w.Write(tc.body(t))
			})
			p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			resp, body := roundtripStream(t, b, p, "GET /v1/x HTTP/1.1\r\nHost: api.anthropic.com\r\n"+
				"Authorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n")
			if resp.Code != 502 || string(body) != "origin\n" {
				t.Fatalf("code %d body %q: an unreadable reply to a substituted request reached the agent", resp.Code, body)
			}
			raw, _ := os.ReadFile(b.Logs.StripPath)
			if !strings.Contains(string(raw), `"rule":"encoded:`) {
				t.Fatalf("no encoded row: %s", raw)
			}
		})
	}
}

func TestResponseCoding(t *testing.T) {
	for _, tc := range []struct {
		encs []string
		want string
	}{
		{nil, "identity"},
		{[]string{""}, "identity"},
		{[]string{"identity"}, "identity"},
		{[]string{" GZIP "}, "gzip"},
		{[]string{"x-gzip"}, "x-gzip"},
		{[]string{"br"}, "br"},
		{[]string{"identity", "gzip"}, "identity,gzip"},
		{[]string{"gzip", "identity"}, "gzip,identity"},
		{[]string{"gzip,gzip"}, "gzip,gzip"},
		{[]string{"gzip", ""}, "gzip"},
	} {
		resp := &httpwire.Response{}
		for _, e := range tc.encs {
			resp.Append("Content-Encoding", e)
		}
		if got := responseCoding(resp); got != tc.want {
			t.Errorf("%q: got %q want %q", tc.encs, got, tc.want)
		}
	}
}
