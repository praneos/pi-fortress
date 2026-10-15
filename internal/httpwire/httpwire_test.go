package httpwire

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, raw string) {
	t.Helper()
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != raw {
		t.Fatalf("round-trip\n got %q\nwant %q", out.String(), raw)
	}
}

func TestStreamsFixtures(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "streams"))
	matches, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no testdata/streams")
	}
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, string(raw))
	}
}

func TestRoundTripChunked(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	roundTrip(t, raw)
}

func TestRequestRejected(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      error
	}{
		{"smuggle", "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", ErrSmuggle},
		{"lf only", "GET / HTTP/1.1\nHost: x\n\n", ErrBadRequest},
	} {
		if _, err := ReadRequest(bufio.NewReader(strings.NewReader(tc.raw))); err != tc.want {
			t.Fatalf("%s: err=%v want %v", tc.name, err, tc.want)
		}
	}
}

func TestSetInPlaceKeepsPosition(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer dummy\r\nX-A: 1\r\n\r\n"
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.SetInPlace("Authorization", "Bearer live")
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "Authorization: Bearer live\r\n") {
		t.Fatal(s)
	}
	if i := strings.Index(s, "Authorization:"); i < 0 || i > strings.Index(s, "X-A:") {
		t.Fatal("order lost")
	}
	if req.Get("host") != "api.anthropic.com" {
		t.Fatal("get host")
	}
}

func TestBodyNotTruncated(t *testing.T) {
	body := strings.Repeat("a", 200_000)
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 200000\r\n\r\n" + body
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 200_000 {
		t.Fatalf("forwarded %d, want 200000 (the head read must not truncate)", len(got))
	}
}

func TestReadResponseHEAD(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
	resp, err := ReadResponse(bufio.NewReader(strings.NewReader(raw)), 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != 0 {
		t.Fatal(resp.Body)
	}
	var out bytes.Buffer
	if _, err := resp.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Content-Length: 12") {
		t.Fatal(out.String())
	}
	if strings.HasSuffix(out.String(), "hello world\r\n") {
		t.Fatal("wrote a body")
	}
}

func TestCloudflareChunkedGET(t *testing.T) {
	html := "<!doctype html><html lang=\"en\"><head><title>Example Domain</title></head><body>ok</body></html>\n"
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" +
		fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(html), html)
	resp, err := ReadResponse(bufio.NewReader(strings.NewReader(raw)), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 200 || string(resp.Body) != html {
		t.Fatalf("code=%d body=%q", resp.Code, resp.Body)
	}
	var out bytes.Buffer
	if _, err := resp.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(strings.ToLower(s), "transfer-encoding") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "Content-Length: "+fmt.Sprintf("%d", len(html))) {
		t.Fatal(s)
	}
}

func TestWriteToHEADDropsChunked(t *testing.T) {
	resp := &Response{
		Proto:  "HTTP/1.1",
		Status: "200 OK",
		Code:   200,
		NoBody: true,
		Fields: []Field{{Name: "Transfer-Encoding", Value: "chunked", line: "Transfer-Encoding: chunked"}},
	}
	var out bytes.Buffer
	if _, err := resp.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out.String()), "transfer-encoding") {
		t.Fatal(out.String())
	}
}

func TestChunkedRequestDecoded(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5;ext=1\r\nworld\r\n0\r\nX-Trailer: 1\r\n\r\n"
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !req.Chunked {
		t.Fatal("not chunked")
	}
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	req2, err := ReadRequest(bufio.NewReader(&out))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req2.Body)
	if string(body) != "hello world" {
		t.Fatalf("%q", body)
	}
}

func TestSetBodyDropsChunkedHeader(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBody([]byte("hi"))
	var out bytes.Buffer
	_, _ = req.WriteTo(&out)
	s := out.String()
	if strings.Contains(strings.ToLower(s), "transfer-encoding") || !strings.HasSuffix(s, "Content-Length: 2\r\n\r\nhi") {
		t.Fatal(s)
	}
}

func TestResponseOverLimitErrors(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n" + strings.Repeat("x", 2000)
	if _, err := ReadResponse(bufio.NewReader(strings.NewReader(raw)), 1000, false); err != ErrBodyLimit {
		t.Fatalf("cl: %v", err)
	}
	raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7d0\r\n" + strings.Repeat("x", 2000) + "\r\n0\r\n\r\n"
	if _, err := ReadResponse(bufio.NewReader(strings.NewReader(raw)), 1000, false); err != ErrBodyLimit {
		t.Fatalf("chunked: %v", err)
	}
}

func TestReadResponseHead204HasNoBody(t *testing.T) {
	raw := "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"
	resp, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false)
	if err != nil || !resp.NoBody {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestStreamToEOFBody(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil eof"
	resp, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Stream)
	if string(body) != "until eof" || resp.ContentLength != -1 {
		t.Fatalf("%q %d", body, resp.ContentLength)
	}
	var out bytes.Buffer
	if err := resp.WriteHead(&out, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Transfer-Encoding: chunked\r\n") || strings.Contains(out.String(), "Content-Length") {
		t.Fatal(out.String())
	}
}

// Chunked framing under an HTTP/1.0 status line is a response that no
// reader can frame as written. The version says that the body ends at
// the close. The bytes say that it ends at the terminating chunk.
func TestChunkedHeadIsNotWrittenUnderAnHTTP10StatusLine(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\n\r\nuntil eof"
	resp, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resp.WriteHead(&out, true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("status line %q", out.String())
	}
	out.Reset()
	if err := resp.WriteHead(&out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "HTTP/1.0 200 OK\r\n") {
		t.Fatalf("unframed body lost the origin's version: %q", out.String())
	}
}

type oneByte struct{ r io.Reader }

func (o oneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestScrubberStraddle(t *testing.T) {
	live := []byte("sk-ant-oat01-" + strings.Repeat("A", 64))
	dummy := []byte("pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT")
	src := bytes.Repeat([]byte("z"), 40000)
	copy(src[32768-5:], live)
	copy(src[100:], live)
	copy(src[39000:], live)
	want := bytes.ReplaceAll(src, live, dummy)
	for name, r := range map[string]io.Reader{"whole": bytes.NewReader(src), "bytewise": oneByte{bytes.NewReader(src)}} {
		sc := NewScrubber(r, [][2][]byte{{live, dummy}})
		got, err := io.ReadAll(sc)
		if err != nil {
			t.Fatal(name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: len=%d want=%d live=%v", name, len(got), len(want), bytes.Contains(got, live))
		}
		if sc.Counts[0] != 3 {
			t.Fatalf("%s: counts=%v", name, sc.Counts)
		}
	}
	sc := NewScrubber(bytes.NewReader(src), nil)
	got, _ := io.ReadAll(sc)
	if !bytes.Equal(got, src) {
		t.Fatal("no pairs must pass through")
	}
}
