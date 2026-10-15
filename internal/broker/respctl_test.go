package broker

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
)

// An origin head with a bare CR in a field value gets to the agent with a
// space in place of the CR. Thus a client that splits header lines on CR
// (Python's http.client) cannot find a Content-Encoding that the scrub
// never saw. Such a client would decide gzip on that header. The scrub did
// not inflate that gzip body, so the scrub could not examine it. The
// operator gets a strip row.
func TestResponseControlBytesReachTheAgentAsSpaces(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 O\x01K\r\nX-A: b\rContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nhi")
		return false
	})
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	var head strings.Builder
	for {
		line, err := s.br.ReadString('\n')
		if err != nil {
			t.Fatalf("head cut short after %q: %v", head.String(), err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	got := head.String()
	if strings.Contains(strings.ReplaceAll(got, "\r\n", "\n"), "\r") || strings.ContainsRune(got, 0x01) {
		t.Fatalf("a control byte reached the agent: %q", got)
	}
	for _, want := range []string{"HTTP/1.1 200 O K\r\n", "X-A: b Content-Encoding: gzip\r\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("no %q in %q", want, got)
		}
	}
	if strings.Contains(strings.ToLower(got), "\ncontent-encoding:") {
		t.Fatalf("the hidden header reached the agent as a line of its own: %q", got)
	}
	_ = s.close()
	raw, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(raw), `"rule":"`+ruleRespCTL+`"`) || !strings.Contains(string(raw), `"where":"response"`) {
		t.Fatalf("no response_ctl row: %s", raw)
	}
}

// A header name has no such repair. Thus the broker answers 502 to a
// response whose name is not a token, and never forwards it.
func TestResponseNameWithControlByteIs502(t *testing.T) {
	b, _ := testBroker(t)
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nX\rContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nhi")
		return false
	})
	s := open(t, b, anthropic)
	s.send("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	if resp := s.read(); resp.Code != 502 {
		t.Fatalf("code %d", resp.Code)
	}
	if err := s.close(); !errors.Is(err, httpwire.ErrBadRequest) {
		t.Fatalf("err=%v", err)
	}
}
