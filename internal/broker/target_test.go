package broker

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
)

// The fence decides on the SNI and the Host, and forwards the target
// verbatim. An RFC 9112 origin routes a target that carries its own
// authority to a vhost that nobody judged, with the credential that the
// Host earned. The broker refuses each such line before the fence runs:
// no strip of the slot list, no injection, no origin.
func TestNonOriginFormTargetRefused(t *testing.T) {
	const oat = "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	for _, tc := range []struct{ name, raw, rule string }{
		{"absolute-form, same authority",
			"GET https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "request_target"},
		{"absolute-form, another authority",
			"GET https://evil.example/x HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "request_target"},
		{"absolute-form refresh",
			"POST http://api.anthropic.com/v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", "request_target"},
		{"connect",
			"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "connect"},
		{"asterisk on GET",
			"GET * HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "request_target"},
		{"no host",
			"GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "no_host"},
		{"websocket absolute-form",
			"GET https://evil.example/ws HTTP/1.1\r\nHost: api.anthropic.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer " + oat + "\r\n\r\n", "request_target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir := t.TempDir()
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
			var seen atomic.Int32
			rawUpstream(t, b, func(_ int, req *httpwire.Request, _ net.Conn) bool {
				seen.Add(1)
				t.Errorf("origin saw %s %s", req.Method, req.Target)
				return false
			})
			s := open(t, b, anthropic)
			s.send(tc.raw)
			resp := s.read()
			if resp.Code != 400 || strings.Contains(string(resp.Body), "sk-ant") {
				t.Fatalf("code %d body %q", resp.Code, resp.Body)
			}
			if err := s.close(); err != nil {
				t.Fatalf("handle: %v", err)
			}
			if seen.Load() != 0 {
				t.Fatal("the origin was reached")
			}
			if use, _ := os.ReadFile(b.Logs.UsePath); len(use) != 0 {
				t.Fatalf("a slot was spent: %s", use)
			}
			strip, _ := os.ReadFile(b.Logs.StripPath)
			if !strings.Contains(string(strip), `"where":"target"`) || !strings.Contains(string(strip), `"rule":"`+tc.rule+`"`) {
				t.Fatalf("strip rows: %s", strip)
			}
		})
	}
}

// What the refusal above must leave alone: origin-form, OPTIONS *, and
// an HTTP/1.0 request, which has no Host to require.
func TestOriginFormTargetsForwarded(t *testing.T) {
	for _, raw := range []string{
		"GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
		"GET /v1/models HTTP/1.0\r\n\r\n",
	} {
		b, _ := testBroker(t)
		var target atomic.Value
		rawUpstream(t, b, func(_ int, req *httpwire.Request, c net.Conn) bool {
			target.Store(req.Target)
			_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
			return false
		})
		s := open(t, b, anthropic)
		s.send(raw)
		if resp := s.read(); resp.Code != 204 {
			t.Fatalf("%q: code %d body %q", raw, resp.Code, resp.Body)
		}
		s.close()
		if got, _ := target.Load().(string); got == "" || !strings.HasPrefix(raw, "GET "+got) && !strings.HasPrefix(raw, "OPTIONS "+got) {
			t.Fatalf("%q: origin saw target %q", raw, got)
		}
	}
}
