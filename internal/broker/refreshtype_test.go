package broker

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// A refresh body that is not application/json gets the one refusal for a
// placeholder of a valid slot, byte for byte the same as for an unknown
// slot. The request does not go to the origin. Thus it logs no use and the
// budget does not count it.
func TestRefreshPlaceholderInNonJSONBodyGetsOneRefusal(t *testing.T) {
	refresh := func(ct, slot string) string {
		body := `{"grant_type":"refresh_token","refresh_token":"pf_` + slot + `_CLAUDE_ORT"}`
		head := "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\n"
		if ct != "" {
			head += "Content-Type: " + ct + "\r\n"
		}
		return head + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	b, _ := testBroker(t)
	rawUpstream(t, b, func(_ int, req *httpwire.Request, _ net.Conn) bool {
		t.Errorf("origin saw %s %s", req.Method, req.Target)
		return false
	})
	want := rawRoundtrip(t, b, p, refresh("application/json", "ffffffffffffffff"))
	if !strings.HasPrefix(want, "HTTP/1.1 503 ") || !strings.Contains(want, "Retry-After: 60") {
		t.Fatalf("unknown slot: %q", want)
	}
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "application/jsonx", ""} {
		b, path := testBroker(t)
		dir := t.TempDir()
		b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
		b.Now = func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }
		rawUpstream(t, b, func(_ int, req *httpwire.Request, _ net.Conn) bool {
			t.Errorf("%q: origin saw %s %s", ct, req.Method, req.Target)
			return false
		})
		before, _ := os.ReadFile(path)
		if got := rawRoundtrip(t, b, p, refresh(ct, "b0b1b2b3b4b5b6b7")); got != want {
			t.Errorf("%q: response %q, want %q", ct, got, want)
		}
		if use, _ := os.ReadFile(b.Logs.UsePath); len(use) != 0 {
			t.Errorf("%q: use rows %s", ct, use)
		}
		if h := b.budget.hour(b.now()); len(h) != 0 {
			t.Errorf("%q: budget counted %v", ct, h)
		}
		if strip, _ := os.ReadFile(b.Logs.StripPath); !strings.Contains(string(strip), `"refused:placeholder_outside_header"`) || !strings.Contains(string(strip), "b0b1b2b3b4b5b6b7") {
			t.Errorf("%q: strip rows %s", ct, strip)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("%q: the store changed:\n%s", ct, after)
		}
	}
}

// BenchmarkPrepareBind runs the decision stages of one request that the
// broker forwards: the fence, then the bind of the harvest.
func BenchmarkPrepareBind(bm *testing.B) {
	ort := `{"grant_type":"refresh_token","refresh_token":"pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"}`
	msg := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	for _, tc := range []struct{ name, raw string }{
		{"get", "GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"},
		{"json", "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\n\r\n" + msg},
		{"refresh", "POST /v1/oauth/token HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(ort)) + "\r\n\r\n" + ort},
	} {
		bm.Run(tc.name, func(bm *testing.B) {
			b := benchBroker(bm)
			p := &preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			bm.ReportAllocs()
			for bm.Loop() {
				req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(tc.raw)))
				if err != nil {
					bm.Fatal(err)
				}
				c := &call{p: p, req: req}
				c.host = prettyHost(req, p.SNI)
				if _, _, done, err := b.prepare(c); done {
					bm.Fatal(err)
				}
				if done, err := b.bindHarvest(c); done {
					bm.Fatal(err)
				}
				b.memGive(&c.memReq)
			}
		})
	}
}

// benchBroker is testBroker for a benchmark. go test runs in the package
// directory, two levels below the checkout root.
func benchBroker(bm *testing.B) *Broker {
	path := filepath.Join(bm.TempDir(), "secrets.env")
	body := secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_OAT") + "=sk-ant-oat01-" + strings.Repeat("A", 64) + "\n" +
		secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_ORT") + "=sk-ant-ort01-" + strings.Repeat("B", 64) + "\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		bm.Fatal(err)
	}
	pol, err := corepolicy.Load(filepath.Join("..", "..", "vm", "policy", "core.hosts"))
	if err != nil {
		bm.Fatal(err)
	}
	re, err := fence.LoadTokenRE(filepath.Join("..", "..", "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		bm.Fatal(err)
	}
	return &Broker{Policy: pol, Store: secrets.Open(path), TokenRE: re, Idle: 5 * time.Second}
}
