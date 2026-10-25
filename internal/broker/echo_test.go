package broker

import (
	"encoding/base64"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// The open echo refuses a placeholder that it must not substitute, and
// replaces a live value. In neither case can the live secret leak.
func TestOpenEcho(t *testing.T) {
	for _, tc := range []struct{ name, auth, want string }{
		{"refuses placeholder", "pf_a1b2c3d4e5f67890_GITHUB_TOKEN", RefusedBody},
		{"strips live", "lab_fence_github", `"stripped": true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			p := preamble.Preamble{
				SNI:     "pf-open-echo.test",
				OrigDst: netip.MustParseAddrPort("192.0.2.3:443"),
			}
			got := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer "+tc.auth+"\r\n\r\n")
			if !strings.Contains(got, tc.want) || strings.Contains(got, "lab_fence_github") {
				t.Fatal(got)
			}
		})
	}
}

func TestOAuthEchoHarvest(t *testing.T) {
	b, path := testBroker(t)
	p := preamble.Preamble{
		SNI:     "pf-core-echo.test",
		OrigDst: netip.MustParseAddrPort("192.0.2.2:443"),
	}
	ort := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	body := `{"grant_type":"refresh_token","refresh_token":"` + ort + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	got := roundtrip(t, b, p, raw)
	if !strings.Contains(got, "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT") || strings.Contains(got, strings.Repeat("N", 8)) {
		t.Fatal(got)
	}
	env, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("N", 64)) {
		t.Fatal(string(env))
	}
}

func TestEchoSNIIgnoresPrivateOrigDst(t *testing.T) {
	b, _ := testBroker(t)
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	p := preamble.Preamble{
		SNI:     "pf-open-echo.test",
		OrigDst: netip.MustParseAddrPort("10.77.0.1:8080"),
	}
	got := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\n\r\n")
	if !strings.Contains(got, `"host": "pf-open-echo.test"`) {
		t.Fatal(got)
	}
	if dialed.Load() {
		t.Fatal("dialed")
	}
}

func TestCoreEchoLabOnly(t *testing.T) {
	b, path := testBroker(t)
	b.LabEcho = false
	before, _ := os.ReadFile(path)
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	got := roundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n")
	if strings.Contains(got, "lab_fence_github") || !strings.Contains(got, "lab_only") {
		t.Fatal(got)
	}
	ort := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	body := `{"grant_type":"refresh_token","refresh_token":"` + ort + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	got = roundtrip(t, b, p, raw)
	if !strings.Contains(got, "lab_only") {
		t.Fatal(got)
	}
	p2 := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	got = roundtrip(t, b, p2, "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n")
	if strings.Contains(got, "lab_fence_github") {
		t.Fatal(got)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatalf("secrets changed:\n%s", after)
	}
	open := preamble.Preamble{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.3:443")}
	got = roundtrip(t, b, open, "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer lab_fence_github\r\n\r\n")
	if !strings.Contains(got, `"stripped": true`) {
		t.Fatal(got)
	}
}

func TestResponseEchoStripped(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"bad token: ` + r.Header.Get("Authorization") + `"}`))
	})
	p := preamble.Preamble{SNI: "api.anthropic.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
	resp, body := roundtripStream(t, b, p, "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n")
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	if strings.Contains(string(body), live) || !strings.Contains(string(body), "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT") {
		t.Fatal(string(body))
	}
	if strings.Contains(resp.Get("X-Echo"), live) || !strings.Contains(resp.Get("X-Echo"), "pf_") {
		t.Fatal(resp.Get("X-Echo"))
	}
	raw, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(raw), `"where":"response"`) || !strings.Contains(string(raw), `"rule":"secret:b0b1b2b3b4b5b6b7_CLAUDE_OAT"`) {
		t.Fatal(string(raw))
	}
}

// The open echo scrubs its reflection with rewriteResponse, and that
// scrub knows only the literal live bytes. A Basic Authorization value
// does not carry them literally. The fence decodes the token68, injects
// the credential into the decoded user:password and re-encodes the
// result. The base64 of a credential shares no substring with it. Thus
// the scrub skips the field, and the echo gives the agent the credential
// in an encoding that it can undo in one line. Selection reads the
// original destination while substitution reads the SNI. Thus the
// fixture address with a permitted SNI is sufficient.
func TestR01OpenEchoReflectsBase64Credential(t *testing.T) {
	b, _ := testBroker(t)
	b.LabEcho = false
	var dialed atomic.Bool
	b.DialTLS = noDial(&dialed)
	p := preamble.Preamble{
		SNI:     "api.anthropic.com",
		OrigDst: netip.MustParseAddrPort("192.0.2.3:443"),
	}
	tok := base64.StdEncoding.EncodeToString([]byte("x:pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"))
	raw := "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Authorization: Basic " + tok + "\r\n\r\n"
	got := roundtrip(t, b, p, raw)
	live := "sk-ant-oat01-" + strings.Repeat("A", 64)
	if strings.Contains(got, live) {
		t.Fatalf("live credential reflected verbatim:\n%s", got)
	}
	for _, dec := range base64Runs(got) {
		if strings.Contains(dec, live) {
			t.Fatalf("live credential reflected base64-encoded as %q:\n%s", dec, got)
		}
	}
	if dialed.Load() {
		t.Fatal("dialed")
	}
}

// base64Runs decodes each maximal base64 alphabet run in s. The echo
// reflects one field. But a test that looked only at that field would
// miss the same value when it arrives through a different field.
func base64Runs(s string) []string {
	var out []string
	isB64 := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
	}
	for i := 0; i < len(s); {
		if !isB64(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isB64(s[j]) {
			j++
		}
		run := s[i:j]
		i = j
		enc := base64.StdEncoding
		if len(run)%4 != 0 {
			enc = base64.RawStdEncoding
		}
		if dec, err := enc.DecodeString(run); err == nil {
			out = append(out, string(dec))
		}
	}
	return out
}

// An echo fixture has no origin, but a streamed body still goes through
// the placeholder guard. A placeholder in it gets the answer that a real
// host gives: the one refusal, and a row that names the cause.
func TestEchoStreamedBodyPlaceholderRefused(t *testing.T) {
	for _, tc := range []struct{ name, sni, dst string }{
		{"core", "pf-core-echo.test", "192.0.2.2:443"},
		{"open", "pf-open-echo.test", "192.0.2.3:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir := t.TempDir()
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
			ph := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
			p := preamble.Preamble{SNI: tc.sni, OrigDst: netip.MustParseAddrPort(tc.dst)}
			raw := "POST / HTTP/1.1\r\nHost: " + tc.sni + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunkWire("k="+ph)
			resp, rb := roundtripStream(t, b, p, raw)
			if resp.Code != 503 || string(rb) != RefusedBody {
				t.Fatalf("%d %q", resp.Code, rb)
			}
			rows, _ := os.ReadFile(b.Logs.StripPath)
			if !strings.Contains(string(rows), `"cause":"placeholder_in_streamed_body"`) || !strings.Contains(string(rows), `"where":"body"`) {
				t.Fatalf("log %q", rows)
			}
		})
	}
}
