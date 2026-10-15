package fence

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

// A field name is a token, and most key formats are tokens too. The fence
// cannot rewrite a name, so a key in a name refuses the request, on each
// host, also when the value of the field is clean.
func TestKeyInHeaderNameRefused(t *testing.T) {
	alnum := func(n int) string { return strings.Repeat("Ab1", n/3+1)[:n] }
	cases := map[string]string{
		"github_classic": "X-ghp_" + alnum(36),
		"github_fine":    "github_pat_" + alnum(22) + "_" + alnum(59),
		"anthropic_oat":  "X-sk-ant-oat01-" + strings.Repeat("Z", 40),
		"aws_akia":       "X-AKIAABCDEFGHIJKLMNOP",
		"npm":            "X-npm_" + alnum(36),
		"gitlab":         "X-glpat-" + alnum(20),
		"huggingface":    "hf_" + strings.Repeat("abc", 12),
		"live_value":     "X-lab_fence_github",
		"live_core_kind": "X-sk-ant-oat01-" + strings.Repeat("A", 64),
		"placeholder":    "X-" + phGH,
	}
	for _, sni := range []string{"api.github.com", "api.anthropic.com", "example.com"} {
		for rule, name := range cases {
			t.Run(sni+"/"+rule, func(t *testing.T) {
				raw := "GET /user HTTP/1.1\r\nHost: " + sni + "\r\n" + name + ": 1\r\n\r\n"
				req := parseReq(t, raw)
				_, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
				refs := refusalsOf(t, err)
				for _, r := range refs {
					if r.Cause == CauseKeyInHeaderName && r.Where == "header_name" {
						return
					}
				}
				t.Fatalf("refusals %+v, want %s", refs, CauseKeyInHeaderName)
			})
		}
	}
}

func TestKeyInHeaderNameNamesSlot(t *testing.T) {
	req := parseReq(t, "GET /user HTTP/1.1\r\nHost: example.com\r\nX-"+phGH+": 1\r\n\r\n")
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	want := Refusal{Cause: CauseKeyInHeaderName, Slot: "a1b2c3d4e5f67890", Kind: "GITHUB_TOKEN", Where: "header_name"}
	for _, r := range refusalsOf(t, err) {
		if r == want {
			return
		}
	}
	t.Fatalf("no %+v in %v", want, err)
}

// The names that real clients send must not trip the check.
func TestCommonHeaderNamesPass(t *testing.T) {
	names := []string{
		"User-Agent", "Accept", "Accept-Encoding", "X-Api-Key", "X-GitHub-Api-Version",
		"anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access",
		"x-stainless-arch", "x-stainless-package-version", "x-stainless-retry-count",
		"OpenAI-Organization", "OpenAI-Project", "X-Amz-Date", "X-Amz-Security-Token",
		"X-Amz-Content-Sha256", "Sec-Fetch-Mode", "X-Request-Id", "Idempotency-Key",
		"X-Forwarded-For", "Git-Protocol", "X-Goog-Api-Client", "PRIVATE-TOKEN",
	}
	for _, sni := range []string{"api.anthropic.com", "example.com"} {
		var b strings.Builder
		b.WriteString("GET /v1/x HTTP/1.1\r\nHost: " + sni + "\r\n")
		for _, n := range names {
			b.WriteString(n + ": 1\r\n")
		}
		b.WriteString("\r\n")
		req := parseReq(t, b.String())
		if _, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
	}
}

// FuzzKeyNeverInHeaderName: when the fence lets a request go, no field
// name on the wire holds a live value, a placeholder or a key match.
func FuzzKeyNeverInHeaderName(f *testing.F) {
	f.Add("X-ghp_"+strings.Repeat("a", 36), "example.com")
	f.Add("X-lab_fence_github", "api.github.com")
	f.Add("x-"+phGH, "api.github.com")
	f.Add("X-AKIAABCDEFGHIJKLMNOP", "example.com")
	f.Add("anthropic-version", "api.anthropic.com")
	re, pol := testPolicy(f)
	slots := labSlots()
	f.Fuzz(func(t *testing.T, name, sni string) {
		raw := "GET /x HTTP/1.1\r\nHost: " + sni + "\r\n" + name + ": 1\r\n\r\n"
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		if _, err := Decide(Ctx{SNI: sni, TokenRE: re}, req, pol, slots); err != nil {
			return
		}
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			return
		}
		again, err := httpwire.ReadRequest(bufio.NewReader(&out))
		if err != nil {
			t.Fatalf("rewritten request unparseable: %v", err)
		}
		for _, fl := range again.Fields {
			n := []byte(fl.Name)
			if re.Match(n) || len(secrets.FindPlaceholderSpans(n)) > 0 {
				t.Fatalf("key-shaped name on the wire: %q", fl.Name)
			}
			for _, sl := range slots {
				if bytes.Contains(n, []byte(sl.Live)) {
					t.Fatalf("live value in a name on the wire: %q", fl.Name)
				}
			}
		}
	})
}
