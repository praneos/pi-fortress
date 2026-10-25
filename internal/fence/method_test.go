package fence

import (
	"strings"
	"testing"
)

// The method is a token, like a field name. The fence cannot rewrite it.
// Thus a placeholder, a live value or a token-prefix match in the method
// refuses the request on each host, with Where "method", also when the
// target and every field are clean.
func TestKeyInMethodRefused(t *testing.T) {
	alnum := func(n int) string { return strings.Repeat("Ab1", n/3+1)[:n] }
	cases := map[string]string{
		"placeholder":    phGH,
		"placeholder_oa": "pf_0123456789abcdef_CLAUDE_OAT",
		"live_value":     liveGH,
		"live_core_kind": "sk-ant-oat01-" + strings.Repeat("A", 64),
		"github_classic": "ghp_" + alnum(36),
		"aws_akia":       "AKIAABCDEFGHIJKLMNOP",
	}
	for _, sni := range []string{"api.github.com", "api.anthropic.com", "example.com"} {
		for rule, method := range cases {
			t.Run(sni+"/"+rule, func(t *testing.T) {
				raw := method + " / HTTP/1.1\r\nHost: " + sni + "\r\n\r\n"
				req := parseReq(t, raw)
				_, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
				if err == nil {
					t.Fatalf("method %q forwarded", method)
				}
				refs := refusalsOf(t, err)
				for _, r := range refs {
					if r.Where == "method" {
						return
					}
				}
				t.Fatalf("refusals %+v, want one at method", refs)
			})
		}
	}
}

// Ordinary methods pass.
func TestCommonMethodsPass(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND"} {
		req := parseReq(t, m+" / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
}
