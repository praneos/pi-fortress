package fence

import (
	"fmt"
	"strings"
	"testing"
)

// percentEncodeAll encodes each byte of s as %XX.
func percentEncodeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// The origin decodes the target, so the fence reads the decoded form too.
// A placeholder, a foreign live value or a token-prefix match that is
// percent-encoded in the target refuses the request, with Where "url", on
// each host. This includes an encoding nested in more levels.
func TestPercentEncodedKeyInTargetRefused(t *testing.T) {
	alnum := func(n int) string { return strings.Repeat("Ab1", n/3+1)[:n] }
	ghp := "ghp_" + alnum(36)
	// 'p' under six levels of percent-encoding.
	nested := "%70"
	for range 5 {
		nested = strings.ReplaceAll(nested, "%", "%25")
	}
	cases := map[string]string{
		"placeholder_5f":     "/?x=pf%5Fa1b2c3d4e5f67890%5FGITHUB_TOKEN",
		"placeholder_oat":    "/?x=pf%5F0123456789abcdef%5FCLAUDE_OAT",
		"placeholder_all":    "/?x=" + percentEncodeAll(phGH),
		"placeholder_double": "/?x=pf%255Fa1b2c3d4e5f67890%255FGITHUB_TOKEN",
		"placeholder_path":   "/a/" + percentEncodeAll("pf_") + "a1b2c3d4e5f67890_GITHUB_TOKEN",
		"token_all":          "/?x=" + percentEncodeAll(ghp),
		"token_split":        "/?x=%67%68%70%5F" + alnum(36),
		"live_foreign":       "/?x=" + percentEncodeAll("sk-ant-oat01-"+strings.Repeat("A", 64)),
		"placeholder_deep":   "/?x=" + nested + "f_a1b2c3d4e5f67890_GITHUB_TOKEN",
	}
	for _, sni := range []string{"api.github.com", "example.com"} {
		for name, target := range cases {
			t.Run(sni+"/"+name, func(t *testing.T) {
				// A literal ghp_ token in the target of its own host
				// is not stripped either (no StripCore). Same rule.
				if sni == "api.github.com" && strings.HasPrefix(name, "token_") {
					t.Skip("own-kind token on its host, kept as in the raw target")
				}
				raw := "GET " + target + " HTTP/1.1\r\nHost: " + sni + "\r\n\r\n"
				req := parseReq(t, raw)
				_, err := Decide(Ctx{SNI: sni, TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
				if err == nil {
					t.Fatalf("target %q forwarded as %q", target, req.Target)
				}
				for _, r := range refusalsOf(t, err) {
					if r.Where == "url" {
						return
					}
				}
				t.Fatalf("refusals %+v, want one at url", refusalsOf(t, err))
			})
		}
	}
}

// The raw target keeps its behaviour: a literal token strips in place, also
// next to an unrelated escape, and ordinary escapes pass.
func TestRawTargetStripAndEscapesUnchanged(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("Ab1", 12)
	for _, target := range []string{
		"/?x=" + ghp + "&q=a%20b",
		"/search?q=hello%20world&r=%2Fpath%3Fa%3D1",
		"/files/a%2520b",
	} {
		req := parseReq(t, "GET "+target+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots()); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if strings.Contains(req.Target, ghp) {
			t.Fatalf("%s: token not stripped: %s", target, req.Target)
		}
	}
}
