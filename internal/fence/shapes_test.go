package fence

import (
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// OpenAI stopped the issue of the 48-character sk- key. What an agent finds
// in a .env today is a project, service-account or admin key. An xAI key is
// xai- and 80 more. None of them matched a rule, so a key that the agent
// never got went to any host whole. The fence strips each shape off a
// foreign host, strips it off a core host of a different kind with
// StripCore on, and does not change it on its own host.
func TestCurrentOpenAIAndXAIShapes(t *testing.T) {
	rules, err := LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	body := func(n int) string { return strings.Repeat("aB3_x-Z9", n/8+1)[:n] + "Q" }
	for _, tc := range []struct{ name, key, home string }{
		{"project", "sk-proj-" + body(73) + "T3BlbkFJ" + body(73), "api.openai.com"},
		{"service account", "sk-svcacct-" + body(73) + "T3BlbkFJ" + body(73), "api.openai.com"},
		{"admin", "sk-admin-" + body(57) + "T3BlbkFJ" + body(57), "api.openai.com"},
		{"no project", "sk-None-" + body(57) + "T3BlbkFJ" + body(57), "api.openai.com"},
		{"xai", "xai-" + strings.Repeat("Ab3_", 20), "api.x.ai"},
	} {
		for _, sni := range []string{"example.com", "api.anthropic.com", tc.home} {
			t.Run(tc.name+" to "+sni, func(t *testing.T) {
				b := `{"k":"` + tc.key + `"}`
				req := parseReq(t, "POST /v1/x HTTP/1.1\r\nHost: "+sni+"\r\nContent-Length: "+strconv.Itoa(len(b))+"\r\n\r\n"+b)
				if _, err := Decide(Ctx{SNI: sni, Rules: rules, StripCore: true}, req, loadPol(t), labSlots()); err != nil {
					t.Fatal(err)
				}
				out, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				kept := strings.Contains(string(out), tc.key)
				if want := sni == tc.home; kept != want {
					t.Fatalf("kept=%v want %v: %q", kept, want, out)
				}
				if !kept && strings.Contains(string(out), tc.key[len(tc.key)-20:]) {
					t.Fatalf("stripped only part of the key: %q", out)
				}
			})
		}
	}
	// Names that share a prefix and are not keys stay as they are.
	for _, s := range []string{"xai-grok-4", "sk-proj-settings", "sk-admin-panel", "the xai-sdk_python package"} {
		b := `{"k":"` + s + `"}`
		req := parseReq(t, "POST /v1/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: "+strconv.Itoa(len(b))+"\r\n\r\n"+b)
		if _, err := Decide(Ctx{SNI: "example.com", Rules: rules}, req, loadPol(t), labSlots()); err != nil {
			t.Fatal(err)
		}
		if out, _ := io.ReadAll(req.Body); string(out) != b {
			t.Fatalf("%q was stripped: %q", s, out)
		}
	}
}
