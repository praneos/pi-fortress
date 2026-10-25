package keyshape

import "testing"

// pf dns, the engine and the broker SNI check all use Match. DNS and TLS
// names fold case. Thus Match finds a placeholder in any letter case, or
// with a letter added, in one label or split across labels, with or
// without heads.
func TestMatchPlaceholderVariantInName(t *testing.T) {
	heads, _ := Heads(nil)
	for _, name := range []string{
		"pf_0123456789abcdef_github_token.evil.example",
		"pf_0123456789abcdef_GITHUB_TOKENx.evil.example",
		"PF_0123456789ABCDEF_GITHUB_TOKEN.evil.example",
		"Pf_0123456789abcdef_Claude_Oat.evil.example",
		"pf_01234567.89abcdef_claude.oat.evil.example",
		"pf_0123456789abcdef_GITHUB_TOKEN.evil.example",
	} {
		for _, h := range [][]string{heads, nil} {
			if got := Match(nil, h, name); got != "placeholder" {
				t.Errorf("%s (heads %v): got %q", name, h != nil, got)
			}
		}
	}
	for _, name := range []string{"example.com", "pf_dns.example", "my_pf_host.example"} {
		if got := Match(nil, heads, name); got != "" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}
