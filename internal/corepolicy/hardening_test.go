package corepolicy

import "testing"

func TestAuthorityHostHeaderParsing(t *testing.T) {
	p := load(t)
	cases := []struct {
		host string
		ok   bool
	}{
		{"api.anthropic.com", true},
		{"API.Anthropic.COM:443", true},
		{"api.anthropic.com.", true},
		{"api.anthropic.com%00.evil", false},
		{"api.anthropic.com%:443", false},
		{"[::1]:443", false},
		{"[::1]", false},
		{"api.anthropic.com:443:9", false},
		{"evil.example:443", false},
	}
	for _, c := range cases {
		if got := p.Authority("api.anthropic.com", c.host); got != c.ok {
			t.Fatalf("Authority(api.anthropic.com, %q)=%v want %v", c.host, got, c.ok)
		}
	}
}
