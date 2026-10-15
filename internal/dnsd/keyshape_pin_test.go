package dnsd

import (
	"strings"
	"testing"
)

// TestKeyShapePinned holds the set of names that the key-shape check
// refuses, and what the log keeps of each. The cases are at the edges of
// the run rules: the last label, the TLD shape, a key in many short
// labels, the case of a placeholder, empty labels and a root dot.
func TestKeyShapePinned(t *testing.T) {
	k := mustKeyShapes(t)
	key := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct{ name, rule, log string }{
		{"x." + key, "github_classic", ""},
		{key, "github_classic", ""},
		{key + ".", "github_classic", ""},
		{"www." + key + ".de", "github_classic", ""},
		{"x." + key + ".abcdefghijklmnopqrstuvwxy", "github_classic", ""},
		{"x." + key + ".xn--p1ai", "github_classic", ""},
		{"x." + key + ".XN--P1AI", "github_classic", ""},
		{"www.." + key + ".com", "github_classic", ""},
		{"tun." + key + ".evil.example", "github_classic", "evil.example"},
		{"asia.kuecheerlangen.de", "", "kuecheerlangen.de"},
		{"www.asia.kuecheerlangen", "", "asia.kuecheerlangen"},
		{"AKIAQ7Q7Q7Q7Q7Q7Q7Q7.7Q", "aws_akia", ""},
		{"x.AKIAQ7Q7Q7Q7Q7Q7Q7.7Q", "aws_akia", ""},
		{"akiaaaaaaaaaaaaaaaaa.evil.example", "aws_akia", "evil.example"},
		{"pf_0123456789abcdef_CLAUDE_OAT.evil.example", "placeholder", "evil.example"},
		{"PF_0123456789ABCDEF_CLAUDE_OAT.evil.example", "", "evil.example"},
		{"pf_0123456789abcdef._CLAUDE_OAT.com", "placeholder", "_CLAUDE_OAT.com"},
		{"x.pf_0123456789abcdef._CLAUDE_OAT", "placeholder", ""},
		{"ghp_AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAA.x.y", "github_classic", "x.y"},
		{"q.ghp_AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAA", "", "ghp_AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAA"},
		{"ghp_A.AAAAA.AAAAA.AAAAA.AAAAA.AAAAA.AAAAA.AAAAA.x.y", "github_classic", "x.y"},
		{"ghp_.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA.x.y", "github_classic", "x.y"},
		{"www.www.", "", "www."},
		{"evil.example", "", "evil.example"},
		{"", "", ""},
		{".", "", "."},
	} {
		if got := k.match(tc.name); got != tc.rule {
			t.Errorf("match(%q) = %q, want %q", tc.name, got, tc.rule)
		}
		if got := k.logName(tc.name); got != tc.log {
			t.Errorf("logName(%q) = %q, want %q", tc.name, got, tc.log)
		}
	}
}
