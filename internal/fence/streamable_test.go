package fence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// The shipped rules all have a literal prefix, so the broker starts.
func TestShippedRulesAreStreamable(t *testing.T) {
	rules, err := LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.Streamable(); err != nil {
		t.Fatal(err)
	}
	if !tokensFor(rules.All()).complete {
		t.Fatal("each rule has a prefix, but the joined set has no complete prefilter")
	}
}

// A rule with no literal prefix is refused, and the error names it.
func TestStreamableRefusesRuleWithNoPrefix(t *testing.T) {
	for _, tc := range []struct {
		name, expr string
		ok         bool
	}{
		{"prefix", `ghp_[A-Za-z0-9]{36}`, true},
		{"lead", `\bsk-[A-Za-z0-9]{40}`, true},
		{"folded", `(?i)akia[A-Z0-9]{16}`, true},
		{"class", `[A-Za-z0-9]{40}`, false},
		{"dot", `.{32}`, false},
		{"optional", `(?:tok_)?[a-f0-9]{32}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key_prefixes.rules")
			body := "github ghp_[A-Za-z0-9]{36}\ncustom " + tc.expr + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			rules, err := LoadTokenRules(path)
			if err != nil {
				t.Fatal(err)
			}
			err = rules.Streamable()
			if tc.ok && err != nil {
				t.Fatalf("refused %s: %v", tc.expr, err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "rule custom ")) {
				t.Fatalf("%s: got %v, want a refusal that names rule custom", tc.expr, err)
			}
		})
	}
}
