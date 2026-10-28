package tokenrules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTokenREFailsClosed(t *testing.T) {
	if _, err := LoadTokenRE(filepath.Join(t.TempDir(), "missing.rules")); err == nil {
		t.Fatal("missing rules file must error")
	}
	empty := filepath.Join(t.TempDir(), "empty.rules")
	if err := os.WriteFile(empty, []byte("# nothing here\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenRE(empty); !errors.Is(err, ErrNoRules) {
		t.Fatalf("empty rules: %v", err)
	}
}

// A. A rules file whose scan stops early loaded as the part that it read.
// A line past the bufio token limit causes this. The broker then started
// and treated that part as the full ruleset.
func TestTruncatedRulesFileRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.rules")
	lines := "github_classic\t\\bghp_[A-Za-z0-9]{36}\\b\tGITHUB_TOKEN\n" +
		"overlong\t\\b" + strings.Repeat("x", 128<<10) + "\\b\n" +
		"npm\t\\bnpm_[A-Za-z0-9]{36}\\b\n"
	if err := os.WriteFile(path, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}
	tr, err := LoadTokenRules(path)
	if err == nil {
		t.Fatalf("a half-read rules file started the fence with %d of 3 rules", len(tr.Rules))
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
