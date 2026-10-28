package fence

import (
	"path/filepath"
	"testing"

	"pi-fortress/internal/testsupport"
	"pi-fortress/internal/tokenrules"
)

// The shipped rules all have a literal prefix, so the broker starts.
func TestShippedRulesAreStreamable(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
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
