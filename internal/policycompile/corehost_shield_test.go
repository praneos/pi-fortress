package policycompile

import (
	"os"
	"path/filepath"
	"testing"

	"pi-fortress/internal/blocklist"
)

// compileAgentBlocklist writes the given policy files, compiles, and loads
// the compiled agent block list the way the broker does.
func compileAgentBlocklist(t *testing.T, files map[string]string) *blocklist.Set {
	t.Helper()
	dir, out := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dns := filepath.Join(out, "blocked-domains.conf")
	if _, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: dns}); err != nil {
		t.Fatal(err)
	}
	set, err := blocklist.Load(dns)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// A feed entry for a parent domain blocks every name under it, but not a
// host that core.hosts binds credentials to. An entry under an exact core
// host does not block the host, so it stays.
func TestFeedParentEntryDoesNotBlockACoreHost(t *testing.T) {
	set := compileAgentBlocklist(t, map[string]string{
		"core.hosts":                  "api.anthropic.com CLAUDE_OAT\n*.openai.example OPENAI_API_KEY\n",
		"generated/blacklist.domains": "anthropic.com\nx.openai.example\nevil.api.anthropic.com\nbad.example\n",
	})
	for _, name := range []string{"api.anthropic.com", "x.openai.example"} {
		if set.Has(name) {
			t.Errorf("a feed entry blocks core host %s", name)
		}
	}
	for _, name := range []string{"evil.api.anthropic.com", "bad.example"} {
		if !set.Has(name) {
			t.Errorf("feed entry %s was dropped", name)
		}
	}
}

// The same applies to a feed entry equal to a core host, from core.hosts
// or from core.hosts.local.
func TestFeedEntryDoesNotBlockACoreHost(t *testing.T) {
	set := compileAgentBlocklist(t, map[string]string{
		"core.hosts":                  "api.anthropic.com CLAUDE_OAT\n",
		"core.hosts.local":            "api.mistral.ai MISTRAL_API_KEY\n",
		"generated/blacklist.domains": "api.anthropic.com\nmistral.ai\nbad.example\n",
	})
	for _, name := range []string{"api.anthropic.com", "api.mistral.ai"} {
		if set.Has(name) {
			t.Errorf("a feed line blocks core host %s", name)
		}
	}
	if !set.Has("bad.example") {
		t.Error("an unrelated feed entry was dropped")
	}
}

// never_block stays the coarse shield that docs/fence.md describes: a
// shield below a listed parent leaves the parent entry in place.
func TestNeverBlockBelowAParentKeepsTheParent(t *testing.T) {
	set := compileAgentBlocklist(t, map[string]string{
		"never_block.domains":         "myapp.herokuapp.com\n",
		"generated/blacklist.domains": "herokuapp.com\n",
	})
	if !set.Has("herokuapp.com") {
		t.Error("a never_block name below a listed parent dropped the parent entry")
	}
}
