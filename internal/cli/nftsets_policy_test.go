package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyNFT is an nft with resolved_v4 and blacklist_v4. It records each
// script that it gets on stdin.
type policyNFT struct{ scripts []string }

func (n *policyNFT) run(stdin string, args ...string) (string, error) {
	if strings.Join(args, " ") == "list sets table inet fortress" {
		return "table inet fortress {\n\tset blacklist_v4 {\n\t}\n\tset resolved_v4 {\n\t}\n}\n", nil
	}
	n.scripts = append(n.scripts, stdin)
	return "", nil
}

// The first run has no state, so it flushes. A run with the same policy
// does not flush. A feed-only change (the compiled sinkhole) does not
// flush. An allow-list change and an operator blocklist change flush.
func TestNFTSetsPolicyFlushesOnlyWhenThePolicyChanged(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	if err := os.Mkdir(policy, 0o755); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(dir, "blocked-domains.conf")
	allow := filepath.Join(dir, "allow.domains")
	cfg := filepath.Join(dir, "dns.json")
	state := filepath.Join(dir, "resolved-policy.state")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(list, "address=/bad.example/0.0.0.0\n")
	write(allow, "github.com\n")
	write(cfg, `{"segments": [{"iface": "eth1", "sinkhole": ["`+list+`"], "nft_set": "resolved_v4", "paranoid": true, "allow": "`+allow+`"}]}`)
	n := &policyNFT{}
	runs := func(want int) {
		t.Helper()
		var out, errb bytes.Buffer
		if code := nftsetsPolicy(n.run, "inet fortress", cfg, policy, state, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		if len(n.scripts) != want {
			t.Fatalf("%d flushes, want %d: %q", len(n.scripts), want, n.scripts)
		}
	}
	runs(1)
	if n.scripts[0] != "flush set inet fortress resolved_v4\n" {
		t.Fatalf("script %q", n.scripts[0])
	}
	runs(1)
	write(list, "address=/bad.example/0.0.0.0\naddress=/feed-new.example/0.0.0.0\n")
	runs(1)
	write(allow, "github.com\npypi.org\n")
	runs(2)
	runs(2)
	write(filepath.Join(policy, "blacklist.domains"), "operator-block.example\n")
	runs(3)
	runs(3)
}

// When the config cannot be read, nothing says which policy changed. Thus
// each resolved set is flushed, and the exit code tells apply.
func TestNFTSetsPolicyFlushesAllWhenItCannotReadTheConfig(t *testing.T) {
	dir := t.TempDir()
	n := &policyNFT{}
	var out, errb bytes.Buffer
	if code := nftsetsPolicy(n.run, "inet fortress", filepath.Join(dir, "none.json"), dir, filepath.Join(dir, "state"), &out, &errb); code == 0 {
		t.Fatal("a missing config gave exit 0")
	}
	if len(n.scripts) != 1 || n.scripts[0] != "flush set inet fortress resolved_v4\n" {
		t.Fatalf("scripts %q, want one flush of resolved_v4", n.scripts)
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Fatalf("a failed run wrote the state: %v", err)
	}
}
