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
// does not flush. A run after a list change flushes again.
func TestNFTSetsPolicyFlushesOnlyWhenThePolicyChanged(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "blocked-domains.conf")
	cfg := filepath.Join(dir, "dns.json")
	state := filepath.Join(dir, "resolved-policy.state")
	if err := os.WriteFile(list, []byte("address=/bad.example/0.0.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := `{"segments": [{"iface": "eth1", "sinkhole": ["` + list + `"], "nft_set": "resolved_v4"}]}`
	if err := os.WriteFile(cfg, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	n := &policyNFT{}
	runs := func(want int) {
		t.Helper()
		var out, errb bytes.Buffer
		if code := nftsetsPolicy(n.run, "inet fortress", cfg, state, &out, &errb); code != 0 {
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
	if err := os.WriteFile(list, []byte("address=/bad.example/0.0.0.0\naddress=/worse.example/0.0.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runs(2)
	runs(2)
}

// When the config cannot be read, nothing says which policy changed. Thus
// each resolved set is flushed, and the exit code tells apply.
func TestNFTSetsPolicyFlushesAllWhenItCannotReadTheConfig(t *testing.T) {
	dir := t.TempDir()
	n := &policyNFT{}
	var out, errb bytes.Buffer
	if code := nftsetsPolicy(n.run, "inet fortress", filepath.Join(dir, "none.json"), filepath.Join(dir, "state"), &out, &errb); code == 0 {
		t.Fatal("a missing config gave exit 0")
	}
	if len(n.scripts) != 1 || n.scripts[0] != "flush set inet fortress resolved_v4\n" {
		t.Fatalf("scripts %q, want one flush of resolved_v4", n.scripts)
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Fatalf("a failed run wrote the state: %v", err)
	}
}
