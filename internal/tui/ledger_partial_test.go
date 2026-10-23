package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

func TestPartialLedgerIsNotRenderedAsNever(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = t.TempDir()
	claims := filepath.Join(c.WWWDir, "claims-redeemed")
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ledger.jsonl", "ledger.jsonl.1"} {
		if err := os.WriteFile(filepath.Join(claims, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	last := run(t, c, NewFake(130, 60).Type(keys(netSystem, secHealth))).Last()
	if strings.Contains(last, "last redeem never") || strings.Contains(last, "last fetch never") {
		t.Fatalf("a tail of the ledger rendered as never:\n%s", last)
	}
	if !strings.Contains(last, "partial") {
		t.Fatalf("nothing qualifies the ledger figures:\n%s", last)
	}
}

// With the full ledger available, "never" is the correct word, and it stays.
func TestWholeLedgerStillSaysNever(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(c.WWWDir, "claims"), 0770); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(130, 60).Type(keys(netSystem, secHealth))).Last()
	if !strings.Contains(last, "last redeem never") {
		t.Fatalf("a complete ledger should still say never:\n%s", last)
	}
}

// The same claim on the Secrets screen. The code read a use log through a
// window that reached only part of the way back. A slot that is not in it
// is not shown to be unused. "never" is the word that makes an operator
// delete a live credential.
func TestPartialUseLogIsNotRenderedAsNever(t *testing.T) {
	c, _ := testConfig(t)
	c.UseLog = filepath.Join(t.TempDir(), "use.jsonl")
	slot, err := secrets.Open(c.SecretsPath).MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "ghp_live"})
	if err != nil {
		t.Fatal(err)
	}
	// Longer than the window that admin reads, and about a different slot.
	// Thus this slot is absent from what the code read, not from the log.
	var b strings.Builder
	for range 6000 {
		b.WriteString(`{"t":"2026-01-01T00:00:00Z","slot":"other","host":"agent"}` + "\n")
	}
	if err := os.WriteFile(c.UseLog, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys))).Last()
	// Only the row of the slot itself: "never fetched" in the standing feeds
	// warning is a different screen element with a different claim.
	line := ""
	for _, l := range strings.Split(last, "\n") {
		if strings.Contains(l, slot) {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("slot %s not on the screen:\n%s", slot, last)
	}
	if strings.Contains(line, "never") {
		t.Fatalf("a slot missing from a partial use log rendered as never:\n%s", line)
	}
	if !strings.Contains(line, "partial") {
		t.Fatalf("nothing qualifies the last-use column:\n%s", line)
	}
}
