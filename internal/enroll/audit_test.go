package enroll

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/secrets"
)

// auditRun runs one pf enroll invocation against a throwaway store, with
// the audit log pointed at a place where a test may write. It gives back
// each entry that it made.
func auditRun(t *testing.T, store string, stdin string, args ...string) ([]audit.Entry, int, string) {
	t.Helper()
	log := filepath.Join(filepath.Dir(store), "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	t.Setenv("SUDO_USER", "tester")
	var out, errb strings.Builder
	rc := MainIO(append([]string{"--secrets", store}, args...), strings.NewReader(stdin), &out, &errb)
	raw, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line does not parse: %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries, rc, string(raw)
}

func newStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pf enroll is its own binary and never reaches admin.CallCtx. So until
// logEnroll existed, the credential store could gain and lose slots with
// nothing in the audit log to say so. Each subcommand that writes must
// leave a line that names itself, the operator and the outcome.
func TestEnrollWritesAnAuditLineForEveryMutation(t *testing.T) {
	store := newStore(t)
	oat, ort := OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40)

	entries, rc, _ := auditRun(t, store, oat+"\n"+ort+"\n", "mint", "--kind", "CLAUDE", "--stdin")
	if rc != 0 || len(entries) != 1 {
		t.Fatalf("mint rc=%d entries=%v", rc, entries)
	}
	mint := entries[0]
	if mint.Verb != "enroll.mint" || !mint.OK || mint.Actor != "sudo:tester" || mint.Ev != "verb" {
		t.Fatalf("mint entry: %+v", mint)
	}
	if mint.T == "" {
		t.Fatalf("mint entry has no timestamp: %+v", mint)
	}
	slot := mint.Args["slot"]
	if len(slot) != secrets.SlotLen || mint.Args["kind"] != "CLAUDE" {
		t.Fatalf("mint args: %+v", mint.Args)
	}

	// Quarantine the slot, so that the retention purge has something to take.
	// Then run the purge that vm/pi/apply.sh runs unattended on each apply.
	if err := secrets.Open(store).Disable(slot); err != nil {
		t.Fatal(err)
	}
	entries, rc, _ = auditRun(t, store, "", "purge", "--older-than", "0d")
	if rc != 0 || len(entries) != 2 {
		t.Fatalf("purge rc=%d entries=%v", rc, entries)
	}
	purge := entries[1]
	if purge.Verb != "enroll.purge" || !purge.OK || purge.Args["older-than"] != "0d" ||
		purge.Args["purged"] != "1" || purge.Args["slots"] != slot {
		t.Fatalf("purge entry: %+v", purge)
	}
}

// A read is not a change. list, peek and state are most of the traffic. A
// record of them would bury the writes, which are the point. Verb.Mutates
// makes the same decision for the verb table.
func TestEnrollDoesNotRecordReadsOrUnknownSubcommands(t *testing.T) {
	store := newStore(t)
	for _, args := range [][]string{{"list"}, {"state"}, {"peek"}, {"nonsense"}} {
		entries, _, raw := auditRun(t, store, "", args...)
		if len(entries) != 0 {
			t.Fatalf("%v wrote %q", args, raw)
		}
	}
}

// A failed mutation is still a mutation attempt, and it still gets a line.
// The outcome is an exit code, because that is all that this layer has:
// the subcommands print their diagnosis to stderr and return a number.
func TestEnrollRecordsAFailedMutation(t *testing.T) {
	store := newStore(t)
	entries, rc, _ := auditRun(t, store, "", "delete", "--slot", "a1b2c3d4e5f67890")
	if rc != 1 || len(entries) != 1 {
		t.Fatalf("rc=%d entries=%v", rc, entries)
	}
	if e := entries[0]; e.Verb != "enroll.delete" || e.OK || e.Err != "exit 1" || e.Args["slots"] != "" {
		t.Fatalf("entry: %+v", e)
	}
}

// This is the reason that admin.Args.Secret exists: a record of what was
// minted must never be a copy of it. --oat, --ort and --value carry the
// credential itself. cmdMint builds the audit payload from the slot and
// the kind, and does not scrape it from the argv that also held the
// tokens. So a token cannot reach the log through a parse of the same line.
func TestEnrollNeverWritesTheCredentialItMinted(t *testing.T) {
	store := newStore(t)
	oat, ort := OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40)
	_, rc, raw := auditRun(t, store, oat+"\n"+ort+"\n", "mint", "--kind", "CLAUDE", "--stdin")
	if rc != 0 {
		t.Fatal(rc)
	}
	for _, token := range []string{oat, ort} {
		if strings.Contains(raw, token) {
			t.Fatalf("the audit log carries the credential:\n%s", raw)
		}
	}

	// The same for a value passed as a flag, not on stdin. On that path,
	// the secret actually is in the argv.
	value := "ghp_" + strings.Repeat("z", 36)
	_, rc, raw = auditRun(t, store, "", "mint", "--kind", "GITHUB_TOKEN", "--value", value,
		"--out", filepath.Join(t.TempDir(), "paste"))
	if rc != 0 {
		t.Fatal(rc)
	}
	if strings.Contains(raw, value) {
		t.Fatalf("the audit log carries the credential:\n%s", raw)
	}
}
