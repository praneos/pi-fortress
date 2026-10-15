package www

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/audit"
)

func auditEntries(t *testing.T, path string) ([]audit.Entry, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
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
	return entries, string(raw)
}

// A redeem of a claim gives the credentials of a slot to an agent and spends
// the code. This is a change to the gateway that never touches
// admin.CallCtx. Before this, the change was only in the claims ledger. So
// the admin log could not tell "which agent got which slot, and when".
func TestRedeemWritesAnAuditLine(t *testing.T) {
	s, ts := testServer(t)
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	s.Audit = audit.New(log)
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(claims, "a1b2c3d4e5f67890", []string{"CLAUDE_OAT", "CLAUDE_ORT"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, ts.URL+"/claim/"+c.Code); code != 200 {
		t.Fatal(code)
	}
	entries, raw := auditEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	e := entries[0]
	if e.Verb != "claim.redeem" || !e.OK || e.Args["slot"] != "a1b2c3d4e5f67890" || e.T == "" {
		t.Fatalf("entry: %+v", e)
	}
	// No user signed in here. So the entry records what it can see: the
	// address that gave a code. It labels that address as an agent, so that no
	// reader reads it as an operator. Role stays empty for the same reason: no
	// role was checked.
	if !strings.HasPrefix(e.Actor, "agent:") || e.Role != "" {
		t.Fatalf("actor/role: %+v", e)
	}
}

// The claim code is a bearer token: a holder of the code can take the
// credentials of the slot. The ledger keeps the code, because a ledger line
// connects a claim to the issue that made it. The audit log answers a
// question for a different reader. It must not become a place to harvest
// codes. The same principle keeps admin.Args.Secret out.
func TestRedeemNeverWritesTheClaimCode(t *testing.T) {
	s, ts := testServer(t)
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	s.Audit = audit.New(log)
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(claims, "a1b2c3d4e5f67890", []string{"GITHUB_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, ts.URL+"/claim/"+c.Code); code != 200 {
		t.Fatal(code)
	}
	_, raw := auditEntries(t, log)
	if strings.Contains(raw, c.Code) || strings.Contains(raw, strings.ToLower(c.Code)) {
		t.Fatalf("the audit log carries the claim code:\n%s", raw)
	}
	// The code does belong in the ledger. So prove that the two records are
	// different, not only that nothing was written anywhere.
	ledger, _ := os.ReadFile(LedgerPath(claims))
	if !strings.Contains(string(ledger), c.Code) {
		t.Fatalf("ledger lost the code:\n%s", ledger)
	}
}

// A wrong code gets the same 404 as a spent code, and the audit log does
// not record it. This listener answers all clients on the agent segment. A
// record of each miss gives a scanner the admin log as a place to write.
// The verb table makes the opposite decision: there, a denial is the most
// useful entry, because only a user already on the gateway can cause one.
func TestARefusedClaimIsNotAudited(t *testing.T) {
	s, ts := testServer(t)
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	s.Audit = audit.New(log)
	if err := os.MkdirAll(ClaimsDir(s.Dir), 0770); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, ts.URL+"/claim/ZZZZZZ"); code != 404 {
		t.Fatal(code)
	}
	if entries, raw := auditEntries(t, log); len(entries) != 0 {
		t.Fatalf("a miss was recorded: %q", raw)
	}
}
