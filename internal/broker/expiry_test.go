package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/secrets"
)

func expiryRows(t *testing.T, path string) []jsonl.Strip {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var rows []jsonl.Strip
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r jsonl.Strip
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

// A slot in its last week warns one time each day, under one row for
// both its kinds. A slot past its deadline says so one time. A slot far
// from its deadline, or with no deadline, says nothing.
func TestExpiryWarnsDailyAndOnceWhenPast(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	soon, gone, far, never := "a1b2c3d4e5f67890", "0f0e0d0c0b0a0908", "1111222233334444", "5555666677778888"
	body := secrets.EnvKey(soon, "CLAUDE_OAT") + "=oat\n" + secrets.EnvKey(soon, "CLAUDE_ORT") + "=ort\n" +
		secrets.EnvKey(gone, "GITHUB_TOKEN") + "=g\n" + secrets.EnvKey(far, "GITHUB_TOKEN") + "=f\n" +
		secrets.EnvKey(never, "GITHUB_TOKEN") + "=n\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := secrets.Open(path)
	now := time.Now()
	for slot, at := range map[string]time.Time{soon: now.Add(5*24*time.Hour - time.Hour), gone: now.Add(-time.Hour), far: now.Add(30 * 24 * time.Hour)} {
		if err := st.SetExpiry(slot, at); err != nil {
			t.Fatal(err)
		}
	}
	strip := filepath.Join(dir, "strip.jsonl")
	b := &Broker{Store: st, Logs: &jsonl.Writer{StripPath: strip}}

	b.checkExpiry(now)
	rows := expiryRows(t, strip)
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	for _, r := range rows {
		if r.Threat != threatSlotExpiry {
			t.Fatalf("threat %+v", r)
		}
		switch r.Slot {
		case soon:
			if r.Rule != "slot_expiring:"+soon || r.Where != "CLAUDE_OAT,CLAUDE_ORT" || r.Count != 5 {
				t.Fatalf("soon %+v", r)
			}
		case gone:
			if r.Rule != "slot_expired:"+gone || r.Count != 0 {
				t.Fatalf("gone %+v", r)
			}
		default:
			t.Fatalf("unexpected %+v", r)
		}
	}

	// The next hour says nothing new. The next day warns again, but the
	// watcher does not announce the expired slot two times.
	b.checkExpiry(now.Add(time.Hour))
	if got := len(expiryRows(t, strip)); got != 2 {
		t.Fatalf("an hour later: %d rows", got)
	}
	b.checkExpiry(now.Add(25 * time.Hour))
	rows = expiryRows(t, strip)
	if len(rows) != 3 || rows[2].Slot != soon || rows[2].Count != 4 {
		t.Fatalf("a day later: %+v", rows)
	}
}
