package secrets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseExpiresSkipsBadRows(t *testing.T) {
	raw := "badid 123\n" +
		slotID(1) + " 0\n" +
		slotID(2) + " -5\n" +
		slotID(3) + " abc\n" +
		slotID(4) + " 100\n"
	m := parseExpires(raw)
	if len(m) != 1 || m[slotID(4)] != 100 {
		t.Fatalf("%+v", m)
	}
}

// The expiry sidecar works like the quarantine sidecar. A slot with no
// entry works exactly as it did before expiry existed. A future deadline
// does not change Live. A past deadline blanks Live and marks Expired.
// §5.2b already gives a disabled slot the same shape.
func TestExpirySidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot, other := "a1b2c3d4e5f67890", "0f0e0d0c0b0a0908"
	body := EnvKey(slot, "GITHUB_TOKEN") + "=live_a\n" + EnvKey(other, "GITHUB_TOKEN") + "=live_b\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)

	// Backward compat: a row with no sidecar entry never expires.
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if sl := snap[EnvKey(slot, "GITHUB_TOKEN")]; sl.Expired || !sl.Expires.IsZero() || sl.Live != "live_a" {
		t.Fatalf("%+v", sl)
	}

	future := time.Now().Add(time.Hour)
	if err := st.SetExpiry(slot, future); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.Snapshot()
	if sl := snap[EnvKey(slot, "GITHUB_TOKEN")]; sl.Expired || sl.Live != "live_a" {
		t.Fatalf("future deadline touched the slot: %+v", sl)
	}
	if fi, err := os.Stat(st.ExpiresPath()); err != nil || fi.Mode().Perm() != 0640 {
		t.Fatal(fi, err)
	}

	past := time.Now().Add(-time.Hour)
	if err := st.SetExpiry(slot, past); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.Snapshot()
	if sl := snap[EnvKey(slot, "GITHUB_TOKEN")]; sl.Live != "" || !sl.Expired {
		t.Fatalf("%+v", sl)
	}
	if sl := snap[EnvKey(other, "GITHUB_TOKEN")]; sl.Live != "live_b" || sl.Expired {
		t.Fatalf("unrelated slot affected: %+v", sl)
	}

	// Only the clock crosses the deadline. No file changes in between.
	// The cache of Snapshot must not freeze the pre-expiry answer. The
	// deadline is stored as whole unix seconds. Thus the margin here must
	// clear a full second, not only the moment tested.
	if err := st.SetExpiry(other, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if snap, _ = st.Snapshot(); snap[EnvKey(other, "GITHUB_TOKEN")].Expired {
		t.Fatal("expired before its deadline")
	}
	time.Sleep(2500 * time.Millisecond)
	snap, _ = st.Snapshot()
	if sl := snap[EnvKey(other, "GITHUB_TOKEN")]; sl.Live != "" || !sl.Expired {
		t.Fatalf("clock-only expiry not observed: %+v", sl)
	}
	if err := st.ClearExpiry(other); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.Snapshot()
	if sl := snap[EnvKey(other, "GITHUB_TOKEN")]; sl.Live != "live_b" || sl.Expired {
		t.Fatalf("clear did not restore the slot: %+v", sl)
	}

	rows, err := st.ListSlots()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Slot != slot {
			continue
		}
		found = true
		if row.Expires == "" {
			t.Fatal("expiry not reported")
		}
		for _, k := range row.Keys {
			if k.State != "expired" {
				t.Fatalf("%+v", k)
			}
		}
	}
	if !found {
		t.Fatal("slot missing from list")
	}

	// A delete of the slot leaves no stale line in either sidecar.
	if _, err := st.DeleteSlot(slot); err != nil {
		t.Fatal(err)
	}
	if m, _ := st.Expires(); len(m) != 0 {
		t.Fatal(m)
	}
}

// A refresh that captures a new oat/ort must not move the deadline of a
// slot. The two are in different files, and Harvest only writes secrets.env.
func TestHarvestDoesNotTouchExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	body := EnvKey(slot, "CLAUDE_OAT") + "=oat_a\n" + EnvKey(slot, "CLAUDE_ORT") + "=ort_a\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	deadline := time.Now().Add(time.Hour)
	if err := st.SetExpiry(slot, deadline); err != nil {
		t.Fatal(err)
	}
	err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
		for i, sl := range cur {
			if sl.Kind == "CLAUDE_OAT" {
				cur[i].Live = "oat_b"
			}
			if sl.Kind == "CLAUDE_ORT" {
				cur[i].Live = "ort_b"
			}
		}
		return cur, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := st.Expires()
	if err != nil {
		t.Fatal(err)
	}
	if m[slot] != deadline.Unix() {
		t.Fatalf("harvest moved the deadline: %+v", m)
	}
	snap, _ := st.Snapshot()
	if sl := snap[EnvKey(slot, "CLAUDE_OAT")]; sl.Live != "oat_b" || sl.Expired {
		t.Fatalf("%+v", sl)
	}
}
