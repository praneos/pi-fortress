package secrets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A disabled or expired slot snapshots with its Live blank and its value
// in Stale. The index lists that value for the strip, and at no location
// where a placeholder or a live lookup could find it.
func TestRevokedSlotIsStripOnlyInTheIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	a, b := "a1a2a3a4a5a6a7a8", "b1b2b3b4b5b6b7b8"
	body := EnvKey(a, "GITHUB_TOKEN") + "=ghp_disabledvalue\n" + EnvKey(b, "GITHUB_TOKEN") + "=ghp_expiredvalue\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	if err := st.Disable(a); err != nil {
		t.Fatal(err)
	}
	if err := st.SetExpiry(b, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{a: "ghp_disabledvalue", b: "ghp_expiredvalue"} {
		sl := snap[EnvKey(id, "GITHUB_TOKEN")]
		if sl.Live != "" || sl.Stale != want || !(sl.Disabled || sl.Expired) {
			t.Fatalf("%s: %+v", id, sl)
		}
	}
	ix := NewIndex(snap)
	if len(ix.ByLive) != 0 {
		t.Fatalf("a revoked value is in the live lookup: %v", ix.ByLive)
	}
	if len(ix.Lives) != 2 {
		t.Fatalf("lives %+v", ix.Lives)
	}
	for _, sl := range ix.Lives {
		if !(sl.Disabled || sl.Expired) || sl.Live == "" {
			t.Fatalf("strip entry %+v", sl)
		}
		if d := ix.ByDummy[sl.Dummy]; d.Live != "" {
			t.Fatalf("the placeholder answers a value: %+v", d)
		}
	}
	if err := st.Restore(a); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.Snapshot()
	if sl := snap[EnvKey(a, "GITHUB_TOKEN")]; sl.Live != "ghp_disabledvalue" || sl.Stale != "" {
		t.Fatalf("re-enabled: %+v", sl)
	}
}
