package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSnapshotAndHarvest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	if err := os.WriteFile(path, []byte(EnvKey(slot, "CLAUDE_OAT")+"=sk-ant-oat01-old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := snap[EnvKey(slot, "CLAUDE_OAT")]
	if got.Dummy != Placeholder(slot, "CLAUDE_OAT") || got.Live != "sk-ant-oat01-old" {
		t.Fatalf("%+v", got)
	}
	err = st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slot, Kind: "CLAUDE_OAT", Live: "sk-ant-oat01-new"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	snap, err = st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap[EnvKey(slot, "CLAUDE_OAT")].Live != "sk-ant-oat01-new" {
		t.Fatal(snap[EnvKey(slot, "CLAUDE_OAT")].Live)
	}
}

// A directory that the harvest cannot write gives a harvest that fails.
// It does not give a harvest that rewrites the live file in place as a
// fallback. The credential in hand is lost in both cases. The difference
// is whether the store with all other credentials survives the attempt.
func TestHarvestDirNotWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	before := EnvKey(slot, "CLAUDE_OAT") + "=old\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)
	st := Open(path)
	if err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slot, Kind: "CLAUDE_OAT", Live: "new"}}, nil
	}); err == nil {
		t.Fatal("harvest reported success with no way to stage the replacement")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatalf("store rewritten in place: %q", raw)
	}
}

func TestDisabledSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot, other := "a1b2c3d4e5f67890", "0f0e0d0c0b0a0908"
	body := EnvKey(slot, "GITHUB_TOKEN") + "=live_a\n" + EnvKey(other, "GITHUB_TOKEN") + "=live_b\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	if err := st.Disable("A1B2C3D4E5F67890"); err != nil {
		t.Fatal(err)
	}
	if err := st.Disable("nope"); err == nil {
		t.Fatal("bad slot id accepted")
	}
	snap, _ := st.Snapshot()
	if sl := snap[EnvKey(slot, "GITHUB_TOKEN")]; sl.Live != "" || !sl.Disabled {
		t.Fatalf("%+v", sl)
	}
	if sl := snap[EnvKey(other, "GITHUB_TOKEN")]; sl.Live != "live_b" || sl.Disabled {
		t.Fatalf("%+v", sl)
	}
	raw, _ := os.ReadFile(st.DisabledPath())
	if !strings.HasPrefix(string(raw), slot+" ") {
		t.Fatal(string(raw))
	}
	if fi, _ := os.Stat(st.DisabledPath()); fi.Mode().Perm() != 0640 {
		t.Fatal(fi.Mode())
	}
	// A hand edit of the sidecar takes effect without a change to secrets.env.
	time.Sleep(5 * time.Millisecond)
	if err := os.WriteFile(st.DisabledPath(), []byte(slot+" 1\n"+other+" 1\n"), 0640); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.Snapshot()
	if !snap[EnvKey(other, "GITHUB_TOKEN")].Disabled {
		t.Fatal("sidecar change not reloaded")
	}
	if err := st.Restore(other); err != nil {
		t.Fatal(err)
	}
	if snap, _ = st.Snapshot(); snap[EnvKey(other, "GITHUB_TOKEN")].Live != "live_b" {
		t.Fatal("restore failed")
	}
	purged, err := st.PurgeOlderThan(24 * time.Hour)
	if err != nil || len(purged) != 1 || purged[0] != slot {
		t.Fatal(purged, err)
	}
	snap, _ = st.Snapshot()
	if _, ok := snap[EnvKey(slot, "GITHUB_TOKEN")]; ok {
		t.Fatal("purged slot still in secrets.env")
	}
	if m, _ := st.Disabled(); len(m) != 0 {
		t.Fatal(m)
	}
}

func TestDeleteSlotLeavesNoQuarantineLineBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	slot, other := "a1b2c3d4e5f67890", "0f0e0d0c0b0a0908"
	body := EnvKey(slot, "GITHUB_TOKEN") + "=live_a\n" + EnvKey(other, "GITHUB_TOKEN") + "=live_b\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	for _, id := range []string{slot, other} {
		if err := st.Disable(id); err != nil {
			t.Fatal(err)
		}
	}
	if kinds, err := st.DeleteSlot(slot); err != nil || len(kinds) != 1 {
		t.Fatal(kinds, err)
	}
	m, err := st.Disabled()
	if err != nil {
		t.Fatal(err)
	}
	if _, held := m[slot]; held {
		t.Fatalf("deleted slot is still quarantined: %v", m)
	}
	if _, held := m[other]; !held {
		t.Fatalf("the other slot's quarantine went with it: %v", m)
	}
}

// The rewrite of a harvest reads the store again. When that read fails,
// the harvest fails. It does not take the store as empty and write it
// back with only the harvested row. A store with no file is empty.
func TestHarvestReadErrorKeepsStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot, other := "a1b2c3d4e5f67890", "b0b1b2b3b4b5b6b7"
	before := EnvKey(slot, "CLAUDE_OAT") + "=sk-ant-oat01-old\n" + EnvKey(other, "GITHUB_TOKEN") + "=ghp_other\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	testHookRead = func(string) error { return syscall.EIO }
	t.Cleanup(func() { testHookRead = nil })
	st := Open(path)
	if err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slot, Kind: "CLAUDE_OAT", Live: "sk-ant-oat01-new"}}, nil
	}); !errors.Is(err, syscall.EIO) {
		t.Fatalf("harvest error %v, want EIO", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatalf("store rewritten after a failed read: %q", raw)
	}
	testHookRead = nil

	fresh := Open(filepath.Join(dir, "new.env"))
	if err := fresh.writeUpdates(map[string]string{EnvKey(slot, "CLAUDE_OAT"): "sk-ant-oat01-new"}); err != nil {
		t.Fatalf("a store with no file: %v", err)
	}
}

// The store reads a slot with upper-case hex as the same slot. Thus a
// harvest replaces that row. It does not add a second row for the slot,
// and the old value does not stay in the file.
func TestHarvestReplacesUpperCaseSlotRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	other := EnvKey("b0b1b2b3b4b5b6b7", "GITHUB_TOKEN") + "=ghp_other"
	if err := os.WriteFile(path, []byte(strings.ToUpper(slot)+"_CLAUDE_OAT=sk-ant-oat01-old\n"+other+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	if err := st.Harvest(slot, func(cur []Slot) ([]Slot, error) {
		return []Slot{{ID: slot, Kind: "CLAUDE_OAT", Live: "sk-ant-oat01-new"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := EnvKey(slot, "CLAUDE_OAT") + "=sk-ant-oat01-new\n" + other + "\n"
	if string(raw) != want {
		t.Fatalf("store %q, want %q", raw, want)
	}
}
