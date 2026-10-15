package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// A store that cannot stage its replacement must stay exactly as it
// was. Before, the code took the alternative: truncate the live file
// and rewrite it. That changes one temp-file problem into the loss of
// all credentials on the box when the second write also fails.
func TestReplaceFileKeepsStoreWhenStagingFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	before := EnvKey(slot, "CLAUDE_OAT") + "=sk-ant-oat01-keepme\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	// A directory where nothing can be created. Staging now selects its own
	// unpredictable name. Thus, to refuse all of them, refuse the
	// directory. This is the trigger that the fallback took.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	if err := replaceFile(path, EnvKey(slot, "CLAUDE_OAT")+"=sk-ant-oat01-new\n"); err == nil {
		t.Fatal("replaceFile reported success after staging failed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("store unreadable after a failed staging: %v", err)
	}
	if string(got) != before {
		t.Fatalf("store was rewritten in place after staging failed:\n got %q\nwant %q", got, before)
	}
}

// Before, Snapshot did a stat of the pathname to decide the identity
// for the cache of the contents that it had just read. A rename between
// the two puts the contents of the old inode under the identity of the
// new file. The broker takes a snapshot for each request. Thus each
// later request then hits that cache and continues to spend the
// credential that the rename revoked.
func TestSnapshotDoesNotCacheOldInodeUnderNewName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	key := EnvKey(slot, "GITHUB_TOKEN")
	if err := os.WriteFile(path, []byte(key+"=ghp_revoked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(dir, "staged")
	if err := os.WriteFile(next, []byte(key+"=ghp_current\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fired := false
	testHookAfterLoad = func(stage string) {
		if fired || stage != "secrets" {
			return
		}
		fired = true
		if err := os.Rename(next, path); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookAfterLoad = nil })

	st := Open(path)
	if _, err := st.Snapshot(); err != nil {
		t.Fatal(err)
	}
	testHookAfterLoad = nil
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got := snap[key].Live; got != "ghp_current" {
		t.Fatalf("Live=%q want ghp_current: the revoked value is being served from a cache stamped with the replacing file's identity", got)
	}
}

// The same window on the quarantine sidecar. To disable a slot also
// replaces that file by rename. Thus a snapshot across the swap must not
// cache the pre-quarantine answer under the identity of the new sidecar.
func TestSnapshotDoesNotCacheOldSidecarUnderNewName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	slot := "a1b2c3d4e5f67890"
	key := EnvKey(slot, "GITHUB_TOKEN")
	if err := os.WriteFile(path, []byte(key+"=ghp_live\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st := Open(path)
	if err := os.WriteFile(st.DisabledPath(), nil, 0640); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(dir, "staged")
	if err := os.WriteFile(next, []byte(slot+" 1\n"), 0640); err != nil {
		t.Fatal(err)
	}
	fired := false
	testHookAfterLoad = func(stage string) {
		if fired || stage != "disabled" {
			return
		}
		fired = true
		if err := os.Rename(next, st.DisabledPath()); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookAfterLoad = nil })

	if _, err := st.Snapshot(); err != nil {
		t.Fatal(err)
	}
	testHookAfterLoad = nil
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !snap[key].Disabled {
		t.Fatalf("quarantined slot still serves %q from a stale cache", snap[key].Live)
	}
}
