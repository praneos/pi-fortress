package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
)

// seedRestoreFixture builds a real archive and returns its path plus an
// empty destination tree to restore it into.
func seedRestoreFixture(t *testing.T) (archive, dstEtc, dstPol string) {
	t.Helper()
	dir := t.TempDir()
	etc := filepath.Join(dir, "src-etc")
	pol := filepath.Join(dir, "src-policy")
	dstEtc = filepath.Join(dir, "dst-etc")
	dstPol = filepath.Join(dir, "dst-policy")
	for _, d := range []string{etc, pol, dstEtc, dstPol} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "net.env"), []byte("INT_IF=eth0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	archive = filepath.Join(dir, "pf-backup.tar.gz")
	if code := runBackup([]string{"-etc", etc, "-policy", pol, "-out", archive}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("fixture backup failed with %d", code)
	}
	return archive, dstEtc, dstPol
}

// redirectApplyLock points the package at a lock file a test can create.
func redirectApplyLock(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run", "apply.lock")
	old := applyLockPath
	applyLockPath = p
	t.Cleanup(func() { applyLockPath = old })
	return p
}

// A restore is not one write. It is a plan from the live tree, and then
// a batch of renames into it. A pf apply between the two compiles a tree
// that is part archive and part the old tree. No operator chose that
// generation, and no backup contained it. Thus restore must take the
// same lock as apply, for the full window. It must refuse loudly when it
// cannot get the lock.
func TestRestoreRefusesWhileAnApplyHoldsTheLock(t *testing.T) {
	archive, dstEtc, dstPol := seedRestoreFixture(t)
	lockPath := redirectApplyLock(t)

	// Stand in for a pf apply that is already running.
	held, err := admin.TryLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	var out, errb bytes.Buffer
	code := runRestore([]string{"-in", archive, "-etc", dstEtc, "-policy", dstPol, "-apply"}, &out, &errb)
	if code != 75 {
		t.Fatalf("restore wrote through a held apply lock: code=%d want 75\nstdout=%q\nstderr=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "another apply is running") {
		t.Fatalf("stderr does not say why: %q", errb.String())
	}
	ents, err := os.ReadDir(dstEtc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("a refused restore still left files behind: %v", ents)
	}
}

// The other half: restore must release the lock. If not, the first
// restore on a box blocks each apply after it.
func TestRestoreReleasesTheApplyLock(t *testing.T) {
	archive, dstEtc, dstPol := seedRestoreFixture(t)
	lockPath := redirectApplyLock(t)

	var out, errb bytes.Buffer
	if code := runRestore([]string{"-in", archive, "-etc", dstEtc, "-policy", dstPol, "-apply"}, &out, &errb); code != 0 {
		t.Fatalf("restore failed with %d\nstdout=%q\nstderr=%q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(dstEtc, "net.env")); err != nil {
		t.Fatalf("restore reported success and wrote nothing: %v", err)
	}
	l, err := admin.TryLock(lockPath)
	if err != nil {
		t.Fatalf("restore kept the apply lock: %v", err)
	}
	l.Release()
}

// A dry run reads and writes nothing. Thus an apply that runs is not a
// reason to refuse it. pf restore stays usable as an inspection tool.
func TestRestoreDryRunDoesNotNeedTheApplyLock(t *testing.T) {
	archive, dstEtc, dstPol := seedRestoreFixture(t)
	lockPath := redirectApplyLock(t)

	held, err := admin.TryLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	var out, errb bytes.Buffer
	if code := runRestore([]string{"-in", archive, "-etc", dstEtc, "-policy", dstPol}, &out, &errb); code != 0 {
		t.Fatalf("dry run refused: code=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "nothing written") {
		t.Fatalf("dry run did not report a plan: %q", out.String())
	}
}
