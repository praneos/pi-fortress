package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/ship"
)

func TestRunRollbackRejectsANegativeTo(t *testing.T) {
	var errb bytes.Buffer
	if code := runRollback([]string{"-to", "-5"}, nil, &errb); code != 2 {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
}

// With no .prev tree, runRollback must refuse before it takes the real
// apply lock (admin.ApplyLockPath; a non-root test cannot hold it). The
// check of rollbackPrev runs first.
func TestRunRollbackWithNoPreviousTreeRefusesWithoutTouchingTheApplyLock(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "opt", "pi-fortress")
	var errb bytes.Buffer
	code := runRollback([]string{
		"-dir", tree,
		"-version-file", filepath.Join(dir, "ship.version"),
		"-log", filepath.Join(dir, "ship.jsonl"),
		"-pending-file", filepath.Join(dir, "ship.pending"),
		"-releases", filepath.Join(dir, "releases"),
	}, nil, &errb)
	if code != 1 {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
}

// A rollback that cannot take the apply lock changes nothing. The
// command must say so: a non-zero exit, no "now at version", and the
// armed confirm stays for pf ship deadman to retry.
func TestRunRollbackThatCannotLockExitsNonZeroAndKeepsPending(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the real apply lock would be taken and the real pf apply run")
	}
	if _, err := os.Stat(filepath.Dir(admin.ApplyLockPath)); err == nil {
		t.Skip(filepath.Dir(admin.ApplyLockPath) + " exists here; this test needs the apply lock to be unobtainable")
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "opt", "pi-fortress")
	for _, p := range []string{tree, tree + ".prev"} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(tree, ".pf-ship-version"), []byte("200\n"), 0644)
	os.WriteFile(filepath.Join(tree+".prev", ".pf-ship-version"), []byte("100\n"), 0644)
	pending := filepath.Join(dir, "ship.pending")
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	code := runRollback([]string{
		"-dir", tree,
		"-version-file", filepath.Join(dir, "ship.version"),
		"-log", filepath.Join(dir, "ship.jsonl"),
		"-pending-file", pending,
		"-releases", filepath.Join(dir, "releases"),
		"-state-version-file", filepath.Join(dir, "state.version"),
	}, nil, &errb)
	if code == 0 || strings.Contains(errb.String(), "now at version") {
		t.Fatalf("code %d, stderr %q: a rollback that did not happen reported success", code, errb.String())
	}
	if _, ok, _ := ship.ReadPending(pending); !ok {
		t.Fatal("pending removed by a rollback that did not happen")
	}
}

// -to is gone: rollback only goes back to .prev. Each spelling is
// refused as a usage error, before any lock, with the correct action.
func TestRunRollbackRefusesTo(t *testing.T) {
	for _, args := range [][]string{{"-to", "100"}, {"--to", "100"}, {"-to=100"}, {"--to=100"}, {"-with-state", "-to", "100"}} {
		var errb bytes.Buffer
		code := runRollback(args, nil, &errb)
		msg := errb.String()
		if code != 2 || !strings.Contains(msg, "goes back one version only") || !strings.Contains(msg, "pf upgrade -version") {
			t.Fatalf("%v: code %d, stderr %q", args, code, msg)
		}
	}
}
