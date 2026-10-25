package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pi-fortress/internal/ship"
)

// pf ship deadman, pf rollback and pf ship confirm build their Installer
// with shipInstallerFlags. It sets the Alert hook, so that each row other
// than ok or confirm posts to the alert webhook (docs/signed_ship.md).
func TestShipInstallerFlagsSetsAlertHook(t *testing.T) {
	for _, name := range []string{"ship deadman", "rollback", "ship confirm"} {
		in := shipInstallerFlags(newFlags(name, io.Discard), io.Discard)
		if in.Alert == nil {
			t.Errorf("pf %s: Installer.Alert is nil; its non-ok ship rows never reach the webhook", name)
		}
	}
}

// The deadman_failed and rollback_failed rows reach the Alert hook. The
// test replaces the hook from shipInstallerFlags with a recorder after
// the nil check, so no real webhook is read or posted to.
func TestDeadmanAndRollbackFailedRowsReachAlertHook(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "opt", "pi-fortress")
	for _, p := range []string{tree, tree + ".prev"} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for p, v := range map[string]string{tree: "200\n", tree + ".prev": "100\n"} {
		if err := os.WriteFile(filepath.Join(p, ".pf-ship-version"), []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	pending := filepath.Join(dir, "ship.pending")
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	fs := newFlags("ship deadman", io.Discard)
	in := shipInstallerFlags(fs, io.Discard)
	if err := fs.Parse([]string{
		"-dir", tree,
		"-version-file", filepath.Join(dir, "ship.version"),
		"-log", filepath.Join(dir, "ship.jsonl"),
		"-pending-file", pending,
		"-releases", filepath.Join(dir, "releases"),
	}); err != nil {
		t.Fatal(err)
	}
	if in.Alert == nil {
		t.Fatal("shipInstallerFlags left Installer.Alert nil")
	}
	var got []string
	in.Alert = func(msg string) { got = append(got, msg) }
	in.Lock = func() (func(), error) { return nil, errors.New("apply lock held") }
	in.StateVersionPath = filepath.Join(dir, "state.version")

	if row, _, _ := in.Deadman(time.Now()); row.Result != "deadman_failed" {
		t.Fatalf("deadman row %q, want deadman_failed", row.Result)
	}
	if row, _ := in.Rollback(ship.RollbackOptions{}); row.Result != "rollback_failed" {
		t.Fatalf("rollback row %q, want rollback_failed", row.Result)
	}
	if len(got) != 2 {
		t.Fatalf("alerts %q, want one for deadman_failed and one for rollback_failed", got)
	}
}
