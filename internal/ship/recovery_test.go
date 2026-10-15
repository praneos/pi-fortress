package ship

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The version floor refuses a replay of an older signed bundle. Before,
// it was written after the apply. Then a failure to write it left the new
// tree live and applied, with a floor that still named the old release.
// Thus the bundle that the box had just installed (or any other bundle
// above the stale floor) was accepted again. The floor must describe the
// tree that is live. Thus it is published with the tree, and the tree is
// undone when the floor cannot be published.
func TestInstallRollsBackWhenTheFloorCannotBePublished(t *testing.T) {
	r := newRig(t, true)
	// The floor is read before the swap and written after it. Inside that
	// window, a regular file replaces the directory of the floor. Then all
	// ways to create a file under it fail, for any uid, without a dependency
	// on the name that writeVersion stages through.
	vdir := filepath.Join(r.root, "floor")
	if err := os.Mkdir(vdir, 0755); err != nil {
		t.Fatal(err)
	}
	r.in.VersionPath = filepath.Join(vdir, "ship.version")
	testHookAfterExchange = func() {
		if err := os.RemoveAll(vdir); err != nil {
			t.Fatal(err)
		}
		write(t, vdir, "not a directory\n")
	}
	t.Cleanup(func() { testHookAfterExchange = nil })
	r.ship(100, r.key)
	row, ok := r.in.Run()
	testHookAfterExchange = nil
	if !ok || row.Result != "version_file" {
		t.Fatalf("row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "old apply\n" {
		t.Fatalf("the new tree is live with no floor naming it: live tree holds %q", got)
	}
	if _, err := os.Stat(r.in.Dir + ".prev"); err == nil {
		t.Fatal(".prev should have moved back to the live path")
	}
}

// When apply fails, the previous tree is restored. Thus the floor must
// come back with it. If it stays advanced, the release that actually
// runs can never be shipped again.
func TestFloorComesBackWithTheTree(t *testing.T) {
	r := newRig(t, true)
	write(t, r.in.VersionPath, "50\n")
	r.applyErr = []error{errors.New("exit status 1"), nil}
	r.ship(100, r.key)
	if row, _ := r.in.Run(); row.Result != "apply_failed" {
		t.Fatalf("row %+v", row)
	}
	if got := read(t, r.in.VersionPath); got != "50\n" {
		t.Fatalf("floor is %q after the tree went back to version 50", got)
	}
}

// exchange makes the new tree live. The rename that follows only parks
// the old tree out of the way. Before, the code returned the error of the
// rename. That left the new tree live and applied to nothing, with the
// old tree at Dir.new. The next upload removes Dir.new before anything
// has examined it. The old tree is the whole recovery story. Thus a
// failure here puts it back.
func TestSwapUndoesTheExchangeWhenTheOldTreeCannotBeParked(t *testing.T) {
	r := newRig(t, true)
	prev := r.in.Dir + ".prev"
	testHookAfterExchange = func() {
		// A non-empty directory where the old tree will be parked. rename
		// refuses it, and it appears only after swap has already cleared the
		// path for itself.
		write(t, filepath.Join(prev, "occupied"), "x\n")
	}
	t.Cleanup(func() { testHookAfterExchange = nil })
	r.ship(100, r.key)
	row, ok := r.in.Run()
	testHookAfterExchange = nil
	if !ok || row.Result != "swap" {
		t.Fatalf("row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "old apply\n" {
		t.Fatalf("a failed swap left the new tree live: %q", got)
	}
	if r.applies != 0 {
		t.Fatalf("applies %d after a refused swap", r.applies)
	}
}

// Two installers share Work, Dir.new and Dir.prev by name. swap takes
// the apply lock and releases it before apply. Thus it never covers the
// paths that a second run would use again, and the version read occurs
// fully outside it.
func TestInstallRefusesToRunBesideAnotherInstaller(t *testing.T) {
	r := newRig(t, true)
	held := 0
	r.in.SelfLock = func() (func(), error) {
		held++
		return nil, errors.New("another pf ship install is running")
	}
	r.ship(100, r.key)
	row, ok := r.in.Run()
	if !ok || row.Result != "busy" {
		t.Fatalf("row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	if held != 1 {
		t.Fatalf("SelfLock attempts %d", held)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "old apply\n" {
		t.Fatalf("a second installer swapped the tree anyway: %q", got)
	}
	if _, err := os.Stat(r.in.Work); err == nil {
		t.Fatal("a second installer reset the work directory the first one is using")
	}
}
