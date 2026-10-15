package ship

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The floor is the replay defence: it is the only thing that refuses an
// older signed bundle. When a missing file read as floor 0, one unlink
// could remove the whole defence. Thus the code must tell a box that has
// taken a ship from a box that never has. The tree gives the signal. A
// provisioned tree that has never taken a ship carries no stamp. A tree
// that has taken one carries the version that it was installed as.
func TestFloorSurvivesTheVersionFileBeingUnlinked(t *testing.T) {
	r := newRig(t, true)
	r.ship(100, r.key)
	if row, ok := r.in.Run(); !ok || row.Result != "ok" {
		t.Fatalf("first ship: row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	if err := os.Remove(r.in.VersionPath); err != nil {
		t.Fatal(err)
	}
	r.ship(100, r.key)
	row, ok := r.in.Run()
	if !ok || row.Result != "rollback" {
		t.Fatalf("version 100 was accepted again after ship.version was unlinked: row %+v ok %v", row, ok)
	}
	// The run that refused it should have put the file back. Thus the next
	// run does not have to reconstruct the floor a second time.
	if got := read(t, r.in.VersionPath); got != "100\n" {
		t.Errorf("floor file not republished: %q", got)
	}
}

// A crash between the exchange that makes a tree live and the write that
// publishes its floor leaves the new tree running under the floor of the
// release that it replaced. park moves a stranded tree aside, but never
// compared the live tree with the floor. Thus that window stayed open
// forever: each bundle above the stale floor, the one just installed
// included, was accepted again. This is the state that such a crash
// leaves, reproduced directly. It does not prove that the writes reached the medium.
func TestStaleFloorFileIsReconciledFromTheLiveTree(t *testing.T) {
	r := newRig(t, true)
	write(t, r.in.VersionPath, "50\n")
	r.ship(100, r.key)
	if row, ok := r.in.Run(); !ok || row.Result != "ok" {
		t.Fatalf("first ship: row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	write(t, r.in.VersionPath, "50\n")
	r.ship(100, r.key)
	if row, ok := r.in.Run(); !ok || row.Result != "rollback" {
		t.Fatalf("version 100 was accepted again while the tree of version 100 was live: row %+v ok %v", row, ok)
	}
	if got := read(t, r.in.VersionPath); got != "100\n" {
		t.Errorf("stale floor not reconciled on disk: %q", got)
	}
}

// The other half of the same question. A Pi is provisioned by a copy of
// the repo to the live path. Thus the tree exists long before the first
// ship, and its existence alone cannot mean "has been shipped". A refusal
// of a first ship because the live path is populated would brick each new box.
func TestAProvisionedTreeWithNoFloorStillTakesItsFirstShip(t *testing.T) {
	r := newRig(t, true)
	if _, err := os.Lstat(r.in.VersionPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("rig starts with a floor file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(r.in.Dir, "vm/pi/apply.sh")); err != nil {
		t.Fatalf("rig starts with no provisioned tree: %v", err)
	}
	r.ship(100, r.key)
	if row, ok := r.in.Run(); !ok || row.Result != "ok" {
		t.Fatalf("first ship onto a provisioned tree was refused: row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
}

// The fixed p+".tmp" staging name of the floor is a name that an attacker
// knows before the write occurs. A symlink planted there aims the write. A
// regular file planted there is the staging file of a second writer. The
// repo selected os.CreateTemp plus O_EXCL plus rename for exactly this.
func TestWriteVersionDoesNotStageAtAPredictableName(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		p := filepath.Join(root, "ship.version")
		victim := filepath.Join(root, "victim")
		write(t, victim, "sacred\n")
		if err := os.Symlink(victim, p+".tmp"); err != nil {
			t.Fatal(err)
		}
		if err := writeVersion(p, 100); err != nil {
			t.Fatalf("a symlink planted at the predictable staging name refused the floor write: %v", err)
		}
		if got := read(t, p); got != "100\n" {
			t.Fatalf("floor = %q", got)
		}
		if got := read(t, victim); got != "sacred\n" {
			t.Fatalf("the floor write went through the planted symlink: victim holds %q", got)
		}
		if st, err := os.Lstat(p + ".tmp"); err != nil || st.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("the planted symlink was consumed by the write: %v", err)
		}
		if got := names(t, root); len(got) != 3 {
			t.Fatalf("staging left files behind: %v", got)
		}
	})
	t.Run("squatted file", func(t *testing.T) {
		root := t.TempDir()
		p := filepath.Join(root, "ship.version")
		squat := p + ".tmp"
		write(t, squat, "another writer\n")
		if err := writeVersion(p, 100); err != nil {
			t.Fatalf("a file at the predictable staging name refused the floor write: %v", err)
		}
		if got := read(t, p); got != "100\n" {
			t.Fatalf("floor = %q", got)
		}
		if got := read(t, squat); got != "another writer\n" {
			t.Fatalf("the floor write took over another writer's staging file: %q", got)
		}
		if got := names(t, root); len(got) != 2 {
			t.Fatalf("staging left files behind: %v", got)
		}
	})
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
