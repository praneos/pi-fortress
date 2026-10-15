package ship

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
)

func TestRollbackDefaultSwapsPrevBackIn(t *testing.T) {
	r := newRig(t, true)
	r.in.ReleasesDir = filepath.Join(r.root, "releases")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	if got := read(t, r.in.VersionPath); got != "200\n" {
		t.Fatalf("floor before rollback: %q", got)
	}

	row, err := r.in.Rollback(RollbackOptions{})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if row.Result != "rollback" || row.Version != 100 {
		t.Fatalf("row %+v", row)
	}
	if got := read(t, r.in.VersionPath); got != "100\n" {
		t.Fatalf("floor after rollback: %q", got)
	}
	if r.applies != 3 {
		t.Fatalf("applies = %d, want 3 (v100, v200, rollback re-apply)", r.applies)
	}

	// A second rollback with nothing at .prev refuses, and does not
	// touch anything.
	if _, err := r.in.Rollback(RollbackOptions{}); err == nil {
		t.Fatal("rollback with no .prev should refuse")
	}
}

// craftRelease puts a hand-built manifest + bundle.tar(.sig) directly
// into releasesRoot/<ver>/. It bypasses Build, so the manifest can
// declare a StateMax lower than what Build (the constants of this
// binary) would write. There is no other way to get an old-looking
// bundle for the state-version guard to refuse.
func craftRelease(t *testing.T, r *rig, ver, stateMax int64) {
	t.Helper()
	m := Manifest{Version: ver, SHA: "old", StateMin: 1, StateMax: stateMax}
	body := "old build\n"
	m.Files = []File{{Path: "vm/pi/apply.sh", SHA256: sum(body), Size: int64(len(body))}}
	raw := mkTar(t, &m, ent{name: "vm/pi/apply.sh", typ: tar.TypeReg, body: body})
	dir := filepath.Join(r.in.ReleasesDir, strconv.FormatInt(ver, 10))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "bundle.tar"), string(raw))
	os.Remove(filepath.Join(dir, "bundle.tar.sig")) // ssh-keygen -Y sign prompts rather than overwrite
	run(t, r.in.Keygen, "-Y", "sign", "-f", r.key, "-n", Namespace, filepath.Join(dir, "bundle.tar"))
}

func TestRollbackRefusesBelowTheStateFloorUnlessForced(t *testing.T) {
	r := newRig(t, true)
	r.in.ReleasesDir = filepath.Join(r.root, "releases")
	r.in.StateVersionPath = filepath.Join(r.root, "state.version")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	// The live install declares StateMax=2 (the constant of this build), so
	// state.version is now 2. Overwrite releases/100 with a hand-built
	// manifest that declares StateMax=1, as a build from before
	// secrets.expires would.
	craftRelease(t, r, 100, 1)

	if _, err := r.in.Rollback(RollbackOptions{}); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("expected the state guard to refuse, got %v", err)
	}
	if got := read(t, r.in.VersionPath); got != "200\n" {
		t.Fatalf("a refused rollback must not have touched the floor: %q", got)
	}

	row, err := r.in.Rollback(RollbackOptions{Force: true})
	if err != nil {
		t.Fatalf("forced rollback: %v", err)
	}
	if row.Result != "rollback" {
		t.Fatalf("row %+v", row)
	}
}

func TestRollbackThatDidNotHappenFailsAndKeepsPending(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	r.in.Lock = lockHeld
	row, err := r.in.Rollback(RollbackOptions{})
	if err == nil {
		t.Fatalf("rollback under a held lock reported success: %+v", row)
	}
	if row.Result != "rollback_failed" || row.Version != 200 {
		t.Fatalf("row %+v, want rollback_failed at 200", row)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); !ok {
		t.Fatal("a rollback that did not happen disarmed the dead-man timer")
	}
	if got := read(t, r.in.VersionPath); got != "200\n" {
		t.Fatalf("floor moved: %q", got)
	}
}

func TestRollbackWhoseReapplyFailsIsAnError(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	r.applyErr = []error{errors.New("nft refused")}
	row, err := r.in.Rollback(RollbackOptions{})
	if err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("err = %v, want the unapplied tree reported", err)
	}
	if row.Result != "rollback" || row.Version != 100 {
		t.Fatalf("row %+v: the tree did go back", row)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); ok {
		t.Fatal("the tree is back, so the pending confirm is moot")
	}
}

func TestRollbackPrevWithStateRestoresTheRolledAwaySnapshotBeforeApplying(t *testing.T) {
	r := newRig(t, true)
	r.in.ReleasesDir = filepath.Join(r.root, "releases")
	r.in.EtcDir = filepath.Join(r.root, "etc")
	r.in.LibDir = filepath.Join(r.root, "lib")
	marker := filepath.Join(r.in.EtcDir, "marker")
	write(t, marker, "before-v100\n")
	r.ship(100, r.key)
	r.in.Run()
	write(t, marker, "under-v100\n")
	r.ship(200, r.key)
	r.in.Run()
	write(t, marker, "under-v200\n")

	var seen string
	r.in.Apply = func() error {
		seen = read(t, marker)
		return nil
	}
	if _, err := r.in.Rollback(RollbackOptions{WithState: true}); err != nil {
		t.Fatalf("rollback -with-state: %v", err)
	}
	if got := read(t, marker); got != "under-v100\n" {
		t.Fatalf("marker = %q, want the state v100 ran under (releases/200/state.tar)", got)
	}
	if seen != "under-v100\n" {
		t.Fatalf("apply saw %q; the state has to be back before the re-apply compiles from it", seen)
	}
}

func TestRollbackPrevWithStateRefusesASnapshotOfAnotherVersion(t *testing.T) {
	r := newRig(t, true)
	r.in.ReleasesDir = filepath.Join(r.root, "releases")
	r.in.EtcDir = filepath.Join(r.root, "etc")
	r.in.LibDir = filepath.Join(r.root, "lib")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	meta := filepath.Join(r.in.ReleasesDir, "200", releaseMetaName)
	write(t, meta, strings.Replace(read(t, meta), `"state_of":100`, `"state_of":50`, 1))

	if _, err := r.in.Rollback(RollbackOptions{WithState: true}); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v, want a refusal before anything moved", err)
	}
	if got := read(t, r.in.VersionPath); got != "200\n" {
		t.Fatalf("floor moved: %q", got)
	}
}

// editListsAfterUpgrade makes the post-upgrade list edits of the operator
// on the live tree: a revocation in house.domains (mode also tightened),
// a list fully deleted, a block added in a list that .prev never had, and
// one non-list file that a rollback must still take from .prev.
func editListsAfterUpgrade(t *testing.T, r *rig) {
	t.Helper()
	live := filepath.Join(r.in.Dir, "vm/policy")
	write(t, filepath.Join(live, "house.domains"), "revoked\n")
	if err := os.Chmod(filepath.Join(live, "house.domains"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.in.Dir+".prev", "vm/policy/allow.domains")); err != nil {
		t.Fatalf("rig: .prev should hold allow.domains for the deletion to mean anything: %v", err)
	}
	if err := os.Remove(filepath.Join(live, "allow.domains")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(live, "blacklist.domains"), "pi-fortress-block.test\n")
	write(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh"), "edited under 200\n")
}

func assertListsSurvived(t *testing.T, r *rig) {
	t.Helper()
	if v, err := readStamp(r.in.Dir); err != nil || v != 100 {
		t.Fatalf("live tree is version %d (%v), want 100", v, err)
	}
	house := filepath.Join(r.in.Dir, "vm/policy/house.domains")
	if got := read(t, house); got != "revoked\n" {
		t.Fatalf("house.domains = %q: the rollback undid the operator's revocation", got)
	}
	if st, err := os.Stat(house); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("house.domains mode: %v %v, want 0600 kept", st.Mode(), err)
	}
	if _, err := os.Lstat(filepath.Join(r.in.Dir, "vm/policy/allow.domains")); err == nil {
		t.Fatal("allow.domains was deleted after the upgrade and came back with the rollback")
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/policy/blacklist.domains")); got != "pi-fortress-block.test\n" {
		t.Fatalf("blacklist.domains = %q: a block added after the upgrade was lost", got)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "new apply\n" {
		t.Fatalf("apply.sh = %q: only the operator's lists ride across, the rest is .prev's", got)
	}
}

func TestRollbackKeepsTheOperatorsListEditsMadeAfterTheUpgrade(t *testing.T) {
	r := newRig(t, true)
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	editListsAfterUpgrade(t, r)
	if _, err := r.in.Rollback(RollbackOptions{}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	assertListsSurvived(t, r)
}

func TestDeadmanRevertKeepsTheOperatorsListEditsMadeAfterTheUpgrade(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	editListsAfterUpgrade(t, r)
	if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if row, ok, err := r.in.Deadman(time.Now()); err != nil || !ok || row.Result != "deadman" {
		t.Fatalf("deadman: row=%+v ok=%v err=%v", row, ok, err)
	}
	assertListsSurvived(t, r)
}

// The failed-apply restore inside pf ship install keeps the same rule:
// an edit that occurs while the apply of the new tree runs is not undone.
func TestInstallApplyFailureRestoreKeepsTheLiveLists(t *testing.T) {
	r := newRig(t, true)
	calls := 0
	r.in.Apply = func() error {
		calls++
		if calls == 2 {
			write(t, filepath.Join(r.in.Dir, "vm/policy/house.domains"), "edited during apply\n")
			return errors.New("exit status 1")
		}
		return nil
	}
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	if row, _ := r.in.Run(); row.Result != "apply_failed" || !strings.Contains(row.Reason, "re-applied") {
		t.Fatalf("row %+v", row)
	}
	if v, _ := readStamp(r.in.Dir); v != 100 {
		t.Fatalf("live tree is version %d, want 100 restored", v)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/policy/house.domains")); got != "edited during apply\n" {
		t.Fatalf("house.domains = %q", got)
	}
}

// A mirror that cannot be done safely stops the swap. A rollback with
// the older lists of .prev would silently allow again what the operator
// revoked. Nothing moves, the pending confirm stays armed, both callers
// return an error. After the obstacle is gone, the retry carries the edits across.
func TestRollbackThatCannotMirrorTheListsDoesNotSwap(t *testing.T) {
	for _, where := range []string{"prev", "live"} {
		for _, via := range []string{"rollback", "deadman"} {
			t.Run(where+"/"+via, func(t *testing.T) {
				r := newRig(t, true)
				r.in.PendingPath = filepath.Join(r.root, "ship.pending")
				r.ship(100, r.key)
				r.in.Run()
				r.ship(200, r.key)
				r.in.Run()
				victim := filepath.Join(r.root, "victim")
				write(t, victim, "victim\n")
				dir := r.in.Dir + ".prev"
				if where == "live" {
					dir = r.in.Dir
				}
				list := filepath.Join(dir, "vm/policy/house.domains")
				saved := read(t, list)
				os.Remove(list)
				if err := os.Symlink(victim, list); err != nil {
					t.Fatal(err)
				}
				if where == "prev" {
					write(t, filepath.Join(r.in.Dir, "vm/policy/house.domains"), "revoked\n")
				}
				if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
					t.Fatal(err)
				}

				var err error
				var result string
				if via == "rollback" {
					var row jsonl.Ship
					row, err = r.in.Rollback(RollbackOptions{})
					result = row.Result
				} else {
					var row jsonl.Ship
					row, _, err = r.in.Deadman(time.Now())
					result = row.Result
				}
				if err == nil || result != via+"_failed" {
					t.Fatalf("result %q err %v, want %s_failed and an error", result, err, via)
				}
				if v, _ := readStamp(r.in.Dir); v != 200 {
					t.Fatalf("live tree is version %d: the swap ran although the lists could not be mirrored", v)
				}
				if got := read(t, r.in.VersionPath); got != "200\n" {
					t.Fatalf("floor moved: %q", got)
				}
				if _, ok, _ := ReadPending(r.in.PendingPath); !ok {
					t.Fatal("pending removed by a rollback that did not happen")
				}
				if got := read(t, victim); got != "victim\n" {
					t.Fatalf("wrote through a symlink: victim = %q", got)
				}

				os.Remove(list)
				write(t, list, saved)
				if via == "rollback" {
					_, err = r.in.Rollback(RollbackOptions{})
				} else {
					_, _, err = r.in.Deadman(time.Now())
				}
				if err != nil {
					t.Fatalf("retry: %v", err)
				}
				if v, _ := readStamp(r.in.Dir); v != 100 {
					t.Fatalf("retry left version %d live", v)
				}
				want := "revoked\n"
				if where == "live" {
					want = saved
				}
				if got := read(t, filepath.Join(r.in.Dir, "vm/policy/house.domains")); got != want {
					t.Fatalf("after the retry house.domains = %q, want %q", got, want)
				}
			})
		}
	}
}
