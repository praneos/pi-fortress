package ship

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPendingRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "ship.pending")
	if _, ok, err := ReadPending(p); ok || err != nil {
		t.Fatalf("ok=%v err=%v, want absent", ok, err)
	}
	want := Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(10 * time.Minute).UTC()}
	if err := WritePending(p, want); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
	got, ok, err := ReadPending(p)
	if err != nil || !ok || got.Version != want.Version || got.PrevVersion != want.PrevVersion || !got.Deadline.Equal(want.Deadline) {
		t.Fatalf("got %+v ok %v err %v, want %+v", got, ok, err, want)
	}
	if err := RemovePending(p); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadPending(p); ok {
		t.Fatal("still present after remove")
	}
	if err := RemovePending(p); err != nil {
		t.Fatalf("removing an already-absent pending: %v", err)
	}
}

func TestInstallArmsPendingOnSuccessAndConfirmDisarmsIt(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	if _, ok := r.in.Run(); !ok {
		t.Fatal("run did not process the upload")
	}
	p, ok, err := ReadPending(r.in.PendingPath)
	if err != nil || !ok {
		t.Fatalf("pending not armed: ok=%v err=%v", ok, err)
	}
	if p.Version != 100 || p.PrevVersion != 0 {
		t.Fatalf("pending %+v", p)
	}
	if p.Deadline.Before(time.Now()) {
		t.Fatalf("deadline already passed: %v", p.Deadline)
	}

	row, ok, err := r.in.Confirm()
	if err != nil || !ok || row.Result != "confirm" || row.Version != 100 {
		t.Fatalf("confirm: row=%+v ok=%v err=%v", row, ok, err)
	}
	// The pending file has no sha. The confirm row takes it from the ok
	// row of the install (seen empty on the Pi, 2026-10-29).
	if row.SHA != "deadbee" {
		t.Fatalf("confirm row sha = %q, want the sha of the install, deadbee", row.SHA)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); ok {
		t.Fatal("still armed after confirm")
	}
	if _, ok, err := r.in.Confirm(); ok || err != nil {
		t.Fatalf("confirm with nothing pending: ok=%v err=%v", ok, err)
	}
}

func TestInstallArmingAPendingReplacesAnEarlierOne(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.in.ReleasesDir = filepath.Join(r.root, "releases")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	if _, ok := r.in.Run(); !ok {
		t.Fatal("second run did not process the upload")
	}
	p, ok, err := ReadPending(r.in.PendingPath)
	if err != nil || !ok {
		t.Fatalf("pending not armed after second ship: ok=%v err=%v", ok, err)
	}
	if p.Version != 200 || p.PrevVersion != 100 {
		t.Fatalf("pending %+v, want version 200 from 100", p)
	}
}

func TestDeadmanNoopBeforeDeadlineOrWithNothingPending(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	if _, ok, err := r.in.Deadman(time.Now()); ok || err != nil {
		t.Fatalf("nothing pending: ok=%v err=%v", ok, err)
	}
	if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.in.Deadman(time.Now()); ok || err != nil {
		t.Fatalf("before deadline: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); !ok {
		t.Fatal("deadman removed a pending that was not due")
	}
}

func TestDeadmanRollsBackAnUnconfirmedUpgradePastItsDeadline(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "new apply\n" {
		t.Fatalf("live tree before deadman: %q", got)
	}
	if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	row, ok, err := r.in.Deadman(time.Now())
	if err != nil || !ok || row.Result != "deadman" || row.Version != 100 {
		t.Fatalf("deadman: row=%+v ok=%v err=%v", row, ok, err)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); ok {
		t.Fatal("pending still present after deadman ran")
	}
	if got := read(t, filepath.Join(r.in.VersionPath)); got != "100\n" {
		t.Fatalf("floor after deadman: %q", got)
	}
	if r.applies != 3 { // v100 install, v200 install, deadman's re-apply of v100
		t.Fatalf("applies = %d", r.applies)
	}
}

func lockHeld() (func(), error) { return nil, errors.New("apply lock held by the TUI") }

func TestDeadmanKeepsPendingWhenTheRollbackDidNotHappen(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	unlocked := r.in.Lock
	r.in.Lock = lockHeld
	row, ok, err := r.in.Deadman(time.Now())
	if err == nil || !ok || row.Result != "deadman_failed" {
		t.Fatalf("locked deadman: row=%+v ok=%v err=%v, want deadman_failed and an error", row, ok, err)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); !ok {
		t.Fatal("a rollback that never happened removed ship.pending; nothing would retry it")
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "new apply\n" {
		t.Fatalf("live tree changed under a held lock: %q", got)
	}

	r.in.Lock = unlocked
	row, ok, err = r.in.Deadman(time.Now())
	if err != nil || !ok || row.Result != "deadman" || row.Version != 100 {
		t.Fatalf("retry: row=%+v ok=%v err=%v", row, ok, err)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); ok {
		t.Fatal("pending still present after the retry rolled back")
	}
	if got := read(t, r.in.VersionPath); got != "100\n" {
		t.Fatalf("floor after retry: %q", got)
	}
}

func TestDeadmanClearsPendingWhenThereIsNoPreviousTree(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	if err := WritePending(r.in.PendingPath, Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	row, ok, err := r.in.Deadman(time.Now())
	if err != nil || !ok || row.Result != "deadman" || !strings.Contains(row.Reason, "no previous tree") {
		t.Fatalf("row=%+v ok=%v err=%v", row, ok, err)
	}
	if _, ok, _ := ReadPending(r.in.PendingPath); ok {
		t.Fatal("a pending no retry can act on should be cleared, not retried every minute")
	}
}

func TestUnreadablePendingRevertsAndConfirmClearsIt(t *testing.T) {
	for _, body := range []string{"", "{", "{}", `{"version":-1}`} {
		r := newRig(t, true)
		r.in.PendingPath = filepath.Join(r.root, "ship.pending")
		r.ship(100, r.key)
		r.in.Run()
		r.ship(200, r.key)
		r.in.Run()
		write(t, r.in.PendingPath, body)
		if _, ok, err := ReadPending(r.in.PendingPath); !ok || !errors.Is(err, ErrPendingUnreadable) {
			t.Fatalf("%q: ok=%v err=%v, want armed and unreadable", body, ok, err)
		}
		row, ok, err := r.in.Deadman(time.Now())
		if err != nil || !ok || row.Result != "deadman" || row.Version != 100 {
			t.Fatalf("%q: deadman row=%+v ok=%v err=%v, want a revert to 100", body, row, ok, err)
		}
		if _, ok, _ := ReadPending(r.in.PendingPath); ok {
			t.Fatalf("%q: still armed after the revert", body)
		}

		write(t, r.in.PendingPath, body)
		row, ok, err = r.in.Confirm()
		if err != nil || !ok || row.Result != "confirm" {
			t.Fatalf("%q: confirm row=%+v ok=%v err=%v", body, row, ok, err)
		}
		if _, ok, _ := ReadPending(r.in.PendingPath); ok {
			t.Fatalf("%q: confirm left the unreadable pending in place", body)
		}
	}
}

func TestPendingSurvivesASwapThatFailed(t *testing.T) {
	r := newRig(t, true)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	r.ship(100, r.key)
	r.in.Run()
	r.ship(200, r.key)
	r.in.Run()
	r.in.Lock = lockHeld
	r.ship(300, r.key)
	if row, _ := r.in.Run(); row.Result != "swap" {
		t.Fatalf("row %+v, want a swap refusal", row)
	}
	p, ok, err := ReadPending(r.in.PendingPath)
	if err != nil || !ok || p.Version != 200 || p.PrevVersion != 100 {
		t.Fatalf("pending after a failed swap: %+v ok=%v err=%v; .prev is untouched, so its pending must be too", p, ok, err)
	}
}

func TestDeadmanLogsAndAlertsOnceWhenNoVersionCanBeRead(t *testing.T) {
	r := newRig(t, false)
	r.in.PendingPath = filepath.Join(r.root, "ship.pending")
	write(t, r.in.PendingPath, "{")
	stamp := filepath.Join(r.in.Dir+".prev", stampName)
	write(t, stamp, "garbage\n")
	for i := range 3 {
		row, ok, err := r.in.Deadman(time.Now())
		if err == nil || !ok || row.Result != "deadman_failed" {
			t.Fatalf("run %d: row=%+v ok=%v err=%v, want deadman_failed and an error", i, row, ok, err)
		}
		if !strings.Contains(row.Reason, "ship.pending is unreadable") || !strings.Contains(row.Reason, `"garbage"`) {
			t.Fatalf("run %d: reason %q does not name both errors", i, row.Reason)
		}
		if _, ok, _ := ReadPending(r.in.PendingPath); !ok {
			t.Fatalf("run %d: ship.pending removed; nothing would retry", i)
		}
	}
	if n := strings.Count(read(t, r.in.Log), `"deadman_failed"`); n != 1 || len(r.alerts) != 1 {
		t.Fatalf("after 3 identical runs: %d rows, %d alerts, want 1 and 1", n, len(r.alerts))
	}

	write(t, stamp, "other\n")
	if _, _, err := r.in.Deadman(time.Now()); err == nil {
		t.Fatal("want an error")
	}
	if n := strings.Count(read(t, r.in.Log), `"deadman_failed"`); n != 2 || len(r.alerts) != 2 {
		t.Fatalf("after a new reason: %d rows, %d alerts, want 2 and 2", n, len(r.alerts))
	}
}
