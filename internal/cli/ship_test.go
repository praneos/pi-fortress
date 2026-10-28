package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/ship"
)

// A ship replaces /usr/local/sbin/pf as one of the first steps of
// apply. When that release is defective, the installer swaps the old
// tree back and applies again. It uses the same path, which then holds
// the new binary. Thus the broken pf drives the rollback of the broken
// pf. A restore of the tree does not restore the executable that ran
// before. The tree carries its own binary. That binary belongs to the
// generation that is live at that time.
func TestApplyPFPrefersTheBinaryOfTheLiveTree(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "opt", "pi-fortress")
	fallback := filepath.Join(dir, "usr", "local", "sbin", "pf")
	if err := os.MkdirAll(filepath.Dir(fallback), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fallback, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// No tree yet: the installed binary is all there is.
	if got := applyPF(tree, fallback); got != fallback {
		t.Fatalf("applyPF = %q, want the installed binary %q", got, fallback)
	}

	own := filepath.Join(tree, "vm", "pi", "pf")
	if err := os.MkdirAll(filepath.Dir(own), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := applyPF(tree, fallback); got != own {
		t.Fatalf("applyPF = %q, want the live tree's own binary %q", got, own)
	}

	// A tree that has the name but not the executable bit is not a binary
	// to give to apply. The installed binary is still the better guess.
	if err := os.Chmod(own, 0644); err != nil {
		t.Fatal(err)
	}
	if got := applyPF(tree, fallback); got != fallback {
		t.Fatalf("applyPF = %q on a non-executable tree binary, want %q", got, fallback)
	}
}

func TestRunShipConfirmNothingPending(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	var errb bytes.Buffer
	if code := runShipConfirm([]string{"-pending-file", pending, "-log", filepath.Join(dir, "ship.jsonl")}, nil, &errb); code != 0 {
		t.Fatalf("code %d, stderr %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "nothing pending") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestRunShipConfirmRemovesAnArmedPendingAndLogs(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	logPath := filepath.Join(dir, "ship.jsonl")
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100}); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if code := runShipConfirm([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code != 0 {
		t.Fatalf("code %d, stderr %s", code, errb.String())
	}
	if _, ok, _ := ship.ReadPending(pending); ok {
		t.Fatal("pending file still present")
	}
	if last, ok := jsonl.LastShip(logPath); !ok || last.Result != "confirm" || last.Version != 200 {
		t.Fatalf("log row %+v ok %v", last, ok)
	}
}

func TestRunShipDeadmanNothingPendingOrNotYetDue(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	logPath := filepath.Join(dir, "ship.jsonl")
	var errb bytes.Buffer
	// Nothing pending at all: a silent no-op.
	if code := runShipDeadman([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code != 0 || errb.Len() != 0 {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	// Pending, but not due: still a no-op. Nothing here must touch the
	// real apply lock, because Deadman returns before it takes it.
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if code := runShipDeadman([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code != 0 || errb.Len() != 0 {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	if _, ok, _ := ship.ReadPending(pending); !ok {
		t.Fatal("deadman removed a pending that was not due")
	}
}

// While another ship operation holds the lock, a due upgrade stays as
// it is. The timer runs again, and two reverts never race over .prev
// (seen on the Pi, 2026-09-27). Confirm with -wait 0 refuses
// immediately.
func TestShipDeadmanAndConfirmWaitForTheShipLock(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	logPath := filepath.Join(dir, "ship.jsonl")
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	held, err := admin.TryLock(filepath.Join(dir, "ship.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	var errb bytes.Buffer
	if code := runShipDeadman([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code != 0 || errb.Len() != 0 {
		t.Fatalf("deadman under a held lock: code %d, stderr %q", code, errb.String())
	}
	if _, ok, _ := ship.ReadPending(pending); !ok {
		t.Fatal("deadman acted on the pending file while the lock was held")
	}
	if code := runShipConfirm([]string{"-pending-file", pending, "-log", logPath, "-wait", "0"}, nil, &errb); code == 0 || !strings.Contains(errb.String(), "holds") {
		t.Fatalf("confirm under a held lock: code %d, stderr %q", code, errb.String())
	}
}

// The confirm line and the confirm row carry the sha of the confirmed
// version. The pending file has no sha. It comes from the ok row of the
// install (seen empty on the Pi, 2026-10-29).
func TestRunShipConfirmPrintsTheSHAOfTheInstall(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	logPath := filepath.Join(dir, "ship.jsonl")
	if err := jsonl.AppendShip(logPath, jsonl.Ship{Result: "ok", Version: 200, SHA: "abc1234"}); err != nil {
		t.Fatal(err)
	}
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if code := runShipConfirm([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code != 0 {
		t.Fatalf("code %d, stderr %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "pf ship confirm: version 200 sha=abc1234 confirmed") {
		t.Fatalf("stderr = %q, want the sha of version 200", errb.String())
	}
	if last, ok := jsonl.LastShip(logPath); !ok || last.Result != "confirm" || last.SHA != "abc1234" {
		t.Fatalf("log row %+v ok %v, want a confirm row with sha abc1234", last, ok)
	}
}

// signalWriter collects what pf writes. It closes waiting at the first
// line that says that pf waits for the ship lock.
type signalWriter struct {
	bytes.Buffer
	waiting chan struct{}
	once    sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("waiting for the ship install")) {
		w.once.Do(func() { close(w.waiting) })
	}
	return w.Buffer.Write(p)
}

// make pi-ship returns after the upload, while the install still holds
// the ship lock (seen on the Pi, 2026-10-29). pf ship confirm waits for
// the holder. Then it confirms only the version that the holder left
// pending, and only before its deadline. A fake holder takes the lock,
// waits until confirm says that it waits, changes the state as an
// install, a rollback or a dead-man run would, and releases the lock.
func TestRunShipConfirmWaitsForTheHolderOfTheShipLock(t *testing.T) {
	defer func(p time.Duration) { shipLockPoll = p }(shipLockPoll)
	shipLockPoll = 10 * time.Millisecond
	soon := time.Now().Add(10 * time.Minute)
	for _, c := range []struct {
		name string
		// before is the pending file when confirm starts. Zero: none.
		before ship.Pending
		// rows and after are what the holder logs and leaves pending.
		rows  []jsonl.Ship
		after ship.Pending
		// confirmed: confirm removes the pending and exits 0. Else
		// it exits 1, says want, and the pending file stays.
		confirmed bool
		want      string
	}{
		{
			name:      "install ok",
			rows:      []jsonl.Ship{{Result: "ok", Version: 300, SHA: "abc1234"}},
			after:     ship.Pending{Version: 300, PrevVersion: 200, Deadline: soon},
			confirmed: true,
			want:      "version 300 sha=abc1234 confirmed",
		},
		{
			name:      "a second install logged busy after the ok",
			rows:      []jsonl.Ship{{Result: "ok", Version: 300, SHA: "abc1234"}, {Result: "busy"}},
			after:     ship.Pending{Version: 300, PrevVersion: 200, Deadline: soon},
			confirmed: true,
			want:      "version 300 sha=abc1234 confirmed",
		},
		{
			name:      "the holder changed nothing",
			before:    ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			after:     ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			confirmed: true,
			want:      "version 200 sha=0ld0ld0 confirmed",
		},
		{
			name:   "install failed before its swap",
			before: ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			rows:   []jsonl.Ship{{Result: "bad_sig", Version: 0, Reason: "ssh-keygen -Y verify failed"}},
			after:  ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			want:   "bad_sig version=0 sha=: ssh-keygen -Y verify failed; ship.pending still names version 200",
		},
		{
			name:   "rollback failed and kept the pending",
			before: ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			rows:   []jsonl.Ship{{Result: "rollback_failed", Version: 200, Reason: "apply lock held"}},
			after:  ship.Pending{Version: 200, PrevVersion: 100, Deadline: soon},
			want:   "rollback_failed version=200",
		},
		{
			name:   "dead-man revert",
			before: ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(-time.Minute)},
			rows:   []jsonl.Ship{{Result: "deadman", Version: 100, Reason: "upgrade to 200 was never confirmed"}},
			want:   "deadman version=100 sha=: upgrade to 200 was never confirmed; nothing is pending",
		},
		{
			name:  "install ok, but the pending names another version",
			rows:  []jsonl.Ship{{Result: "ok", Version: 300, SHA: "abc1234"}},
			after: ship.Pending{Version: 250, PrevVersion: 200, Deadline: soon},
			want:  "ship.pending names version 250; nothing confirmed",
		},
		{
			name:  "install ok, but its deadline has passed",
			rows:  []jsonl.Ship{{Result: "ok", Version: 300, SHA: "abc1234"}},
			after: ship.Pending{Version: 300, PrevVersion: 200, Deadline: time.Now().Add(-time.Second)},
			want:  "dead-man deadline",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			pending := filepath.Join(dir, "ship.pending")
			logPath := filepath.Join(dir, "ship.jsonl")
			if err := jsonl.AppendShip(logPath, jsonl.Ship{Result: "ok", Version: 200, SHA: "0ld0ld0"}); err != nil {
				t.Fatal(err)
			}
			if c.before.Version != 0 {
				if err := ship.WritePending(pending, c.before); err != nil {
					t.Fatal(err)
				}
			}
			held, err := admin.TryLock(filepath.Join(dir, "ship.lock"))
			if err != nil {
				t.Fatal(err)
			}
			errb := &signalWriter{waiting: make(chan struct{})}
			go func() {
				defer held.Release()
				<-errb.waiting
				for _, r := range c.rows {
					if err := jsonl.AppendShip(logPath, r); err != nil {
						t.Error(err)
					}
				}
				if err := ship.RemovePending(pending); err != nil {
					t.Error(err)
				}
				if c.after.Version != 0 {
					if err := ship.WritePending(pending, c.after); err != nil {
						t.Error(err)
					}
				}
			}()
			code := runShipConfirm([]string{"-pending-file", pending, "-log", logPath, "-wait", "10s"}, nil, errb)
			out := errb.String()
			if !strings.Contains(out, "waiting for the ship install to finish") {
				t.Fatalf("no waiting line: %q", out)
			}
			if !strings.Contains(out, c.want) {
				t.Fatalf("stderr = %q, want %q", out, c.want)
			}
			_, armed, _ := ship.ReadPending(pending)
			if c.confirmed {
				if code != 0 || armed {
					t.Fatalf("code %d, pending still armed %v, stderr %q", code, armed, out)
				}
				return
			}
			if code == 0 {
				t.Fatalf("code 0, want a refusal; stderr %q", out)
			}
			if armed != (c.after.Version != 0) {
				t.Fatalf("pending armed = %v after a refusal, want it as the holder left it", armed)
			}
			if last, _ := jsonl.LastShip(logPath); last.Result == "confirm" {
				t.Fatalf("a refusal logged a confirm row: %+v", last)
			}
		})
	}
}

// A holder that does not release the lock in the wait bound: confirm
// stops with a clear error and changes nothing.
func TestRunShipConfirmStopsAtTheWaitBound(t *testing.T) {
	defer func(p time.Duration) { shipLockPoll = p }(shipLockPoll)
	shipLockPoll = 10 * time.Millisecond
	dir := t.TempDir()
	pending := filepath.Join(dir, "ship.pending")
	if err := ship.WritePending(pending, ship.Pending{Version: 200, PrevVersion: 100, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	held, err := admin.TryLock(filepath.Join(dir, "ship.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	var errb bytes.Buffer
	start := time.Now()
	code := runShipConfirm([]string{"-pending-file", pending, "-log", filepath.Join(dir, "ship.jsonl"), "-wait", "100ms"}, nil, &errb)
	if code == 0 || !strings.Contains(errb.String(), "still held after 100ms; nothing confirmed") {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 5*time.Second {
		t.Fatalf("confirm returned after %s, want about the 100ms bound", d)
	}
	if _, ok, _ := ship.ReadPending(pending); !ok {
		t.Fatal("confirm removed the pending file after the wait bound")
	}
}

func TestRunShipLint(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.tar")
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "hello"), []byte("hi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := ship.Build(&buf, src, ship.BundleOptions{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if code := runShipLint([]string{good}, nil, &errb); code != 0 {
		t.Fatalf("code %d, stderr %s", code, errb.String())
	}

	if code := runShipLint(nil, nil, &errb); code != 2 {
		t.Fatalf("no file argument: code %d, stderr %q", code, errb.String())
	}
	if code := runShipLint([]string{filepath.Join(dir, "absent.tar")}, nil, &errb); code != 1 {
		t.Fatalf("missing file: code %d", code)
	}
}

// pf ship install gives -post-upgrade-settle to pf doctor --post-upgrade
// as --settle. With no flag, the window stays 90 s and the doctor
// command line has no --settle.
func TestShipInstallPostUpgradeSettleReachesDoctor(t *testing.T) {
	if postUpgradeSettle != 90*time.Second {
		t.Fatalf("default settle window = %v, want 90s", postUpgradeSettle)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "doctor --post-upgrade"},
		{[]string{"-post-upgrade-settle", "90s"}, "doctor --post-upgrade"},
		{[]string{"-post-upgrade-settle", "10s"}, "doctor --post-upgrade --settle 10s"},
	} {
		fs := newFlags("ship install", io.Discard)
		d := postUpgradeSettleFlag(fs)
		if err := fs.Parse(c.args); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(postUpgradeArgs(*d), " "); got != c.want {
			t.Errorf("flags %q: doctor args = %q, want %q", c.args, got, c.want)
		}
	}
}
