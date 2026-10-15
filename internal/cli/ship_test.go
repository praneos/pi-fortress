package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
// (seen on the Pi, 2026-09-27). Confirm refuses immediately.
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
	if code := runShipConfirm([]string{"-pending-file", pending, "-log", logPath}, nil, &errb); code == 0 || !strings.Contains(errb.String(), "holds") {
		t.Fatalf("confirm under a held lock: code %d, stderr %q", code, errb.String())
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
