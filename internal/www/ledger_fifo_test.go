package www

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The claims directory is group-writable, so a compromised www can replace
// ledger.jsonl with a FIFO. An open of a FIFO blocks until the other end
// opens. This hung the TUI of root, pf claim and pf apply on a file that no
// process would ever open. Now each opener refuses it immediately.
func TestLedgerRefusesAFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(LedgerPath(dir), 0660); err != nil {
		t.Skip("no mkfifo here:", err)
	}
	within := func(name string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			fn()
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: blocked on a FIFO in the ledger's place", name)
		}
	}
	within("read", func() {
		if ev, _ := ReadLedgerCovering(dir); ev != nil {
			t.Errorf("read events from a FIFO: %+v", ev)
		}
	})
	within("append", func() {
		if err := AppendEvent(dir, Event{Ev: "issued", Code: "ABCDEF"}); err == nil {
			t.Error("append: a FIFO in the ledger's place was accepted")
		}
	})
	within("init", func() {
		if err := InitLedger(dir); err == nil {
			t.Error("init: a FIFO in the ledger's place was accepted")
		}
	})
	if fi, err := os.Lstat(LedgerPath(dir)); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the FIFO was replaced or removed: %v %v", fi, err)
	}
}

// With O_NONBLOCK on the open, an ordinary ledger must still work: create,
// append, and read back whole.
func TestLedgerStillAppendsAndReadsARegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := InitLedger(dir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"AAAAAA", "BBBBBB", "CCCCCC"} {
		if err := AppendEvent(dir, Event{Ev: "issued", Code: c}); err != nil {
			t.Fatal(err)
		}
	}
	ev := ReadLedger(dir)
	if len(ev) != 3 || ev[2].Code != "CCCCCC" {
		t.Fatalf("%+v", ev)
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger.jsonl")); err != nil {
		t.Fatal(err)
	}
}
