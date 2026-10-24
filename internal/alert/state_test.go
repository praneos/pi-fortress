package alert

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUncleanRestartNeedsNewBootAndNoCleanMark(t *testing.T) {
	prev := pressureState{BootID: "boot-old", At: at(0), High: "memory", Snapshot: "MemAvailable 80 MiB of 7.6 GiB (1.0%)"}
	msg := uncleanRestart(prev, "boot-new")
	for _, want := range []string{"RESTART: the Pi started again without a clean shutdown", "2026-01-02 03:00:00 UTC", "MemAvailable 80 MiB", "Pressure was HIGH on memory then"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message lacks %q: %s", want, msg)
		}
	}
	for name, c := range map[string]struct {
		prev pressureState
		boot string
	}{
		"clean shutdown":    {pressureState{BootID: "boot-old", Clean: true}, "boot-new"},
		"same boot (crash)": {pressureState{BootID: "boot-new"}, "boot-new"},
		"no boot id":        {pressureState{BootID: "boot-old"}, ""},
		"old file, no id":   {pressureState{}, "boot-new"},
	} {
		if msg := uncleanRestart(c.prev, c.boot); msg != "" {
			t.Errorf("%s: posted %q", name, msg)
		}
	}
}

func runOnce(t *testing.T, root, state string) []string {
	t.Helper()
	now := at(0)
	p := testPressure()
	p.Root, p.StatePath = root, state
	p.Now = func() time.Time { return now }
	p.Stderr = &bytes.Buffer{}
	w := &scriptWaiter{steps: make([]uint32, 20), clock: &now}
	p.newWaiter = func(context.Context, *procReader) waiter { return w }
	var log postLog
	p.Run(context.Background(), log.post)
	return log.msgs
}

func TestPressureStateFileAcrossBoots(t *testing.T) {
	root := fakeRoot(t, true)
	state := filepath.Join(t.TempDir(), "pressure.json")
	// The first start: no file, no post. A stop writes the clean mark.
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("first start posted %q", msgs)
	}
	st, ok := readState(state)
	if !ok || !st.Clean || st.BootID != "boot-a" || !strings.Contains(st.Snapshot, "MemAvailable") {
		t.Fatalf("after a stop: %+v", st)
	}
	// A reboot with a clean stop before it: no post.
	put(t, root, "proc/sys/kernel/random/boot_id", "boot-b\n")
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("clean reboot posted %q", msgs)
	}
	// The Pi froze: the last write has no clean mark. The next boot posts
	// one time, and its own stop is clean again.
	raw := `{"boot_id":"boot-b","clean":false,"at":"2026-01-02T03:00:00Z","high":"memory","snapshot":"memory full 40.0%/20.0%"}`
	if err := os.WriteFile(state, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	put(t, root, "proc/sys/kernel/random/boot_id", "boot-c\n")
	msgs := runOnce(t, root, state)
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "RESTART:") || !strings.Contains(msgs[0], "memory full 40.0%/20.0%") {
		t.Fatalf("after a freeze: %q", msgs)
	}
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("the restart posted again: %q", msgs)
	}
	// The unit stopped hard (SIGKILL, OOM) in the same boot: no post.
	raw = `{"boot_id":"boot-c","clean":false,"snapshot":"x"}`
	if err := os.WriteFile(state, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("a unit crash in the same boot posted %q", msgs)
	}
}

// TestStateWrittenWhileRunning: the loop writes the state each 30 s
// without the clean mark, so a hard stop leaves the last sample.
func TestStateWrittenWhileRunning(t *testing.T) {
	root := fakeRoot(t, true)
	state := filepath.Join(t.TempDir(), "pressure.json")
	now := at(0)
	p := testPressure()
	p.Root, p.StatePath = root, state
	p.Now = func() time.Time { return now }
	p.Stderr = &bytes.Buffer{}
	seen := make(chan pressureState, 1)
	w := &scriptWaiter{steps: make([]uint32, 20), clock: &now}
	w.hook = func(i int) {
		if i != 19 {
			return
		}
		// The writer goroutine is asynchronous. Wait for its file.
		for range 200 {
			if st, ok := readState(state); ok && !st.At.Before(at(30)) {
				seen <- st
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(seen)
	}
	p.newWaiter = func(context.Context, *procReader) waiter { return w }
	p.Run(context.Background(), func(string) {})
	st, ok := <-seen
	if !ok || st.Clean {
		t.Fatalf("the running state: %+v %v", st, ok)
	}
	if _, err := os.Stat(state + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the temp file stayed: %v", err)
	}
}

func TestStateWriterKeepsNewest(t *testing.T) {
	w := newStateWriter(filepath.Join(t.TempDir(), "s.json"), &bytes.Buffer{})
	// No run goroutine yet: put must not block, and the newest wins.
	w.put(pressureState{Snapshot: "old"})
	w.put(pressureState{Snapshot: "new"})
	if st := <-w.ch; st.Snapshot != "new" {
		t.Fatalf("queued %q", st.Snapshot)
	}
}
