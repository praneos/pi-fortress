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

// The BOOT post: each new boot, clean or not, names the host, the boot
// time and how the boot before ended. A boot that did not end clean adds
// the RESTART detail. The same boot, or a state with no boot ID, gives
// nothing.
func TestBootLine(t *testing.T) {
	booted := at(-60)
	clean := bootLine(pressureState{BootID: "boot-old", Clean: true, At: at(-120)}, "boot-new", "pi5", booted)
	if clean != "BOOT pi5: booted at 2026-01-02 02:59:00 UTC; the boot before ended clean at 2026-01-02 02:58:00 UTC." {
		t.Fatalf("clean reboot: %q", clean)
	}
	frozen := bootLine(pressureState{BootID: "boot-old", At: at(-3600), High: "memory", Snapshot: "MemAvailable 80 MiB"}, "boot-new", "pi5", booted)
	for _, want := range []string{
		"BOOT pi5: booted at 2026-01-02 02:59:00 UTC; the boot before ended not clean at 2026-01-02 02:00:00 UTC. ",
		"RESTART: the Pi started again without a clean shutdown", "MemAvailable 80 MiB", "Pressure was HIGH on memory then",
	} {
		if !strings.Contains(frozen, want) {
			t.Fatalf("unclean reboot lacks %q: %q", want, frozen)
		}
	}
	if !strings.HasPrefix(frozen, "BOOT ") {
		t.Fatalf("unclean reboot does not start with BOOT: %q", frozen)
	}
	// A state from before the At field: no time for the end.
	if got := bootLine(pressureState{BootID: "boot-old", Clean: true}, "boot-new", "pi5", booted); got != "BOOT pi5: booted at 2026-01-02 02:59:00 UTC; the boot before ended clean." {
		t.Fatalf("no end time: %q", got)
	}
	for name, c := range map[string]struct {
		prev pressureState
		boot string
	}{
		"same boot (a restart of the unit)": {pressureState{BootID: "boot-new", Clean: true}, "boot-new"},
		"same boot, not clean (a crash)":    {pressureState{BootID: "boot-new"}, "boot-new"},
		"no boot id":                        {pressureState{BootID: "boot-old"}, ""},
		"old file, no id":                   {pressureState{}, "boot-new"},
	} {
		if msg := bootLine(c.prev, c.boot, "pi5", booted); msg != "" {
			t.Errorf("%s: posted %q", name, msg)
		}
	}
	// The host is printable, and never empty.
	if h := (&Pressure{Host: "pi\x1b[2J5"}).host(); strings.ContainsRune(h, 0x1b) {
		t.Errorf("host kept an escape: %q", h)
	}
	if h := (&Pressure{Host: " "}).host(); h != "?" {
		t.Errorf("an empty host is %q, not ?", h)
	}
}

func runOnce(t *testing.T, root, state string) []string {
	t.Helper()
	now := at(0)
	p := testPressure()
	p.Root, p.StatePath, p.Host = root, state, "pi5"
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
	// A start of the unit in the same boot: no post.
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("a restart of the unit posted %q", msgs)
	}
	// A reboot with a clean stop before it: one BOOT post, with the boot
	// time from btime in /proc/stat.
	put(t, root, "proc/sys/kernel/random/boot_id", "boot-b\n")
	put(t, root, "proc/stat", testStat+"btime 1767322700\n")
	st, _ = readState(state)
	msgs := runOnce(t, root, state)
	want := "BOOT pi5: booted at 2026-01-02 02:58:20 UTC; the boot before ended clean at " + st.At.UTC().Format(stampUTC) + "."
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("clean reboot: %q, want %q", msgs, want)
	}
	// The Pi froze: the last write has no clean mark. The next boot posts
	// one time, with the RESTART detail, and its own stop is clean again.
	raw := `{"boot_id":"boot-b","clean":false,"at":"2026-01-02T02:59:30Z","high":"memory","snapshot":"memory full 40.0%/20.0%"}`
	if err := os.WriteFile(state, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	put(t, root, "proc/sys/kernel/random/boot_id", "boot-c\n")
	msgs = runOnce(t, root, state)
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "BOOT pi5: booted at ") || !strings.Contains(msgs[0], "ended not clean at 2026-01-02 02:59:30 UTC") ||
		!strings.Contains(msgs[0], "RESTART:") || !strings.Contains(msgs[0], "memory full 40.0%/20.0%") {
		t.Fatalf("after a freeze: %q", msgs)
	}
	if msgs := runOnce(t, root, state); len(msgs) != 0 {
		t.Fatalf("the boot posted again: %q", msgs)
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
