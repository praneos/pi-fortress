package tui

import (
	"testing"
	"time"
)

// Run starts a goroutine that waits in ReadKey. Run returns at
// approximately six points (q, Ctrl-C, idle, EOF, an error) without a join
// of it. A terminal read does not end when the loop that wanted it is
// gone. Thus that goroutine, and its tty, lived longer than the TUI. The
// next action of the process shared stdin with a reader that nobody could
// stop.
func TestRunJoinsTheKeyReader(t *testing.T) {
	c, _ := testConfig(t)
	for _, tc := range []struct {
		name string
		keys func(*Fake) *Fake
		idle time.Duration
	}{
		{"q", func(f *Fake) *Fake { return f.Type("q") }, 0},
		{"ctrl-c", func(f *Fake) *Fake { return f.Press(KeyCtrlC) }, 0},
		{"idle", func(f *Fake) *Fake { return f }, time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFake(80, 24)
			// Hold is what a real tty does: the read blocks. It does not report
			// EOF because the script is empty.
			f.Hold = true
			tc.keys(f)
			a := New(c, f)
			a.Idle = tc.idle
			if err := a.Run(); err != nil {
				t.Fatal(err)
			}
			if n := f.InRead(); n != 0 {
				t.Fatalf("Run returned with %d goroutine(s) still blocked in ReadKey", n)
			}
			if f.Raw {
				t.Fatal("terminal not restored")
			}
		})
	}
}

// A terminal can enter raw mode again after a Restore, as the real one
// does. A second Run on the same terminal also joins its key reader.
func TestRunTwiceOnOneTerminal(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24)
	f.Hold = true
	for i := 0; i < 2; i++ {
		f.Type("q")
		if err := New(c, f).Run(); err != nil {
			t.Fatal(err)
		}
		if n := f.InRead(); n != 0 || f.Raw {
			t.Fatalf("run %d: %d reader(s) left, raw %v", i, n, f.Raw)
		}
	}
}
