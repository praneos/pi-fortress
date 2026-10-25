package tui

import (
	"strings"
	"testing"
	"time"
)

// runApp runs the script on a new App and gives the App back, so that a test
// can read the state where the loop stopped.
func runApp(t *testing.T, f *Fake) *App {
	t.Helper()
	c, _ := testConfig(t)
	a := New(c, f)
	if err := a.Run(); err != nil {
		t.Fatal(err)
	}
	return a
}

// sawFrame tells if a frame on the way contained s.
func sawFrame(f *Fake, s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fr := range f.Frames {
		if strings.Contains(stripANSI(fr), s) {
			return true
		}
	}
	return false
}

// An edit is saved at once and does nothing until an apply. A quit that
// does not ask leaves the operator sure of a change that never took
// effect.
func TestQuitWithSavedEditsAsks(t *testing.T) {
	save := keys(netHouse, secFiltering) + "a"
	const ask = "1 saved edit was never applied; quit anyway [y/N]"
	for _, tc := range []struct {
		name   string
		f      *Fake
		quit   bool
		prompt bool
	}{
		{"q declined", NewFake(80, 24).Type(save).Type("x.example").Press(KeyEnter).Type("qqn"), false, true},
		{"q accepted", NewFake(80, 24).Type(save).Type("x.example").Press(KeyEnter).Type("qqy"), true, true},
		{"ctrl-c declined", NewFake(80, 24).Type(save).Type("x.example").Press(KeyEnter, KeyCtrlC).Type("n"), false, true},
		{"no edits", NewFake(80, 24).Type("q"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := runApp(t, tc.f)
			if a.quit != tc.quit {
				t.Fatalf("quit = %v, want %v:\n%s", a.quit, tc.quit, tc.f.Last())
			}
			if sawFrame(tc.f, ask) != tc.prompt {
				t.Fatalf("prompt shown = %v, want %v:\n%s", !tc.prompt, tc.prompt, tc.f.Last())
			}
		})
	}
}

// The count is plural when it must be.
func TestQuitNamesTheEditCount(t *testing.T) {
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering))
	f.Type("a").Type("x.example").Press(KeyEnter).Type("a").Type("y.example").Press(KeyEnter).Type("qq")
	runApp(t, f)
	if !sawFrame(f, "2 saved edits were never applied; quit anyway [y/N]") {
		t.Fatalf("no count in the quit prompt:\n%s", f.Last())
	}
}

// waitFrame waits until a frame on the way contains s.
func waitFrame(t *testing.T, f *Fake, s string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !sawFrame(f, s) {
		if time.Now().After(deadline) {
			t.Fatalf("no frame with %q:\n%s", s, f.Last())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Ctrl-C is the reflex for "stop this screen", not "stop the apply". While
// an action streams, Ctrl-C and q ask first, because the quit stops it.
func TestQuitDuringAnActionAsks(t *testing.T) {
	c, _ := testConfig(t)
	c.PfCmd = []string{"/bin/sh", "-c", "sleep 30"}
	f := NewFake(80, 24).Type(keys(netSystem, secActions)).Press(KeyEnter)
	f.Hold = true
	a := New(c, f)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	waitFrame(t, f, "running...")
	const ask = "an action still runs and quit stops it; quit anyway [y/N]"
	a.events <- event{key: Key{Kind: KeyCtrlC}}
	waitFrame(t, f, ask)
	a.events <- event{key: Key{Kind: KeyRune, Rune: 'n'}}
	waitFrame(t, f, "cancelled")
	select {
	case <-done:
		t.Fatal("the TUI quit after n")
	case <-time.After(50 * time.Millisecond):
	}
	for _, r := range "qqy" {
		a.events <- event{key: Key{Kind: KeyRune, Rune: r}}
	}
	waitRun(t, done, 3*time.Second)
	if !a.quit {
		t.Fatal("y did not quit")
	}
}

// A running action and saved edits give one prompt that names both, not
// two prompts in a row.
func TestQuitDuringAnActionWithEditsAsksOnce(t *testing.T) {
	c, _ := testConfig(t)
	c.PfCmd = []string{"/bin/sh", "-c", "sleep 30"}
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a").Type("x.example").Press(KeyEnter).
		Type(keys(netSystem, secActions)).Press(KeyEnter)
	f.Hold = true
	a := New(c, f)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	waitFrame(t, f, "running...")
	a.events <- event{key: Key{Kind: KeyCtrlC}}
	waitFrame(t, f, "an action still runs; 1 saved edit was never applied; quit anyway [y/N]")
	a.events <- event{key: Key{Kind: KeyRune, Rune: 'y'}}
	waitRun(t, done, 3*time.Second)
}

// The idle exit leaves the shell with no prompt to ask. Thus the line that
// it writes on the tty names the saved edits that no apply took. Without
// it, the operator who comes back is sure of a change that never took
// effect.
func TestIdleExitNamesUnappliedEdits(t *testing.T) {
	for _, tc := range []struct {
		name, save, want string
	}{
		{"none", "", ""},
		{"one", "x.example", "1 saved edit was never applied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testConfig(t)
			f := NewFake(80, 24)
			if tc.save != "" {
				f.Type(keys(netHouse, secFiltering) + "a").Type(tc.save).Press(KeyEnter)
			}
			f.Hold = true
			a := New(c, f)
			a.Idle = 50 * time.Millisecond
			if err := a.Run(); err != nil {
				t.Fatal(err)
			}
			last := f.Last()
			if !strings.Contains(last, idleNote) {
				t.Fatalf("no idle note: %q", last)
			}
			if got := strings.Contains(last, "never applied"); got != (tc.want != "") || !strings.Contains(last, tc.want) {
				t.Fatalf("idle exit line: %q, want %q", last, tc.want)
			}
		})
	}
	if got := unapplied(2); got != "2 saved edits were never applied" {
		t.Fatalf("plural: %q", got)
	}
}
