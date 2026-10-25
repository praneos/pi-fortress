package tui

import (
	"strings"
	"testing"
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
