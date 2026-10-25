package tui

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The edits that a running A apply takes are not "never applied". Thus
// the quit prompt during the apply does not count them. When the apply
// fails, they wait for an apply again, and the next quit names them.
func TestQuitDuringApplyCountsOnlyEditsTheApplyDidNotTake(t *testing.T) {
	save := keys(netHouse, secFiltering) + "a"
	t.Run("running", func(t *testing.T) {
		c, _ := testConfig(t)
		c.PfCmd = []string{"/bin/sh", "-c", "sleep 30"}
		f := NewFake(80, 24).Type(save).Type("x.example").Press(KeyEnter).Type("Ay")
		f.Hold = true
		a := New(c, f)
		done := make(chan error, 1)
		go func() { done <- a.Run() }()
		waitFooter(t, f, "running...")
		a.events <- event{key: Key{Kind: KeyCtrlC}}
		waitFooter(t, f, "an action still runs and quit stops it; quit anyway [y/N]")
		a.events <- event{key: Key{Kind: KeyRune, Rune: 'y'}}
		waitRun(t, done, 3*time.Second)
	})
	t.Run("failed", func(t *testing.T) {
		c, _ := testConfig(t)
		c.PfCmd = []string{"/bin/sh", "-c", "exit 3"}
		f := NewFake(80, 24).Type(save).Type("x.example").Press(KeyEnter).Type("Ay")
		f.Hold = true
		a := New(c, f)
		done := make(chan error, 1)
		go func() { done <- a.Run() }()
		waitFrame(t, f, "error: ")
		waitFooter(t, f, "A applies saved changes")
		a.events <- event{key: Key{Kind: KeyRune, Rune: 'q'}}
		a.events <- event{key: Key{Kind: KeyRune, Rune: 'q'}}
		waitFooter(t, f, "1 saved edit was never applied; quit anyway [y/N]")
		a.events <- event{key: Key{Kind: KeyRune, Rune: 'y'}}
		waitRun(t, done, 3*time.Second)
	})
}

// apply --local from Actions does not take an edit that needs the full
// apply. That edit still waits after it.
func TestLocalApplyKeepsAFullEdit(t *testing.T) {
	c, _ := testConfig(t)
	// System > Settings to System > Actions is three sections right; j is
	// apply --local.
	f := NewFake(80, 24).Type(settingsDown("AGENT_DNS")).Press(KeyEnter).
		Type("lllj").Press(KeyEnter)
	f.Hold = true
	a := New(c, f)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	waitFrame(t, f, "done")
	a.events <- event{key: Key{Kind: KeyRune, Rune: 'q'}}
	a.events <- event{key: Key{Kind: KeyRune, Rune: 'q'}}
	waitFooter(t, f, "1 saved edit was never applied; quit anyway [y/N]")
	a.events <- event{key: Key{Kind: KeyRune, Rune: 'y'}}
	waitRun(t, done, 3*time.Second)
}

// A key that is saved again is one edit. Its newest value replaces the old
// entry, so on, off and on again is one edit, not three. Each add or delete
// of a list item is its own edit.
func TestEditsKeepOneEntryPerKey(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering)+"a").Type("x.example").Press(KeyEnter).
		Press(KeyEnd).Type("dy").
		Type(settingsDown("AGENT_DNS")).Press(KeyEnter, KeyEnter, KeyEnter)
	a := New(c, f)
	if err := a.Run(); err != nil {
		t.Fatal(err)
	}
	want := []string{"added x.example", "deleted x.example", "AGENT_DNS=forward"}
	if strings.Join(a.edits, "|") != strings.Join(want, "|") {
		t.Fatalf("edits = %q, want %q", a.edits, want)
	}
}

// A save on a box that does not render is a save that the next apply
// refuses. Its message has the error attr. A warning that only names the
// cost of a save does not.
func TestRenderFailureWarningHasTheErrorAttr(t *testing.T) {
	c, path := segSettings(t)
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_EGRESS=bogus\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(160, 24).Type(settingsDown("AGENT_DNS", "desk")).Press(KeyEnter))
	if frame := f.Frames[len(f.Frames)-1]; !strings.Contains(f.Last(), "does not render") || !strings.Contains(frame, attrCodes[alarm]) {
		t.Fatalf("a save that the next apply refuses is not in the error attr:\n%q", lastLine(frame))
	}

	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, "ADMIN=yes\n"...), 0644); err != nil {
		t.Fatal(err)
	}
	f = run(t, c, NewFake(160, 24).Type(segmentDown("ADMIN")).Press(KeyEnter).Type("y"))
	if frame := f.Frames[len(f.Frames)-1]; !strings.Contains(f.Last(), "stops at the next apply") || strings.Contains(frame, attrCodes[alarm]) {
		t.Fatalf("a warning that is not a failure uses the error attr:\n%q", lastLine(frame))
	}
}
