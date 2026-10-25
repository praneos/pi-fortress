package tui

import (
	"strings"
	"testing"
	"time"
)

// The A confirm names the edits that it applies. A bare "run pf apply now"
// after a long session gets a y from habit, not from a review.
func TestApplyConfirmNamesTheSavedEdits(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a").Type("tracker.example").Press(KeyEnter).
		Type(settingsDown("AGENT_DNS")).Press(KeyEnter).Type("A")
	last := run(t, c, f).Last()
	lines := strings.Split(last, "\n")
	prompt := lines[len(lines)-1]
	for _, want := range []string{"2 edits:", "tracker.example", "AGENT_DNS=forward", "run pf apply now [y/N]"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the apply confirm does not show %q:\n%s", want, prompt)
		}
	}
}

// Many long edits do not push [y/N] off an 80-column line. The count stays
// whole, and the oldest edits go first.
func TestApplyConfirmStaysInside80Columns(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(80, 24).Type(keys(netHouse, secFiltering))
	for _, d := range []string{"first-long-name.example", "second-long-name.example", "third-long-name.example"} {
		f.Type("a").Type(d).Press(KeyEnter)
	}
	f.Type("A")
	last := run(t, c, f).Last()
	lines := strings.Split(last, "\n")
	prompt := strings.TrimRight(lines[len(lines)-1], " ")
	if !strings.HasSuffix(prompt, "[y/N]: _") || !strings.Contains(prompt, "3 edits") || !strings.Contains(prompt, "third-long-name.example") {
		t.Fatalf("the apply confirm lost its count, newest edit or [y/N]:\n%q", prompt)
	}
	if strings.Contains(prompt, "first-long-name") {
		t.Fatalf("the oldest edit stayed, the line cannot hold it:\n%q", prompt)
	}
}

// A clears the saved-changes marker only after the apply that it ran
// finished cleanly. Before, the code cleared it when the apply started.
// Then a failed apply left a footer that said nothing was waiting, but the
// edit never took effect.
func TestPendingClearedOnlyByASuccessfulApply(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  []string
		want string
	}{
		{"failed", []string{"/bin/sh", "-c", "echo apply broke; exit 1"}, applyLocal},
		{"succeeded", []string{"/bin/echo", "pf"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testConfig(t)
			c.PfCmd = tc.cmd
			f := NewFake(120, 30).Type(keys(netHouse, secFiltering) + "a").Type("tracker.example").Press(KeyEnter).Type("Ay")
			f.Hold = true
			a := New(c, f)
			a.Idle = 50 * time.Millisecond
			done := make(chan error, 1)
			go func() { done <- a.Run() }()
			waitRun(t, done, 5*time.Second)
			pane := strings.Join(a.pane, "\n")
			if !strings.Contains(pane, "$ pf apply --local") || strings.Contains(pane, "running") {
				t.Fatalf("the apply did not run to its end:\n%s", pane)
			}
			if a.pending != tc.want {
				t.Fatalf("pending %q after a %s apply, want %q:\n%s", a.pending, tc.name, tc.want, pane)
			}
			if (tc.want == "") != (len(a.edits) == 0) {
				t.Fatalf("edits %q after a %s apply, pending %q", a.edits, tc.name, a.pending)
			}
		})
	}
}
