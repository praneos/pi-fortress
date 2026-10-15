package tui

import (
	"strings"
	"testing"
	"time"
)

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
		})
	}
}
