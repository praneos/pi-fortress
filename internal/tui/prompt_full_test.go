package tui

import (
	"strings"
	"testing"
)

// A prompt that is full refuses each next key. The prompt line must say so.
// Before, the keys after the cap went nowhere and the line did not change.
// Thus a pasted value that was too long was saved in cut form, and the
// operator did not know.
func TestFullPromptSaysItTakesNoMoreInput(t *testing.T) {
	c, _ := testConfig(t)
	open := func() *Fake { return NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a") }
	f := run(t, c, open().Type(strings.Repeat("x", promptCap-1)))
	if strings.Contains(f.Last(), "[full]") {
		t.Fatalf("a prompt below the cap says it is full:\n%s", f.Last())
	}
	f = run(t, c, open().Type(strings.Repeat("x", promptCap+7)))
	last := f.Last()
	if !strings.Contains(last, "[full]") {
		t.Fatalf("a full prompt does not say that it refuses input:\n%s", last)
	}
	if lines := strings.Split(last, "\n"); !strings.Contains(lines[len(lines)-1], "add to") {
		t.Fatalf("the mark pushed the label off the prompt line:\n%s", last)
	}
}
