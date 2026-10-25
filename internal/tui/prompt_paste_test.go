package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A pasted value that ends in a newline stays on the prompt line until
// the operator presses Enter. Before, the newline of the paste was Enter,
// and the value was saved before the operator could read it.
func TestPastedLineEndDoesNotSave(t *testing.T) {
	c, _ := testConfig(t)
	path := filepath.Join(c.PolicyDir, "house.domains")
	open := func() *Fake { return NewFake(80, 24).Type(keys(netHouse, secFiltering) + "a") }
	f := run(t, c, open().Paste("tracker.example\r\n"))
	if got, _ := os.ReadFile(path); string(got) != "ads.example\n" {
		t.Fatalf("the line end of a paste saved the value: %q", got)
	}
	if !strings.Contains(f.Last(), "add to house.domains: tracker.example_") {
		t.Fatalf("the pasted value is not on the prompt line:\n%s", f.Last())
	}
	run(t, c, open().Paste("tracker.example\n").Press(KeyEnter))
	if got, _ := os.ReadFile(path); string(got) != "ads.example\ntracker.example\n" {
		t.Fatalf("Enter after a paste did not save: %q", got)
	}
}

// The tty reader marks a line end as pasted only when it ends a read that
// also carried text. An Enter alone, or a line end inside the text, is a
// key.
func TestReadMarksOnlyTheLineEndOfAPaste(t *testing.T) {
	for in, want := range map[string]string{
		"\r":         "0",
		"\r\n":       "00",
		"ab\r":       "001",
		"ab\r\n":     "0011",
		"a\rb":       "000",
		"\x1b[A\r":   "0001",
		"tracker.ex": "0000000000",
	} {
		stop := make(chan struct{})
		src := newByteSource(strings.NewReader(in), stop)
		got := ""
		for range in {
			select {
			case b := <-src.ch:
				got += map[bool]string{false: "0", true: "1"}[b.paste]
			case <-time.After(time.Second):
				t.Fatalf("%q: a byte was lost", in)
			}
		}
		close(stop)
		if got != want {
			t.Fatalf("%q: paste marks %s, want %s", in, got, want)
		}
	}
}
