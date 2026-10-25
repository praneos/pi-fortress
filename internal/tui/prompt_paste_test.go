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

// The tty reader marks a key as pasted only between the paste brackets of
// the terminal. A typed Enter is a key, also when the tty brings it in one
// read with the keys before it: an arrow key and Enter, or "yes" and Enter
// on a slow link. The brackets themselves are not keys.
func TestReadMarksOnlyKeysInsideThePasteBrackets(t *testing.T) {
	for in, want := range map[string]string{
		"\r":                           "0",
		"\r\n":                         "00",
		"ab\r":                         "000",
		"yes\r":                        "0000",
		"\x1b[A\r":                     "00",
		"\x1b[200~ab\r\n\x1b[201~":     "1111",
		"\x1b[200~a\rb\x1b[201~\r":     "1110",
		"y\x1b[200~x.example\x1b[201~": "0111111111",
	} {
		stop := make(chan struct{})
		src := newByteSource(strings.NewReader(in), stop)
		got := ""
		for len(src.back) > 0 || len(got) < len(want) {
			var b byte
			if p, ok := src.pending(); ok {
				b = p
			} else {
				select {
				case b = <-src.ch:
				case <-time.After(time.Second):
					t.Fatalf("%q: a key was lost after %s", in, got)
				}
			}
			if k, ok := src.key(b); ok {
				got += map[bool]string{false: "0", true: "1"}[k.Paste]
			}
		}
		close(stop)
		if got != want {
			t.Fatalf("%q: paste marks %s, want %s", in, got, want)
		}
	}
}

// A paste longer than the prompt takes stops at the cap, and the prompt
// line says [full]. Thus a later Enter does not save the cut value without
// a sign on the screen.
func TestLongPasteShowsFull(t *testing.T) {
	c, _ := testConfig(t)
	path := filepath.Join(c.PolicyDir, "house.domains")
	f := run(t, c, NewFake(80, 24).Type(keys(netHouse, secFiltering)+"a").Paste(strings.Repeat("x", promptCap+40)+".example\n"))
	if got, _ := os.ReadFile(path); string(got) != "ads.example\n" {
		t.Fatalf("the line end of a long paste saved the value: %q", got)
	}
	if footer := footerOf(f); !strings.Contains(footer, "[full]") {
		t.Fatalf("a long paste does not show [full]: %q", footer)
	}
}
