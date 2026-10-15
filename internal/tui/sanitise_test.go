package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPutNeverWritesTerminalControls(t *testing.T) {
	b := newBuffer(40, 1)
	b.put(0, 0, "a\u009b2Jb\u009dc‮d⁦e‎f\tg\x1bh i", plain)
	got := strings.TrimRight(stripANSI(string(b.frame())), " ")
	if want := "a?2Jb?c?d?e?f g h?i"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	b = newBuffer(10, 1)
	b.put(0, 0, "│ → ▸", plain)
	if got := strings.TrimRight(stripANSI(string(b.frame())), " "); got != "│ → ▸" {
		t.Fatalf("the TUI's own glyphs were touched: %q", got)
	}
}

// A device chooses the names that it queries, and the device detail shows
// its top names. A C1 CSI or a bidi override in a name shows as '?', and
// never goes to the terminal.
func TestDeviceDetailDrawsHostileNamesAsQuestionMarks(t *testing.T) {
	c, _ := testConfig(t)
	body := fmt.Sprintf(`{"clients":{
"house/10.78.0.101":{"segment":"house","ip":"10.78.0.101","mac":"aa:bb:cc:dd:ee:02","name":"phone","last_seen":"2026-01-01T00:00:00Z","queries":42,
  "names":{%q:30,%q:12},"dests":{}}},"events":[]}`, "a\u009b2Jb.example", "‮gnp.example")
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(140, 24).Type(keys(netHouse, secDevices)+"j").Press(KeyEnter))
	raw := f.Frames[len(f.Frames)-1]
	if strings.ContainsAny(raw, "\u009b‮") {
		t.Fatalf("a control rune reached the terminal: %q", raw)
	}
	last := f.Last()
	if !strings.Contains(last, "a?2Jb.example") || !strings.Contains(last, "?gnp.example") {
		t.Fatalf("hostile names not drawn as '?':\n%s", last)
	}
}
