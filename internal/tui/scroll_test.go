package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// contentOf is a screen row right of the menu column and its rule.
func contentOf(line string) string {
	r := []rune(line)
	if len(r) <= menuWidth {
		return ""
	}
	return string(r[menuWidth:])
}

// reverseRows returns the content rows drawn in reverse video. The cursor
// shows in reverse video. The title bar and the footer are also reverse,
// but they are not the cursor, so the function leaves them out.
func reverseRows(frame string) []string {
	lines := strings.Split(strings.TrimPrefix(frame, "\x1b[H"), "\r\n")
	var out []string
	for i, l := range lines {
		if i == 0 || i == len(lines)-1 {
			continue
		}
		if !strings.Contains(l, attrCodes[reverse]) {
			continue
		}
		// The menu column shares the line with the content pane. Thus the
		// screen name to the left of the cursor is not part of it.
		out = append(out, strings.TrimSpace(contentOf(stripANSI(l))))
	}
	return out
}

func filled(n int, sel bool) []row {
	out := make([]row, n)
	for i := range out {
		out[i] = row{text: fmt.Sprintf("row-%02d", i), sel: sel}
	}
	return out
}

// When the list is longer than the pane, the cursor index counts rows from
// the top of the list, but the highlight counts them from the top of the
// pane. The operator then deletes a reservation that is not the one that
// looks selected.
func TestHighlightFollowsTheSelectionAfterScrolling(t *testing.T) {
	f := NewFake(60, 12)
	a := &App{t: f, cur: view{netHouse, secDevices}, focus: true, rows: filled(30, true)}
	a.here().pos = 25
	a.draw()
	got := reverseRows(f.Frames[len(f.Frames)-1])
	if len(got) != 1 || got[0] != "row-25" {
		t.Fatalf("highlighted %q, want [row-25]", got)
	}
}

// Logs and Status show j/k in the footer but build nothing selectable.
// Thus the keys did nothing, and all text above the last screenful was
// unreachable.
func TestLogsScrollBackThroughOlderLines(t *testing.T) {
	f := NewFake(60, 12)
	a := &App{t: f, cur: view{netSystem, secAdminLog}, focus: true, rows: filled(40, false)}
	a.draw()
	if !strings.Contains(f.Last(), "row-39") {
		t.Fatalf("logs did not open at the newest line:\n%s", f.Last())
	}
	for range 12 {
		a.move(-1)
	}
	a.draw()
	last := f.Last()
	if !strings.Contains(last, "row-20") {
		t.Fatalf("j/k did not scroll back:\n%s", last)
	}
	for range 40 {
		a.move(1)
	}
	a.draw()
	if !strings.Contains(f.Last(), "row-39") {
		t.Fatalf("could not get back to the newest line:\n%s", f.Last())
	}
}

func TestStatusScrollsFromTheTop(t *testing.T) {
	f := NewFake(60, 12)
	a := &App{t: f, cur: view{netSystem, secHealth}, focus: true, rows: filled(40, false)}
	a.draw()
	if !strings.Contains(f.Last(), "row-00") {
		t.Fatalf("status did not open at the first line:\n%s", f.Last())
	}
	for range 12 {
		a.move(1)
	}
	a.draw()
	if !strings.Contains(f.Last(), "row-20") {
		t.Fatalf("j/k did not scroll down:\n%s", f.Last())
	}
}

// The status line said "not configured" in all box states. Thus a tunnel
// that went down looked exactly like one that was never set up.
func TestStatusReadsTheWireguardLink(t *testing.T) {
	c, _ := testConfig(t)
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_ADMIN_IP=\nWG_IF=wg-absent\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(100, 40).Type(keys(netSystem, secHealth)))
	last := f.Last()
	if !strings.Contains(last, "wg-absent") {
		t.Fatalf("status never names the configured link:\n%s", last)
	}
	if strings.Contains(last, "wireguard  not configured") {
		t.Fatalf("status still says not configured with WG_IF set:\n%s", last)
	}
}

// The operator types a passphrase one byte at a time. If the code widens
// each byte to a rune and encodes it again, each non-ASCII character
// becomes two. Then the passphrase of the operator never matches the one
// that sealed the store.
func TestParseKeyKeepsMultibyteRunes(t *testing.T) {
	for _, s := range []string{"é", "ß", "€", "🔑"} {
		in := []byte(s)
		i := 1
		k := parseKey(in[0], func(time.Duration) (byte, bool) {
			if i >= len(in) {
				return 0, false
			}
			b := in[i]
			i++
			return b, true
		}, nil)
		want := []rune(s)[0]
		if k.Kind != KeyRune || k.Rune != want {
			t.Fatalf("%q decoded to %v %q, want rune %q", s, k.Kind, k.Rune, want)
		}
	}
}

// Before, Backspace over a multibyte character cut one byte off it.
// This left a prompt buffer that was not valid UTF-8.
func TestPromptBackspaceRemovesAWholeRune(t *testing.T) {
	a := &App{}
	a.ask("passphrase", func(string) {})
	a.pr.buf = "né"
	a.promptKey(Key{Kind: KeyBackspace})
	if a.pr.buf != "n" {
		t.Fatalf("buf = %q, want %q", a.pr.buf, "n")
	}
}

// Action output is all that the subprocess prints. A run that emits
// megabytes without a newline made one string grow until the seat died.
// Also, the last line of a command that does not end in a newline never
// reached the pane.
func TestLineWriterIsBoundedAndFlushesTheTail(t *testing.T) {
	ch := make(chan event, 64)
	var lines []string
	drained := make(chan struct{})
	go func() {
		for e := range ch {
			lines = append(lines, e.line)
		}
		close(drained)
	}()
	w := &lineWriter{ch: ch}
	if _, err := w.Write([]byte(strings.Repeat("A", 3<<20))); err != nil {
		t.Fatal(err)
	}
	if len(w.buf) > 1<<16 {
		t.Fatalf("held %d bytes of a line that never ended", len(w.buf))
	}
	if _, err := w.Write([]byte("no trailing newline")); err != nil {
		t.Fatal(err)
	}
	w.flush()
	close(ch)
	<-drained
	if len(lines) == 0 {
		t.Fatal("nothing reached the pane")
	}
	if last := lines[len(lines)-1]; !strings.Contains(last, "no trailing newline") {
		t.Fatalf("the unterminated tail never reached the pane; last line %q", last)
	}
}
