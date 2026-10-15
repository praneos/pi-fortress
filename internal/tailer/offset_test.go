package tailer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The code writes the offset again only when it moved, as one fixed-width
// record on top of the old one. A new Tail reads it back.
func TestOffsetWrittenOnlyWhenItMoves(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off}
	drainInto(t, tl, &seen)
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(off)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != offsetWidth+1 || !strings.HasPrefix(string(raw), "8 ") {
		t.Fatalf("offset record %q", raw)
	}
	if err := os.WriteFile(off, []byte("sentinel"), 0644); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := tl.Drain(false); err != nil {
			t.Fatal(err)
		}
	}
	if raw, _ := os.ReadFile(off); string(raw) != "sentinel" {
		t.Fatalf("a pass that moved nothing rewrote the offset: %q", raw)
	}
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(off); len(raw) != offsetWidth+1 || !strings.HasPrefix(string(raw), "16 ") {
		t.Fatalf("offset record %q", raw)
	}
	var again []string
	fresh := &Tail{Path: log, OffsetPath: off}
	drainInto(t, fresh, &again)
	if err := fresh.Drain(true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 || again[0] != "{\"n\":3}\n" {
		t.Fatalf("a fresh tail resumed wrong: %q", again)
	}
}

// pf-sidecar owns its offset file, but not the root-owned directory of the
// file (vm/pi/apply.sh creates the file first). Thus the code must save the
// checkpoint and create nothing beside it.
func TestOffsetSavedWithoutWriteAccessToTheDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(state, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0755) })
	tl := &Tail{Path: log, OffsetPath: off}
	if err := tl.Drain(false); err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	if raw, _ := os.ReadFile(off); !strings.HasPrefix(string(raw), "8 ") {
		t.Fatalf("offset record %q", raw)
	}
}

// A record from a log row can have ESC, C1 or a bidi override. show
// prints the last record, to the terminal of the operator.
func TestShowNeverPrintsTerminalControls(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	if err := os.WriteFile(log, []byte("{\"host\":\"a\u009b2J‮b\x1b]0;x\x07\"}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	tl := &Tail{ShowPath: log, Stdout: &out}
	tl.Show()
	if got, want := out.String(), "{\"host\":\"a?2J?b?]0;x?\"}\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
