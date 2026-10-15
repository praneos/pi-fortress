package tailer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// apply leaves an empty offset file that the sidecar owns. Run must still
// start at the end of the log. It must not replay it.
func TestDrainFromEndWithEmptyOffset(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "unknown.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"host\":\"old.example\"}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, nil, 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off, Handler: func() func(string) {
		return func(line string) { seen = append(seen, line) }
	}}
	if err := tl.Drain(true); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Fatalf("replayed %q", seen)
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"host\":\"new.example\"}\n")
	_ = f.Close()
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "{\"host\":\"new.example\"}\n" {
		t.Fatalf("got %q, want only the new line", seen)
	}
}

// TestDrainRetriesFailedLineAcrossPolls copies the real control flow of pf
// alert run: one Tail, and Drain again on the next tick. The descriptor is
// not closed and opened again between them (that occurs only across process
// restarts). A line that the sink rejects must come back on that next poll.
// It must not be skipped because readLine already consumed its bytes from
// the buffered reader before the sink saw it. That would leave the saved
// offset at the rejected line, while the live reader was already past it.
func TestDrainRetriesFailedLineAcrossPolls(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	l1, l2 := "{\"host\":\"one.example\"}\n", "{\"host\":\"two.example\"}\n"
	if err := os.WriteFile(log, []byte(l1+l2), 0644); err != nil {
		t.Fatal(err)
	}
	fail := true
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off, Deliver: func() func(string) error {
		return func(line string) error {
			if fail && line == l1 {
				fail = false
				return errors.New("undelivered")
			}
			seen = append(seen, line)
			return nil
		}
	}}
	if err := tl.Drain(false); err == nil {
		t.Fatal("Drain reported success though the sink rejected a line")
	}
	if len(seen) != 0 {
		t.Fatalf("delivered %q before the failed line was ever retried", seen)
	}
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != l1 || seen[1] != l2 {
		t.Fatalf("got %q, want the failed line retried before the next one", seen)
	}
}
