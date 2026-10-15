package tailer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func drainInto(t *testing.T, tl *Tail, seen *[]string) {
	t.Helper()
	tl.Handler = func() func(string) {
		return func(line string) { *seen = append(*seen, line) }
	}
}

// logrotate renames the file and the writer creates a new one. The new
// file is usually as large as the data already read, or larger. Thus a
// size check alone cannot see the rotation, and the code skips the first
// records of the new file.
func TestDrainAfterRotation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off}
	drainInto(t, tl, &seen)
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("first pass read %q", seen)
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte("{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	want := []string{"{\"n\":1}\n", "{\"n\":2}\n", "{\"n\":3}\n", "{\"n\":4}\n", "{\"n\":5}\n"}
	if strings.Join(seen, "") != strings.Join(want, "") {
		t.Fatalf("got %q, want %q", seen, want)
	}
}

// A rotation between two runs of the sidecar has no held descriptor to
// use. Thus the offset file must tell the inode in which it counts
// bytes.
func TestDrainAfterRotationBetweenRuns(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var first []string
	one := &Tail{Path: log, OffsetPath: off}
	drainInto(t, one, &first)
	if err := one.Drain(false); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte("{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var second []string
	two := &Tail{Path: log, OffsetPath: off}
	drainInto(t, two, &second)
	if err := two.Drain(false); err != nil {
		t.Fatal(err)
	}
	want := "{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n"
	if strings.Join(second, "") != want {
		t.Fatalf("got %q, want %q", second, want)
	}
}

// A writer in the middle of an append leaves a record without its newline.
// If the code gives that prefix to a JSON parser and then checkpoints past
// it, the record is lost permanently.
func TestDrainLeavesPartialRecord(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n{\"n\":2"), 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off}
	drainInto(t, tl, &seen)
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "{\"n\":1}\n" {
		t.Fatalf("got %q, want only the complete record", seen)
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("}\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[1] != "{\"n\":2}\n" {
		t.Fatalf("got %q, want the record once it was whole", seen)
	}
}

// The agent writes most of the data in these logs. Thus a line with no
// newline is an unbounded allocation from a hostile author.
func TestDrainBoundsLineLength(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	off := filepath.Join(dir, "off")
	huge := strings.Repeat("A", 4<<20)
	if err := os.WriteFile(log, []byte(huge+"\n{\"n\":1}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	tl := &Tail{Path: log, OffsetPath: off}
	drainInto(t, tl, &seen)
	if err := tl.Drain(false); err != nil {
		t.Fatal(err)
	}
	for _, l := range seen {
		if len(l) > 1<<20 {
			t.Fatalf("handler got a %d byte line", len(l))
		}
	}
	if len(seen) != 1 || seen[0] != "{\"n\":1}\n" {
		t.Fatalf("got %d lines %.40q, want the short record only", len(seen), seen)
	}
}

// Watch holds one descriptor for the life of the process. A rotation
// under it makes pf alert watch of the operator quiet permanently.
func TestWatchFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	if err := os.WriteFile(log, nil, 0644); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	idle := make(chan struct{}, 1)
	tl := &Tail{Path: log, ShowPath: log, OffsetPath: filepath.Join(dir, "off"), Poll: 5 * time.Millisecond, Stdout: &out}
	tl.idle = func() {
		select {
		case idle <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Watch(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	append := func(s string) {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	// until waits for Watch to catch up with cond true. It uses the
	// signal of Watch, not a guessed sleep.
	until := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case <-idle:
				if cond() {
					return
				}
			case <-deadline:
				t.Fatalf("%s: %q", what, out.String())
			}
		}
	}
	until("watch never caught up", func() bool { return true })
	append("before\n")
	until("watch missed the line before the rotation", func() bool { return strings.Contains(out.String(), "before") })
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	append("after\n")
	until("watch stopped at the rotation", func() bool { return strings.Contains(out.String(), "after") })
}
