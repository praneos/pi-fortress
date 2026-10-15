package tailer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Before, report returned early when Stderr was nil. All daemon callers
// leave it nil: pf alert run builds its Tail without one. Thus the error
// that tells that a line was never delivered was written nowhere. That
// error is the only reason that Deliver reports errors. This test replaces
// the process stderr and does not give a writer, because a given writer
// is the case that already worked.
func TestDrainErrorReachesStderrWithoutBeingGivenOne(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "in.jsonl")
	if err := os.WriteFile(log, []byte("{\"a\":1}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()

	tl := &Tail{
		Path:       log,
		OffsetPath: filepath.Join(dir, "off"),
		Deliver: func() func(string) error {
			return func(string) error { return errors.New("the sink refused it") }
		},
	}
	// The daemons use Once. It drains and reports. Drain alone only
	// returns.
	tl.Once()
	w.Close()
	os.Stderr = saved
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "the sink refused it") {
		t.Fatalf("the drain error was written nowhere: %q", out)
	}
}
