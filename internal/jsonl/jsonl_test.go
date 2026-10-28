package jsonl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStripAndUnknown(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{
		StripPath:   filepath.Join(dir, "strip.jsonl"),
		UnknownPath: filepath.Join(dir, "unknown.jsonl"),
		Now:         func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	if err := w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Unknown(Unknown{Host: "example.com", Src: Src}); err != nil {
		t.Fatal(err)
	}
	s, err := os.ReadFile(w.StripPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s), `"rule":"github_classic"`) || !strings.Contains(string(s), "example.com") {
		t.Fatal(string(s))
	}
	u, err := os.ReadFile(w.UnknownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(u), `"host":"example.com"`) || !strings.Contains(string(u), `"src":"split"`) {
		t.Fatal(string(u))
	}
}

func TestStampNormalisesInjectedClockToUTC(t *testing.T) {
	east := time.FixedZone("east", 5*3600)
	dir := t.TempDir()
	w := &Writer{
		StripPath: filepath.Join(dir, "strip.jsonl"),
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, east) },
	}
	if err := w.Strip(Strip{Host: "example.com"}); err != nil {
		t.Fatal(err)
	}
	s, err := os.ReadFile(w.StripPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s), `"t":"2026-01-01T22:04:05Z"`) {
		t.Fatalf("stamp not UTC-normalised: %s", s)
	}
}

// pf ship confirm takes a mark before it waits for the ship lock. Then
// it reads only the rows that the holder logged. A log that logrotate
// replaced during the wait is shorter than the mark: all of its rows
// are new.
func TestShipsAfterAndFindShip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ship.jsonl")
	if got := ShipsAfter(path, ShipLogSize(path)); len(got) != 0 {
		t.Fatalf("no log: rows %+v", got)
	}
	if err := AppendShip(path, Ship{Result: "ok", Version: 100, SHA: "aaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	mark := ShipLogSize(path)
	if mark == 0 {
		t.Fatal("mark 0 after one row")
	}
	for _, r := range []Ship{{Result: "ok", Version: 200, SHA: "bbbbbbb"}, {Result: "busy"}} {
		if err := AppendShip(path, r); err != nil {
			t.Fatal(err)
		}
	}
	got := ShipsAfter(path, mark)
	if len(got) != 2 || got[0].Version != 200 || got[1].Result != "busy" {
		t.Fatalf("rows after the mark: %+v", got)
	}
	if r, ok := FindShip(path, func(r Ship) bool { return r.Result == "ok" && r.Version == 100 }); !ok || r.SHA != "aaaaaaa" {
		t.Fatalf("FindShip ok 100: %+v %v", r, ok)
	}
	if _, ok := FindShip(path, func(r Ship) bool { return r.Version == 300 }); ok {
		t.Fatal("FindShip found a version that is not in the log")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := AppendShip(path, Ship{Result: "deadman", Version: 100}); err != nil {
		t.Fatal(err)
	}
	if got := ShipsAfter(path, mark+1000); len(got) != 1 || got[0].Result != "deadman" {
		t.Fatalf("rows of a rotated log: %+v", got)
	}
}
