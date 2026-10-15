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
