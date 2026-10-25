package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasWalksParents(t *testing.T) {
	s := New("evil.example", "Tracker.Example.")
	for name, want := range map[string]bool{
		"evil.example":            true,
		"EVIL.example.":           true,
		"cdn.evil.example":        true,
		"a.b.c.evil.example":      true,
		"evil.example.com":        false,
		"notevil.example":         false,
		"example":                 false,
		"tracker.example":         true,
		"img.tracker.example":     true,
		"":                        false,
		"evil.example.evil.other": false,
	} {
		if got := s.Has(name); got != want {
			t.Errorf("Has(%q)=%v want %v", name, got, want)
		}
	}
}

func TestNilAndEmptyNeverMatch(t *testing.T) {
	var s *Set
	if s.Has("anything.example") || s.Len() != 0 {
		t.Fatal("nil set matched")
	}
	if New().Has("anything.example") {
		t.Fatal("empty set matched")
	}
}

func TestLoadDnsmasqFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked-domains.conf")
	raw := "# compiled\naddress=/evil.example/0.0.0.0\n\naddress=/Phish.Example./\nserver=9.9.9.9\nnot a line\naddress=/\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Fatalf("len=%d want 2", s.Len())
	}
	if !s.Has("evil.example") || !s.Has("www.phish.example") {
		t.Fatal("listed names not matched")
	}
	if s.Has("9.9.9.9") || s.Has("server") {
		t.Fatal("a non-address line became a name")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 || s.Has("evil.example") {
		t.Fatal("missing file did not yield an empty set")
	}
}

// A hand-written "*.name" line blocks what "name" blocks. A bare name
// already covers each subdomain, and Has never sees a "*" label.
func TestLoadWildcardLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked-domains.conf")
	raw := "address=/*.Wild.Example./0.0.0.0\naddress=/*./0.0.0.0\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("len=%d want 1", s.Len())
	}
	for name, want := range map[string]bool{
		"a.wild.example":   true,
		"b.a.wild.example": true,
		"wild.example":     true,
		"notwild.example":  false,
		"example":          false,
	} {
		if got := s.Has(name); got != want {
			t.Errorf("Has(%q)=%v want %v", name, got, want)
		}
	}
}
