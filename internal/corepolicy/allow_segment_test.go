package corepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// The set of a plain segment is only its own file, read the same way as
// allow.domains. It has no core table and no echo fixtures, for each value of lab.
func TestLoadAllowIsTheSegmentFileAlone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allow.desk.domains")
	body := "github.com\n# comment\n\n*.example.com\n"
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := LoadAllow(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"github.com", true},
		{"api.github.com", true},
		{"github.com.evil.example", false},
		{"a.example.com", false},
		{"example.com", false},
		{"x..github.com", false},
		{"", false},
		{OpenEcho, false},
		{CoreEcho, false},
	} {
		for _, lab := range []bool{false, true} {
			if got := f.Allowed(tc.name, lab); got != tc.want {
				t.Errorf("Allowed(%q, lab=%v) = %v, want %v", tc.name, lab, got, tc.want)
			}
		}
	}
	if n := f.Names(); len(n) != 1 || n[0] != "github.com" {
		t.Errorf("Names() = %v, want [github.com]: a *. line is not a usable name", n)
	}
}

func TestLoadAllowRefusesAMissingFile(t *testing.T) {
	if _, err := LoadAllow(filepath.Join(t.TempDir(), "allow.desk.domains")); err == nil {
		t.Fatal("a missing allow file loaded as an empty set")
	}
}

func TestLoadAllowEmptyFileHasNoNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow.desk.domains")
	if err := os.WriteFile(p, []byte("# nothing yet\n*.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := LoadAllow(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.Names(); len(n) != 0 {
		t.Fatalf("Names() = %v, want none", n)
	}
}
