package corepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The set of a plain segment is only its own file, read the same way as
// allow.domains. It has no core table and no echo fixtures, for each value of lab.
// A "*.name" line is the line "name" (AllowEntry). A "*.*.name" line allows nothing.
func TestLoadAllowIsTheSegmentFileAlone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allow.desk.domains")
	body := "github.com\n# comment\n\n*.example.com\n*.*.other.example\n"
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
		{"a.example.com", true},
		{"example.com", true},
		{"evilexample.com", false},
		{"a.other.example", false},
		{"other.example", false},
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
	if n := f.Names(); len(n) != 2 || n[0] != "example.com" || n[1] != "github.com" {
		t.Errorf("Names() = %v, want [example.com github.com]: a *.*. line is not a usable name", n)
	}
}

func TestLoadAllowRefusesAMissingFile(t *testing.T) {
	if _, err := LoadAllow(filepath.Join(t.TempDir(), "allow.desk.domains")); err == nil {
		t.Fatal("a missing allow file loaded as an empty set")
	}
}

func TestLoadAllowEmptyFileHasNoNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow.desk.domains")
	if err := os.WriteFile(p, []byte("# nothing yet\n*.*.example.com\n*.com\n"), 0644); err != nil {
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

// An allow list line with an empty label or over the DNS length limits
// allows nothing. AllowEntry gives "" for it, so the set does not hold a
// key that no query can match.
func TestAllowEntryRefusesEmptyLabelAndLongNames(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 63)+".", 4) + "test"
	for _, tok := range []string{".example.com", "..example.com", "x..example.com", strings.Repeat("a", 64) + ".example.com", long, "*." + long} {
		if name, _, oneLabel := AllowEntry(tok); name != "" || oneLabel {
			t.Errorf("AllowEntry(%.20q) = %q, %v; want nothing", tok, name, oneLabel)
		}
		if AllowProblem(tok) == "" {
			t.Errorf("AllowProblem(%.20q) gives no reason", tok)
		}
	}
	for _, tok := range []string{"example.com", "*.example.com", "Example.COM.", "com", "münchen.de"} {
		if AllowProblem(tok) != "" {
			t.Errorf("AllowProblem(%q) = %q, want none", tok, AllowProblem(tok))
		}
	}
}
