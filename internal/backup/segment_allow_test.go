package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// The allowlist of a paranoid desk is beside segments.d, and is operator
// state like the segment file. An archive without it restores a desk that
// apply refuses. Only allow.<segment>.domains for a segment that exists is
// carried, and only that shape is let back in.
func TestArchiveCarriesASegmentsAllowlist(t *testing.T) {
	c, etc, _ := box(t)
	if err := os.WriteFile(filepath.Join(etc, "allow.lab.domains"), []byte("github.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "allow.ghost.domains"), []byte("x.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, man := archive(t, c)
	got := map[string]bool{}
	for _, f := range man.Files {
		got[f.Name] = true
	}
	if !got["etc/allow.lab.domains"] {
		t.Error("the lab segment's allowlist is not in the archive")
	}
	if got["etc/allow.ghost.domains"] {
		t.Error("an allowlist for a segment that does not exist was carried")
	}
	for _, name := range []string{"etc/allow.lab.domains", "etc/allow.lab-2.domains"} {
		if !safeName(name) {
			t.Errorf("safeName rejected %q", name)
		}
	}
	for _, name := range []string{"etc/allow.domains", "etc/allow.Lab.domains", "etc/allow.../x.domains", "etc/allow.lab.domains.bak", "etc/segments.d/allow.lab.domains"} {
		if safeName(name) {
			t.Errorf("safeName accepted %q", name)
		}
	}
}
