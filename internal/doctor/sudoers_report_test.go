package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parser skips alias definitions and include directives on purpose.
// So it cannot see a rule that grants ALL through an alias, or a rule in
// a file reached by an include. The report still said "no
// passwordless sudo for ALL" as a flat fact.
func TestSudoRungIsInconclusiveAfterSkippingAnAlias(t *testing.T) {
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "sudoers"),
		[]byte("Cmnd_Alias EVERY = ALL\npi ALL=(ALL) NOPASSWD: EVERY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok := SudoRung(SudoersFiles(etc))
	if !ok {
		t.Fatal("no sudo rung")
	}
	if r.Status == OK {
		t.Fatalf("a parse that skipped an alias reported a clean box as fact: %q", r.Detail)
	}
	if !strings.Contains(r.Detail, "alias") {
		t.Fatalf("the report does not say what was skipped: %q", r.Detail)
	}
}

func TestSudoRungIsInconclusiveAfterSkippingAnInclude(t *testing.T) {
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "sudoers"),
		[]byte("%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok := SudoRung(SudoersFiles(etc))
	if !ok {
		t.Fatal("no sudo rung")
	}
	if r.Status == OK {
		t.Fatalf("a parse that skipped an include reported a clean box as fact: %q", r.Detail)
	}
	if !strings.Contains(r.Detail, "include") {
		t.Fatalf("the report does not say what was skipped: %q", r.Detail)
	}
}

// A sudoers.d that nobody can list is a directory full of rules that nobody
// checked. The read error was discarded, and the answer came back clean.
func TestSudoRungIsInconclusiveWhenSudoersDCannotBeListed(t *testing.T) {
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "sudoers"), []byte("%sudo ALL=(ALL:ALL) ALL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(etc, "sudoers.d")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "010_nopasswd"), []byte("pi ALL=(ALL) NOPASSWD: ALL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Root lists a mode-0 directory in any case, so it cannot stage this.
	if os.Geteuid() == 0 {
		t.Skip("root lists a mode-0 directory regardless")
	}
	if err := os.Chmod(d, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d, 0o755) })

	r, ok := SudoRung(SudoersFiles(etc))
	if !ok {
		t.Fatal("no sudo rung")
	}
	if r.Status == OK {
		t.Fatalf("a directory that could not be listed reported a clean box as fact: %q", r.Detail)
	}
	if !strings.Contains(r.Detail, "sudoers.d") {
		t.Fatalf("the report does not name what could not be read: %q", r.Detail)
	}
}

// A file that the parser understood from start to end still gets the plain answer.
func TestSudoRungStaysGreenOnAFullyParsedFile(t *testing.T) {
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "sudoers"),
		[]byte("Defaults env_reset\n%sudo ALL=(ALL:ALL) ALL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok := SudoRung(SudoersFiles(etc))
	if !ok || r.Status != OK {
		t.Fatalf("%+v ok=%v", r, ok)
	}
}
