package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// An operator often takes a backup immediately before a risky step. The
// file that the backup writes over is the last known good one. If the
// code opens the destination O_TRUNC before it reads one source, any
// failure leaves the operator with neither archive. Examples: a file
// that stat fails on, a full disk, an interrupted read.
func TestBackupOutKeepsThePreviousArchiveWhenTheNewOneFails(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	pol := filepath.Join(dir, "policy")
	for _, d := range []string{etc, pol} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "net.env"), []byte("INT_IF=eth0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A self-referential symlink is in the location of a policy list: stat
	// fails with ELOOP. Thus the enumeration of the sources fails after the
	// code has opened the destination.
	loop := filepath.Join(pol, "blacklist.domains")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pf-backup.tar.gz")
	const good = "the last good backup"
	if err := os.WriteFile(out, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runBackup([]string{"-etc", etc, "-policy", pol, "-out", out}, io.Discard, io.Discard); code == 0 {
		t.Fatal("pf backup reported success while it could not read its sources")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the previous archive is gone: %v", err)
	}
	if string(got) != good {
		t.Fatalf("a failed backup replaced the previous archive:\n got %q\nwant %q", got, good)
	}
}

// The success path must also end with the archive at the name that the
// operator gave. Only the operator can read it.
func TestBackupOutWritesTheArchiveItPromised(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	pol := filepath.Join(dir, "policy")
	for _, d := range []string{etc, pol} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "net.env"), []byte("INT_IF=eth0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pf-backup.tar.gz")
	if code := runBackup([]string{"-etc", etc, "-policy", pol, "-out", out}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("pf backup failed with %d", code)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() == 0 {
		t.Fatal("pf backup left an empty archive")
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("archive mode %v, want 0600", st.Mode().Perm())
	}
	if ents, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	} else if len(ents) != 3 {
		t.Fatalf("staging files left behind: %v", ents)
	}
}
