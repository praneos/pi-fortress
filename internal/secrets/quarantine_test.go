package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func slotID(n int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i := range out {
		out[i] = hex[(n+i)%16]
	}
	return string(out)
}

// Quarantine is a read of the whole sidecar, an edit, and a write of the
// whole sidecar. Nothing holds the file across the three steps. Two
// operators that revoke two slots (or a purge at the same time as a
// revocation) each write back the list that they read. The one that
// finishes second erases the entry of the other. The slot that it erases
// is served again. That is the exact opposite of the operator request.
func TestConcurrentQuarantineEditsAllSurvive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	var body strings.Builder
	const n = 8
	for i := 0; i < n; i++ {
		body.WriteString(EnvKey(slotID(i), "GITHUB_TOKEN") + "=ghp_value" + string(rune('a'+i)) + "\n")
	}
	if err := os.WriteFile(path, []byte(body.String()), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A separate Store for each goroutine: two pf processes that revoke
			// at the same time share only the file.
			errs[i] = Open(path).Disable(slotID(i))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Disable(%s): %v", slotID(i), err)
		}
	}
	off, err := Open(path).Disabled()
	if err != nil {
		t.Fatal(err)
	}
	var lost []string
	for i := 0; i < n; i++ {
		if _, ok := off[slotID(i)]; !ok {
			lost = append(lost, slotID(i))
		}
	}
	if len(lost) > 0 {
		t.Fatalf("%d of %d revocations were erased by a concurrent one: %v", len(lost), n, lost)
	}
}

// Both writers stage through a name that an attacker can guess and
// create first. The broker can write to the store directory. Thus a
// symlink at the staging name sends all credentials in the file to its
// target. The rename that follows then publishes whatever was there at
// the path of the store.
func TestStagingWillNotFollowASymlink(t *testing.T) {
	for _, c := range []struct {
		name  string
		file  string
		write func(s *Store) error
	}{
		{"secrets.env", "secrets.env", func(s *Store) error {
			return replaceFile(s.path, EnvKey(slotID(1), "GITHUB_TOKEN")+"=ghp_new\n")
		}},
		{"secrets.disabled", "secrets.disabled", func(s *Store) error {
			return s.writeDisabled(map[string]int64{slotID(1): 1700000000})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secrets.env")
			if err := os.WriteFile(path, []byte(EnvKey(slotID(1), "GITHUB_TOKEN")+"=ghp_old\n"), 0600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "stolen")
			if err := os.Symlink(target, filepath.Join(dir, c.file+".tmp")); err != nil {
				t.Fatal(err)
			}
			_ = c.write(Open(path))
			if raw, err := os.ReadFile(target); err == nil {
				t.Fatalf("the staging write followed a symlink out of the store directory: %q", raw)
			}
		})
	}
}

// All writers except HarvestHeld put the value on the line, and did not
// check that it survives a read back. A newline is the sharp case: the
// remainder becomes a separate line, and a line of the correct shape is
// another key in the store.
func TestMintRefusesAValueThatCannotSurviveTheFile(t *testing.T) {
	for _, bad := range []string{
		"ghp_x\n" + EnvKey(slotID(2), "CLAUDE_OAT") + "=sk-ant-oat01-injected",
		"ghp with a space",
		"ghp_\"quoted\"",
		"ghp_hash#comment",
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "secrets.env")
		s := Open(path)
		if _, err := s.MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": bad}); err == nil {
			t.Errorf("MintKinds accepted %q", bad)
		}
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "injected") {
			t.Fatalf("a newline in a value wrote a second key:\n%s", raw)
		}
	}
}

// Before, migration published the file two times: first without the
// legacy rows that it moves, then again with their slotted replacements.
// A failure between the two leaves the operator with neither copy of the
// credential. (A refusal of a value that cannot be written is one.)
func TestMigrateKeepsLegacyValuesWhenTheRewriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	const before = "GITHUB_TOKEN=ghp not a token\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	s := Open(path)
	if _, err := s.MigrateUnslotted(); err == nil {
		t.Fatal("migration of a value it cannot write reported success")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != before {
		t.Fatalf("a refused migration destroyed the legacy value:\n got %q\nwant %q", got, before)
	}
}

// The directory of the store belongs to the broker, and root runs pf
// enroll on the same names. A link at the name of the store must not
// pull a different file into the store. A link at the name of the lock
// must not make root create the file that it points at.
func TestStoreNamesAreNotFollowed(t *testing.T) {
	mint := func(s *Store) {
		_, _ = s.MigrateUnslotted()
		_, _ = s.MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "ghp_new"})
	}
	t.Run("store", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.env")
		other := filepath.Join(t.TempDir(), "other")
		if err := os.WriteFile(other, []byte("not-a-store-line\nGITHUB_TOKEN=ghp_unslotted\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, path); err != nil {
			t.Fatal(err)
		}
		mint(Open(path))
		if raw, err := readNoFollow(path); err == nil && strings.Contains(string(raw), "not-a-store-line") {
			t.Fatalf("the store took in the file its name linked to: %q", raw)
		}
	})
	t.Run("lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.env")
		target := filepath.Join(t.TempDir(), "made")
		if err := os.Symlink(target, path+".lock"); err != nil {
			t.Fatal(err)
		}
		mint(Open(path))
		if _, err := os.Lstat(target); err == nil {
			t.Fatal("opening the lock created the file its name linked to")
		}
	})
}
