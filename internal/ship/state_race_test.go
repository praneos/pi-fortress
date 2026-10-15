package ship

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withRestoreHook installs testHookRestore for one test.
func withRestoreHook(t *testing.T, h func(stage, path string)) {
	t.Helper()
	testHookRestore = h
	t.Cleanup(func() { testHookRestore = nil })
}

// noneUnder fails if anything other than the names in keep exists
// under dir: a restore that wrote outside its root left it there.
func noneUnder(t *testing.T, dir string, keep ...string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]bool{}
	for _, k := range keep {
		ok[k] = true
	}
	for _, e := range ents {
		if !ok[e.Name()] {
			t.Errorf("restore wrote %s outside its root", filepath.Join(dir, e.Name()))
		}
	}
}

// A daemon that can write a directory under libDir (pf-dns owns its own
// state there) swaps a component that the restore has just checked for a
// symlink, between the check and the write. The write must not follow
// it, if the link goes out of the root or points elsewhere inside it.
func TestRestoreStateDirectorySwappedAfterCheck(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"to outside", "outside"},
		{"within lib", "lib/engine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			etc, lib, outside := filepath.Join(root, "etc"), filepath.Join(root, "lib"), filepath.Join(root, "outside")
			write(t, filepath.Join(outside, "keep"), "x\n")
			write(t, filepath.Join(lib, "dns", "old"), "y\n")
			write(t, filepath.Join(lib, "engine", "ca-cert.pem"), "cert\n")
			swapped := false
			withRestoreHook(t, func(stage, p string) {
				if stage != "dir" || filepath.Base(p) != "dns" || swapped {
					return
				}
				swapped = true
				if err := os.Rename(p, p+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, tc.target), p); err != nil {
					t.Fatal(err)
				}
			})
			err := RestoreState(etc, lib, stateTar(t, map[string]string{"lib/dns/ca-cert.pem": "owned\n"}))
			if !swapped {
				t.Fatal("the hook never ran")
			}
			if err == nil {
				t.Fatal("restore wrote through a directory swapped for a symlink")
			}
			noneUnder(t, outside, "keep")
			if got := read(t, filepath.Join(lib, "engine", "ca-cert.pem")); got != "cert\n" {
				t.Fatalf("redirected into lib/engine: %q", got)
			}
			noneUnder(t, filepath.Join(lib, "engine"), "ca-cert.pem")
		})
	}
}

// If the final name is swapped for a symlink after its check, the link is
// replaced, never followed. The file is renamed over the link, and the
// target of the link stays as it was.
func TestRestoreStateFileSwappedAfterCheck(t *testing.T) {
	root := t.TempDir()
	etc, lib, outside := filepath.Join(root, "etc"), filepath.Join(root, "lib"), filepath.Join(root, "outside")
	write(t, filepath.Join(outside, "shadow"), "root:x\n")
	write(t, filepath.Join(lib, "dns", "state"), "old\n")
	swapped := false
	withRestoreHook(t, func(stage, p string) {
		if stage != "file" || swapped {
			return
		}
		swapped = true
		os.Remove(p)
		if err := os.Symlink(filepath.Join(outside, "shadow"), p); err != nil {
			t.Fatal(err)
		}
	})
	if err := RestoreState(etc, lib, stateTar(t, map[string]string{"lib/dns/state": "new\n"})); err != nil {
		t.Fatal(err)
	}
	if !swapped {
		t.Fatal("the hook never ran")
	}
	if got := read(t, filepath.Join(outside, "shadow")); got != "root:x\n" {
		t.Fatalf("written through the swapped link: %q", got)
	}
	st, err := os.Lstat(filepath.Join(lib, "dns", "state"))
	if err != nil || !st.Mode().IsRegular() {
		t.Fatalf("lib/dns/state is not the restored file: %v %v", st, err)
	}
	if got := read(t, filepath.Join(lib, "dns", "state")); got != "new\n" {
		t.Fatalf("lib/dns/state = %q", got)
	}
	noneUnder(t, outside, "shadow")
}

// A snapshot restored over the tree that it was taken from gives back the
// same bytes and modes. Run as root, it also gives the same owners: the
// file of a daemon still belongs to the daemon after, not to root.
func TestRestoreStateKeepsBytesModesAndOwners(t *testing.T) {
	root := t.TempDir()
	etc, lib := filepath.Join(root, "etc"), filepath.Join(root, "lib")
	files := map[string]os.FileMode{
		"etc/net.env":            0600,
		"etc/segments.d/a.env":   0640,
		"lib/www/index.html":     0644,
		"lib/dns/fakeip/state":   0640,
		"lib/engine/ca-cert.pem": 0644,
	}
	for p, m := range files {
		write(t, filepath.Join(root, p), "body of "+p+"\n")
		if err := os.Chmod(filepath.Join(root, p), m); err != nil {
			t.Fatal(err)
		}
	}
	asRoot := os.Geteuid() == 0
	const daemon = 65534
	if asRoot {
		if err := os.Chown(filepath.Join(lib, "dns", "fakeip", "state"), daemon, daemon); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := SnapshotState(etc, lib)
	if err != nil {
		t.Fatal(err)
	}
	for p := range files {
		write(t, filepath.Join(root, p), "changed since\n")
		os.Chmod(filepath.Join(root, p), 0666)
	}
	if err := RestoreState(etc, lib, raw); err != nil {
		t.Fatal(err)
	}
	for p, m := range files {
		full := filepath.Join(root, p)
		if got := read(t, full); got != "body of "+p+"\n" {
			t.Errorf("%s = %q", p, got)
		}
		st, err := os.Lstat(full)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode() != m {
			t.Errorf("%s mode %v, want %v", p, st.Mode(), m)
		}
		if !asRoot {
			continue
		}
		want := uint32(0)
		if strings.HasPrefix(p, "lib/dns/") {
			want = daemon
		}
		if sys := st.Sys().(*syscall.Stat_t); sys.Uid != want || sys.Gid != want {
			t.Errorf("%s owner %d:%d, want %d:%d", p, sys.Uid, sys.Gid, want, want)
		}
	}
	if !asRoot {
		t.Log("not root: owners not checked")
	}
	for _, d := range []string{etc, lib} {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && strings.HasPrefix(e.Name(), ".pf-restore-") {
				t.Errorf("stage left behind: %s", p)
			}
			return nil
		})
	}
}

// A file that the restore creates, because nothing was at its name,
// belongs to root. Only a file that it replaces passes its owner on. Run
// as root (the root of a user namespace is sufficient). Skipped otherwise.
func TestRestoreStateNewFileIsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root")
	}
	root := t.TempDir()
	etc, lib := filepath.Join(root, "etc"), filepath.Join(root, "lib")
	write(t, filepath.Join(lib, "dns", "old"), "y\n")
	if err := RestoreState(etc, lib, stateTar(t, map[string]string{"lib/dns/new": "n\n", "lib/fresh/dir/file": "f\n", "etc/net.env": "e\n"})); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"lib/dns/new", "lib/fresh/dir/file", "etc/net.env"} {
		st, err := os.Lstat(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		if uid := st.Sys().(*syscall.Stat_t).Uid; uid != 0 {
			t.Errorf("%s is owned by %d, want root", p, uid)
		}
	}
}
