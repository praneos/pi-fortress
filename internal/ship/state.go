package ship

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// StateMin and StateMax are the on-disk state versions that this build
// can read. 1 is older than the secrets.expires sidecar. 2 is the format
// that carries it. Increase StateMax (and StateMin, after an older format
// is fully removed) each time /etc/pi-fortress or /var/lib/pi-fortress
// changes shape in a way that an older build would misread, not only
// ignore. Build reads these into each manifest that it writes. Thus the
// declared range of a bundle always matches the binary that made it.
const (
	StateMin = 1
	StateMax = 2
)

// DefaultStateVersionPath and DefaultReleasesDir are the locations of the
// state version integer and the kept releases. Both survive a swap the
// same way as /etc/pi-fortress and /var/lib/pi-fortress.
const (
	DefaultStateVersionPath = "/var/lib/pi-fortress/state.version"
	DefaultReleasesDir      = "/var/lib/pi-fortress/releases"
)

// keepReleases is how many prior generations releases/ retains.
const keepReleases = 3

// ReadStateVersion reads the integer at p. A missing file is a box from
// before this feature, or a box that has never taken a sidecar change.
// In both cases, it is state version 1, the only one that it could hold.
func ReadStateVersion(p string) (int64, error) {
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return legacyStateMax, nil
	}
	if err != nil {
		return 0, err
	}
	return parseVersion(p, raw)
}

// WriteStateVersion raises the state version at p to v when v is higher
// than the current value. It never lowers it. State that a newer build
// wrote stays on disk, and stays recorded, even after a rollback to an
// older build. The record makes the guard on a further rollback
// still work.
func WriteStateVersion(p string, v int64) error {
	cur, err := ReadStateVersion(p)
	if err != nil {
		return err
	}
	if v <= cur {
		return nil
	}
	return writeVersion(p, v)
}

// releaseDir is releasesRoot/<ver>.
func releaseDir(releasesRoot string, ver int64) string {
	return filepath.Join(releasesRoot, strconv.FormatInt(ver, 10))
}

// SaveRelease copies bundle into releasesRoot/<ver>/ as bundle.tar. It
// writes stateTar beside it as state.tar when non-nil. It prunes all
// generations except the newest three. bundle.tar is kept for its
// manifest, which the state-version guard of pf rollback reads. It is
// never installed again. It is called after a successful install. A
// failure here must not be treated as a failed install, because the
// tree is already live and applied when this runs.
func SaveRelease(releasesRoot string, ver int64, bundle string, stateTar []byte) error {
	dir := releaseDir(releasesRoot, ver)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := copyIn(bundle, filepath.Join(dir, "bundle.tar"), 1<<62); err != nil {
		return err
	}
	if stateTar != nil {
		if err := os.WriteFile(filepath.Join(dir, "state.tar"), stateTar, 0600); err != nil {
			return err
		}
	}
	return pruneReleases(releasesRoot, keepReleases)
}

// Identity is the ssh-keygen -Y verify triple that a bundle is accepted
// under: the triple of pf ship install (Namespace, Principal,
// allowed_signers) for a desktop push, and the public download triple
// for pf install and pf upgrade.
type Identity struct {
	Namespace string
	Principal string
	Signers   string
}

// ReleaseMeta is releases/<ver>/release.json: which version was live
// when the kept state.tar was taken. Thus pf rollback -with-state puts
// back only the state that .prev itself ran with. Records written before
// rollback lost -to also carry the identity that the bundle was verified
// under. Nothing reads it now.
type ReleaseMeta struct {
	StateOf int64 `json:"state_of"`
}

const releaseMetaName = "release.json"

// writeReleaseMeta records meta beside a kept release.
func writeReleaseMeta(releasesRoot string, ver int64, meta ReleaseMeta) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(releaseDir(releasesRoot, ver), releaseMetaName), append(raw, '\n'), 0600)
}

// readReleaseMeta reads releases/<ver>/release.json. ok is false for a
// release kept before the record existed. A record that is there and
// unreadable is an error, never a reason to fall back.
func readReleaseMeta(releasesRoot string, ver int64) (ReleaseMeta, bool, error) {
	p := filepath.Join(releaseDir(releasesRoot, ver), releaseMetaName)
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ReleaseMeta{}, false, nil
	}
	if err != nil {
		return ReleaseMeta{}, false, err
	}
	var m ReleaseMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return ReleaseMeta{}, false, fmt.Errorf("%s: %w", p, err)
	}
	return m, true, nil
}

// pruneReleases keeps the keep highest-numbered version directories
// under root and removes the rest.
func pruneReleases(root string, keep int) error {
	ents, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var vers []int64
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if v, err := strconv.ParseInt(e.Name(), 10, 64); err == nil && v > 0 {
			vers = append(vers, v)
		}
	}
	sort.Slice(vers, func(i, j int) bool { return vers[i] > vers[j] })
	if len(vers) <= keep {
		return nil
	}
	for _, v := range vers[keep:] {
		if err := os.RemoveAll(releaseDir(root, v)); err != nil {
			return err
		}
	}
	return nil
}

// stateSkip is what a state snapshot leaves out, by path under etcDir
// ("etc") and libDir ("lib"). A restore also refuses to write it, even
// when an older snapshot still carries it. A pattern that matches a
// directory covers all below it.
//
// Live credentials, the CA private key and the WireGuard key are
// excluded for the reason that backup.Exclusions gives. Otherwise, a
// state.tar kept for three generations would outlive each seal and each
// delete, and -with-state would bring back a credential that the
// operator removed. The trust roots and the lab marker are also
// excluded. An older copy would trust again a key that was revoked, or
// enable the echo again. Run counters and offsets are the state of a run
// that has ended. The remainder is the bookkeeping of ship: the floor,
// the pending timer, the state version and the upload work space. A
// restore must never move these backwards without the knowledge of the installer.
var stateSkip = map[string][]string{
	"etc": {
		"secrets.env*", ".secrets.env*", "secrets.disabled",
		"broker/secrets.env*", "broker/.secrets.env*", "broker/secrets.disabled",
		"mullvad.conf", "wireguard",
		"allowed_signers", "release-signers", "pfship.pub",
		"agent-env-*.sh", "agent-credentials-*.json",
		"lab",
	},
	"lib": {
		"engine/ca.pem", "mitm", "www/claims", "www/claims-redeemed",
		"*.offset", "*.last", "journal.cursor", "observe.json", "*.leases", "monitor",
		"releases", "incoming", "ship-work", "install", "install-work", "upgrade",
		"ship.version", "ship.pending", ".ship.pending-*", "ship.lock", "state.version", ".pf-ship-*",
	},
}

// stateSkipped reports whether rel under top ("etc" or "lib"), or any
// directory above it, matches a stateSkip pattern.
func stateSkipped(top, rel string) bool {
	parts := strings.Split(rel, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		for _, pat := range stateSkip[top] {
			if ok, _ := path.Match(pat, p); ok {
				return true
			}
		}
	}
	return false
}

// SnapshotState tars etcDir as "etc/..." and libDir as "lib/...", and
// leaves out what stateSkip names. It is taken before a swap. Thus it is
// the state that the box ran under the generation that will be
// replaced. pf rollback --with-state puts it back if that generation is
// later the one to return to. Symlinks, sockets and other non-regular
// entries are skipped: pi-fortress keeps no state as such an
// entry.
func SnapshotState(etcDir, libDir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := snapshotAdd(tw, etcDir, "etc"); err != nil {
		return nil, err
	}
	if err := snapshotAdd(tw, libDir, "lib"); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func snapshotAdd(tw *tar.Writer, root, prefix string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if stateSkipped(prefix, rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		name := prefix + "/" + rel
		switch {
		case d.IsDir():
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0700, ModTime: info.ModTime(), Typeflag: tar.TypeDir})
		case info.Mode().IsRegular():
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			return err
		default:
			return nil
		}
	})
}

// RestoreState writes a SnapshotState tar back under etcDir and libDir,
// by the same "etc/" and "lib/" prefixes that it was written with. It
// refuses all else in the tar, and a path that is not clean. It does not
// skip them silently. This restores root-owned state from a local file,
// and a tar that does not match what this build writes must not get
// blind trust. It passes over what stateSkip names. Thus a snapshot taken
// before those exclusions existed cannot put a deleted credential back.
//
// A daemon account can write some of these directories (the store
// directory of the broker, the state of pf-dns). Thus a symlink planted
// in one must not redirect a root write. A symlink swapped in after the
// check must not either. A check by path and then a write by path left
// that window open. Thus etcDir and libDir are each opened one time as
// an os.Root. Each directory below is reached from the descriptor of the
// directory above it. A component is Lstat'ed, refused if it is a symlink
// or not a directory, and opened. The descriptor is held only if it is
// the same directory that was checked. Each later step (create the
// stage, fchmod and fchown on its descriptor, the rename over the
// target) works relative to that descriptor. Thus a name swap on the
// path after that changes nothing that the restore touches. A missing
// directory is created one level at a time. Each file is staged under a
// new name beside its target and renamed over it. It keeps the owner of
// the file that it replaces.
func RestoreState(etcDir, libDir string, stateTar []byte) error {
	roots := map[string]*os.Root{}
	defer func() {
		for _, r := range roots {
			r.Close()
		}
	}()
	open := func(top, base string) (*os.Root, error) {
		if r, ok := roots[top]; ok {
			return r, nil
		}
		if err := os.MkdirAll(base, 0755); err != nil {
			return nil, err
		}
		r, err := os.OpenRoot(base)
		if err != nil {
			return nil, err
		}
		roots[top] = r
		return r, nil
	}
	tr := tar.NewReader(bytes.NewReader(stateTar))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		top, rel, ok := strings.Cut(strings.TrimSuffix(hdr.Name, "/"), "/")
		var base string
		switch top {
		case "etc":
			base = etcDir
		case "lib":
			base = libDir
		default:
			return fmt.Errorf("state.tar: %q is outside etc/ and lib/", hdr.Name)
		}
		if !ok || rel == "" {
			continue
		}
		if !CleanRel(rel) {
			return fmt.Errorf("state.tar: bad path %q", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("state.tar: %q: entry type %q is not allowed", hdr.Name, hdr.Typeflag)
		}
		if stateSkipped(top, rel) {
			continue
		}
		r, err := open(top, base)
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir {
			d, err := restoreDirs(r, base, rel, 0700)
			if err != nil {
				return err
			}
			if d != r {
				d.Close()
			}
			continue
		}
		dir, name := path.Split(rel)
		dir = strings.TrimSuffix(dir, "/")
		d, err := restoreDirs(r, base, dir, 0755)
		if err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode).Perm()
		if mode == 0 {
			mode = 0600
		}
		err = restoreFile(d, filepath.Join(base, filepath.FromSlash(dir)), name, tr, hdr.Size, mode)
		if d != r {
			d.Close()
		}
		if err != nil {
			return fmt.Errorf("state.tar: %s: %w", hdr.Name, err)
		}
	}
	return nil
}

// testHookRestore runs between a check and the step that relies on it.
// "dir": after a directory component passed its Lstat and before it is
// opened. "file": after the target passed its Lstat and before the stage
// is created. The race tests swap a symlink in there.
var testHookRestore func(stage, path string)

// restoreDirs walks rel down from r, one component at a time, and
// returns the directory where it ends, open. It returns r itself when rel
// is empty. What is missing is created with mode. A symlink, anything
// that is not a directory, or a directory that is not the one just
// checked when it is opened, is refused. base only names paths in errors.
func restoreDirs(r *os.Root, base, rel string, mode os.FileMode) (*os.Root, error) {
	return walkDirs(r, base, rel, true, mode)
}

// walkDirs is restoreDirs, or with create false the same walk that
// creates nothing and returns the fs.ErrNotExist of the first missing
// component.
func walkDirs(r *os.Root, base, rel string, create bool, mode os.FileMode) (*os.Root, error) {
	cur := r
	fail := func(err error) (*os.Root, error) {
		if cur != r {
			cur.Close()
		}
		return nil, err
	}
	if rel == "" {
		return r, nil
	}
	p := base
	for c := range strings.SplitSeq(rel, "/") {
		p = filepath.Join(p, c)
		st, err := cur.Lstat(c)
		if create && errors.Is(err, fs.ErrNotExist) {
			if err := cur.Mkdir(c, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return fail(err)
			}
			st, err = cur.Lstat(c)
		}
		if err != nil {
			return fail(err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return fail(fmt.Errorf("state restore: %s is a symlink; refusing to write through it", p))
		}
		if !st.IsDir() {
			return fail(fmt.Errorf("state restore: %s is not a directory", p))
		}
		if testHookRestore != nil {
			testHookRestore("dir", p)
		}
		next, err := cur.OpenRoot(c)
		if err == nil {
			err = sameAs(next, st)
		}
		if err != nil {
			if next != nil {
				next.Close()
			}
			return fail(fmt.Errorf("state restore: %s changed while it was being restored: %w", p, err))
		}
		if cur != r {
			cur.Close()
		}
		cur = next
	}
	return cur, nil
}

// sameAs says that d is the directory that st was taken of. os.Root
// follows a symlink that stays inside it. Thus this catches a name
// swapped for a symlink between the Lstat and the open, by identity, not by name.
func sameAs(d *os.Root, st fs.FileInfo) error {
	now, err := d.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(st, now) {
		return errors.New("not the directory that was checked")
	}
	return nil
}

// restoreFile stages n bytes of src beside name in d and renames the
// stage over it. It keeps the owner of the file that it replaces. dir
// only names paths in errors.
func restoreFile(d *os.Root, dir, name string, src io.Reader, n int64, mode os.FileMode) error {
	return stageOver(d, dir, name, ".pf-restore-", func(cur fs.FileInfo) (os.FileMode, int, int) {
		if cur == nil {
			return mode, -1, -1
		}
		uid, gid := fileOwner(cur)
		return mode, uid, gid
	}, func(f *os.File) error {
		_, err := io.CopyN(f, src, n)
		return err
	})
}

// stageOver writes a new file beside name in d and renames it over name.
// A symlink or anything other than a regular file at the target is
// refused. It is not followed or replaced. The stage is created O_EXCL
// under a new name and filled. It then gets the mode and owner that perm
// returns for the file that it replaces (nil when there is none): the
// owner only when run as root, and -1 for none. All of this occurs on
// its own descriptor. The rename and the directory sync go by d. Nothing
// is done by a path that an unprivileged writer could point to a
// different location. The rename replaces a link swapped in at the
// target after the check. It never follows it.
func stageOver(d *os.Root, dir, name, prefix string, perm func(cur fs.FileInfo) (os.FileMode, int, int), fill func(*os.File) error) error {
	dst := filepath.Join(dir, name)
	var cur fs.FileInfo
	if st, err := d.Lstat(name); err == nil {
		if st.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to write through it", dst)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", dst)
		}
		cur = st
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	mode, uid, gid := perm(cur)
	if testHookRestore != nil {
		testHookRestore("file", dst)
	}
	tmp, f, err := createStage(d, prefix)
	if err != nil {
		return err
	}
	werr := fill(f)
	if werr == nil {
		werr = f.Chmod(mode)
	}
	if werr == nil && uid >= 0 && os.Geteuid() == 0 {
		werr = f.Chown(uid, gid)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = d.Rename(tmp, name)
	}
	if werr != nil {
		d.Remove(tmp)
		return werr
	}
	return syncRoot(d)
}

// createStage makes a new, empty file in d under a name nobody else
// picked.
func createStage(d *os.Root, prefix string) (string, *os.File, error) {
	for range 16 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", nil, err
		}
		name := prefix + hex.EncodeToString(b[:])
		f, err := d.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return name, f, err
	}
	return "", nil, errors.New("no free stage name")
}

// syncRoot flushes the directory entries of d, so a rename into it
// survives a power loss.
func syncRoot(d *os.Root) error {
	f, err := d.Open(".")
	if err != nil {
		return err
	}
	serr := f.Sync()
	cerr := f.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// fileOwner is st's uid and gid, or -1, -1 where the platform does not
// say.
func fileOwner(st fs.FileInfo) (int, int) {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid), int(sys.Gid)
	}
	return -1, -1
}
