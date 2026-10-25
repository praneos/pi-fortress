package ship

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pi-fortress/internal/jsonl"
)

const (
	BundleName = "pf-bundle.tar"
	SigName    = BundleName + ".sig"
	Namespace  = "pi-fortress-release"
	Principal  = "release"
	maxSig     = 64 << 10
)

// Installer is pf ship install: take the pair that pfship uploaded, verify,
// swap the tree, apply, roll back on failure. The caller wires Apply, Lock
// and Alert, so tests run without root.
type Installer struct {
	Incoming    string
	Work        string
	Dir         string
	VersionPath string
	Signers     string
	// Namespace and Principal are the ssh-keygen -Y verify identity that a
	// bundle must be signed under. Empty means the current constants
	// (Namespace, Principal: the desktop-push identity, docs/signed_ship.md).
	// Thus each existing caller is unchanged. pf install/pf upgrade pass the
	// public-download identity in their place (pi-fortress-dist,
	// docs/gateway_install.md "Two signers, on purpose"). Thus the two trust
	// roots stay separate, although both run through this Installer.
	Namespace string
	Principal string
	Log       string
	Keygen    string
	Limits    Limits
	// Settle is the time that the upload directory may stay unchanged
	// without a complete pair before the attempt is abandoned.
	Settle time.Duration
	Poll   time.Duration
	Apply  func() error
	Lock   func() (release func(), err error)
	// SelfLock excludes a second installer. Lock is the apply lock. swap
	// must release it before apply takes it again through pf, so it never
	// covers the whole attempt. Work, Dir.new and Dir.prev are fixed
	// names that two runs would otherwise use again under each other.
	SelfLock func() (release func(), err error)
	// Merge reconciles a kept path with the copy of it in the bundle, by
	// path. The file of the Pi wins, and the function decides what it still
	// takes from the shipped file (fetch.MergeSeed for sources.json).
	// changed false leaves the kept file as it was.
	Merge  map[string]func(kept, shipped []byte) (out []byte, changed bool, err error)
	Alert  func(msg string)
	Stderr io.Writer

	// PostUpgradeCheck runs after Apply has succeeded. A non-nil error
	// rolls back the same way as a failed Apply. Nil skips the check.
	// That is the state of each existing caller until pf ship install
	// wires pf doctor --post-upgrade in.
	PostUpgradeCheck func() error
	// PendingPath and PendingTTL arm the confirm-or-revert timer after a
	// successful install. An empty PendingPath skips the write.
	PendingPath string
	PendingTTL  time.Duration
	// ReleasesDir keeps the bundle and state snapshot of the last few
	// generations: the manifest of the bundle for the state-version guard
	// of pf rollback, and the snapshot for -with-state. Empty skips this.
	ReleasesDir string
	// StateVersionPath is where the state version integer lives. Empty
	// uses DefaultStateVersionPath.
	StateVersionPath string
	// EtcDir and LibDir are what a state.tar snapshot covers. Empty
	// uses /etc/pi-fortress and /var/lib/pi-fortress.
	EtcDir, LibDir string
}

// testHookAfterExchange runs in the window where the new tree is already
// live and the old one is not yet parked at Dir.prev. Nothing else can
// reach that window. What occurs in it decides whether a failed swap is
// recoverable.
var testHookAfterExchange func()

func Defaults() *Installer {
	return &Installer{
		Incoming:    "/var/lib/pi-fortress/incoming",
		Work:        "/var/lib/pi-fortress/ship-work",
		Dir:         "/opt/pi-fortress",
		VersionPath: "/var/lib/pi-fortress/ship.version",
		Signers:     "/etc/pi-fortress/allowed_signers",
		Log:         "/var/log/pi-fortress/ship.jsonl",
		Keygen:      "/usr/bin/ssh-keygen",
		Limits:      DefaultLimits,
		Settle:      60 * time.Second,
		Poll:        time.Second,
	}
}

type refusal struct {
	class string
	err   error
}

func (r *refusal) Error() string { return r.class + ": " + r.err.Error() }

func refuse(class string, err error) error { return &refusal{class, err} }

// Run processes at most one upload. It returns the logged row, or ok=false
// when the directory was empty.
func (in *Installer) Run() (jsonl.Ship, bool) {
	// Before anything is read or removed. The work directory, Dir.new and
	// Dir.prev are fixed names. The first act of a second installer is to
	// delete the work directory that the first installer verifies inside.
	// Thus the exclusion must cover the attempt from end to end, not only
	// the swap. On purpose, the upload stays where it is. The path unit
	// starts this service again, and the run that holds the lock is the
	// correct run to consume it.
	if in.SelfLock != nil {
		release, err := in.SelfLock()
		if err != nil {
			row := jsonl.Ship{Result: "busy", Reason: err.Error()}
			in.record(row)
			return row, true
		}
		if release != nil {
			defer release()
		}
	}
	seen, ready, err := in.wait()
	if err != nil {
		row := jsonl.Ship{Result: "incoming", Reason: err.Error()}
		in.record(row)
		return row, true
	}
	if len(seen) == 0 {
		return jsonl.Ship{}, false
	}
	defer in.clean(seen)
	var row jsonl.Ship
	if !ready {
		row = jsonl.Ship{Result: "incomplete", Reason: "no " + BundleName + " + " + SigName + " pair before the upload went quiet"}
	} else {
		row = in.install()
	}
	in.record(row)
	return row, true
}

func (in *Installer) wait() (map[string]os.FileInfo, bool, error) {
	type stamp struct {
		size int64
		mod  time.Time
	}
	var prev map[string]stamp
	last := time.Now()
	hard := last.Add(30 * time.Minute)
	for {
		ents, err := os.ReadDir(in.Incoming)
		if err != nil {
			return nil, false, err
		}
		seen := make(map[string]os.FileInfo, len(ents))
		cur := make(map[string]stamp, len(ents))
		busy := false
		for _, e := range ents {
			info, err := e.Info()
			if err != nil {
				continue
			}
			seen[e.Name()] = info
			cur[e.Name()] = stamp{info.Size(), info.ModTime()}
			busy = busy || strings.HasPrefix(e.Name(), ".")
		}
		if len(seen) == 0 {
			return nil, false, nil
		}
		if seen[BundleName] != nil && seen[SigName] != nil && !busy {
			return seen, true, nil
		}
		if !sameStamps(prev, cur) {
			last = time.Now()
		}
		prev = cur
		if now := time.Now(); now.Sub(last) >= in.Settle || now.After(hard) {
			return seen, false, nil
		}
		time.Sleep(in.Poll)
	}
}

func sameStamps[K comparable, V comparable](a, b map[K]V) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// clean removes what this run saw, and only if it is still the same file.
// A newer upload that replaced a name during the run stays for the next trigger.
func (in *Installer) clean(seen map[string]os.FileInfo) {
	for name, info := range seen {
		p := filepath.Join(in.Incoming, name)
		if now, err := os.Lstat(p); err == nil && os.SameFile(now, info) {
			os.RemoveAll(p)
		}
	}
}

func (in *Installer) record(row jsonl.Ship) {
	if in.Log != "" {
		if err := jsonl.AppendShip(in.Log, row); err != nil {
			fmt.Fprintf(in.stderr(), "pf ship: log: %v\n", err)
		}
	}
	fmt.Fprintf(in.stderr(), "pf ship: %s version=%d sha=%s %s\n", row.Result, row.Version, row.SHA, row.Reason)
	// confirm is not a problem to alert on. It is an operator (or later,
	// the TUI) that says that a ship that already went out as "ok" is good.
	if row.Result != "ok" && row.Result != "confirm" && in.Alert != nil {
		in.Alert(fmt.Sprintf("pi-fortress ship %s: %s", row.Result, row.Reason))
	}
}

func (in *Installer) stderr() io.Writer {
	if in.Stderr != nil {
		return in.Stderr
	}
	return os.Stderr
}

func (in *Installer) install() jsonl.Ship {
	m, err := in.stage()
	row := jsonl.Ship{Result: "ok"}
	if m != nil {
		row.Version, row.SHA = m.Version, m.SHA
	}
	if err != nil {
		row.Result, row.Reason = "error", err.Error()
		var r *refusal
		if errors.As(err, &r) {
			row.Result, row.Reason = r.class, r.err.Error()
		}
	}
	return row
}

func (in *Installer) bundleCap() int64 {
	l := in.Limits
	return l.MaxTotal + l.MaxManifest + int64(2*l.MaxFiles)*1024 + 1<<20
}

// stage runs every step; the refusal class of the error is the log result.
func (in *Installer) stage() (*Manifest, error) {
	if err := os.RemoveAll(in.Work); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(in.Work), 0755); err != nil {
		return nil, err
	}
	if err := os.Mkdir(in.Work, 0700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(in.Work)
	bundle, sig := filepath.Join(in.Work, BundleName), filepath.Join(in.Work, SigName)
	if err := copyIn(filepath.Join(in.Incoming, BundleName), bundle, in.bundleCap()); err != nil {
		return nil, refuse("bad_upload", err)
	}
	if err := copyIn(filepath.Join(in.Incoming, SigName), sig, maxSig); err != nil {
		return nil, refuse("bad_upload", err)
	}
	if err := in.verify(bundle, sig); err != nil {
		return nil, refuse("bad_sig", err)
	}
	cur, err := readVersion(in.VersionPath, in.Dir)
	if err != nil {
		return nil, refuse("version_file", err)
	}
	// The tree can name a higher floor than the file: the file was
	// unlinked, or a crash occurred between the exchange and the write that
	// publishes it. Repair the file here, not only on the paths that then
	// succeed. Thus a box that continues to refuse replays does not
	// reconstruct the floor from the tree on each run. Also, the number
	// that an operator reads is the number that is enforced.
	if err := repairVersion(in.VersionPath, cur); err != nil {
		return nil, refuse("version_file", err)
	}
	next := in.Dir + ".new"
	// A tree at Dir.new that survived the last run is the old generation.
	// The only window that leaves one there is a crash between the
	// exchange and the rename that parks it. In that window, the live
	// tree is a generation that was never applied. Before, this code
	// deleted it as its first step. That discards the only copy of the
	// installation that the box used.
	if err := in.park(next); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(next); err != nil {
		return nil, err
	}
	f, err := os.Open(bundle)
	if err != nil {
		return nil, err
	}
	m, err := Extract(f, next, in.Limits, cur)
	f.Close()
	if errors.Is(err, ErrRollback) {
		return m, refuse("rollback", err)
	}
	if err != nil {
		return m, refuse("bad_bundle", err)
	}
	// The state snapshot is of the generation that this swap will
	// replace, taken before anything moves. pf rollback --with-state
	// puts it back if this release is the release that is later
	// rolled back.
	var stateTar []byte
	if in.ReleasesDir != "" {
		if snap, err := SnapshotState(in.etcDir(), in.libDir()); err == nil {
			stateTar = snap
		} else {
			fmt.Fprintf(in.stderr(), "pf ship: state snapshot: %v\n", err)
		}
	}
	if err := in.swap(m, next); err != nil {
		return m, refuse("swap", err)
	}
	// A pending confirm from an earlier ship names the .prev that this
	// swap has just overwritten. Thus it would point pf ship deadman at a
	// rollback target that no longer exists. But only now: a swap that
	// failed left that .prev and its pending as they were. Best effort: a
	// leftover pending file is at worst a stale safety net. It is never a
	// reason to fail an install that is otherwise good.
	if in.PendingPath != "" {
		RemovePending(in.PendingPath)
	}
	// The floor is published with the tree, not after the apply that
	// follows it. The floor refuses a replay of an older signed bundle.
	// Thus it must name the generation that is live. Before, this was
	// written last. Then a failed write left the new tree running, with a
	// floor that still named the release that it replaced. Each bundle
	// above that stale floor (the defective one included) was accepted
	// again. The cost: a floor that cannot be written undoes the tree.
	// That is the same answer as any other failure at this point.
	if err := writeVersion(in.VersionPath, m.Version); err != nil {
		return m, refuse("version_file", in.rollback(cur, err).err)
	}
	if err := in.Apply(); err != nil {
		return m, refuse("apply_failed", in.rollback(cur, err).err)
	}
	if in.PostUpgradeCheck != nil {
		if err := in.PostUpgradeCheck(); err != nil {
			return m, refuse("post_upgrade", in.rollback(cur, err).err)
		}
	}
	// All steps below are bookkeeping on an install that has already
	// swapped, applied and, if configured, passed the post-upgrade
	// doctor. A failure here is logged, never rolled back over.
	if in.ReleasesDir != "" {
		if err := SaveRelease(in.ReleasesDir, m.Version, bundle, stateTar); err != nil {
			fmt.Fprintf(in.stderr(), "pf ship: keeping release %d: %v\n", m.Version, err)
		} else if err := writeReleaseMeta(in.ReleasesDir, m.Version, ReleaseMeta{StateOf: cur}); err != nil {
			fmt.Fprintf(in.stderr(), "pf ship: recording which state release %d took over: %v\n", m.Version, err)
		}
	}
	if err := WriteStateVersion(in.stateVersionPath(), m.EffectiveStateMax()); err != nil {
		fmt.Fprintf(in.stderr(), "pf ship: state version: %v\n", err)
	}
	if in.PendingPath != "" {
		ttl := in.PendingTTL
		if ttl <= 0 {
			ttl = DefaultPendingTTL
		}
		p := Pending{Version: m.Version, PrevVersion: cur, Deadline: time.Now().Add(ttl)}
		if err := WritePending(in.PendingPath, p); err != nil {
			fmt.Fprintf(in.stderr(), "pf ship: arming the confirm timer: %v\n", err)
		}
	}
	return m, nil
}

func (in *Installer) etcDir() string {
	if in.EtcDir != "" {
		return in.EtcDir
	}
	return "/etc/pi-fortress"
}

func (in *Installer) libDir() string {
	if in.LibDir != "" {
		return in.LibDir
	}
	return "/var/lib/pi-fortress"
}

func (in *Installer) namespace() string {
	if in.Namespace != "" {
		return in.Namespace
	}
	return Namespace
}

func (in *Installer) principal() string {
	if in.Principal != "" {
		return in.Principal
	}
	return Principal
}

func (in *Installer) identity() Identity {
	return Identity{Namespace: in.namespace(), Principal: in.principal(), Signers: in.Signers}
}

func (in *Installer) stateVersionPath() string {
	if in.StateVersionPath != "" {
		return in.StateVersionPath
	}
	return DefaultStateVersionPath
}

// park moves a tree stranded at Dir.new into Dir.prev when nothing is
// there. It only ever runs on the remains of an interrupted attempt.
func (in *Installer) park(next string) error {
	if _, err := os.Lstat(next); err != nil {
		return nil
	}
	prev := in.Dir + ".prev"
	if _, err := os.Lstat(prev); err == nil {
		return nil
	}
	if err := os.Rename(next, prev); err != nil {
		return fmt.Errorf("a tree from an interrupted ship is at %s and cannot be moved aside: %w", next, err)
	}
	return nil
}

// verify shells out. ssh-keygen already parses SSHSIG, sk-ssh-ed25519 flags included. A stdlib reimplementation is new crypto code that can be wrong.
func (in *Installer) verify(bundle, sig string) error {
	return in.verifyAs(in.identity(), bundle, sig)
}

func (in *Installer) verifyAs(id Identity, bundle, sig string) error {
	st, err := os.Lstat(id.Signers)
	if err != nil {
		return fmt.Errorf("%s: %w; every bundle is refused until it exists", id.Signers, err)
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&022 != 0 || sys == nil || int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be a regular file owned by uid %d and not group- or world-writable", id.Signers, os.Geteuid())
	}
	return KeygenVerify(in.Keygen, id.Signers, id.Principal, id.Namespace, bundle, sig)
}

// KeygenVerify runs keygen -Y verify on bundle against sig. Its error
// carries the first line of the ssh-keygen output. It first refuses a
// signers file with a line that is not bound to namespace (CheckSigners).
func KeygenVerify(keygen, signers, principal, namespace, bundle, sig string) error {
	if err := CheckSigners(signers, namespace); err != nil {
		return err
	}
	f, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, keygen, "-Y", "verify", "-f", signers, "-I", principal, "-n", namespace, "-s", sig)
	cmd.Stdin = f
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = strings.TrimSpace(msg[:i])
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("ssh-keygen -Y verify: %v: %s", err, msg)
	}
	return nil
}

// swap carries the Pi-owned paths into the new tree, and exchanges it with
// the live tree under the apply lock. The old tree stays at Dir.prev.
func (in *Installer) swap(m *Manifest, next string) error {
	release, err := in.Lock()
	if err != nil {
		os.RemoveAll(next)
		return err
	}
	defer release()
	err = func() error {
		for _, k := range m.Keep {
			shipped, merge := []byte(nil), in.Merge[k]
			if merge != nil {
				shipped, _ = os.ReadFile(filepath.Join(next, filepath.FromSlash(k)))
			}
			if err := carry(in.Dir, next, k); err != nil {
				return fmt.Errorf("keep %s: %w", k, err)
			}
			if shipped != nil {
				if err := mergeKept(filepath.Join(next, filepath.FromSlash(k)), shipped, merge); err != nil {
					return fmt.Errorf("merge %s: %w", k, err)
				}
			}
		}
		// Both of these occur before the tree is published, never
		// after. The stamp, so that the floor and the generation that it
		// names go live in the same rename. The flush, so that what the
		// exchange publishes is on the medium, not only in the cache.
		if err := writeStamp(next, m.Version); err != nil {
			return err
		}
		if err := syncTree(next); err != nil {
			return err
		}
		if err := os.RemoveAll(in.Dir + ".prev"); err != nil {
			return err
		}
		if _, err := os.Lstat(in.Dir); errors.Is(err, fs.ErrNotExist) {
			return os.Rename(next, in.Dir)
		}
		return exchange(next, in.Dir)
	}()
	if err != nil {
		os.RemoveAll(next)
		return err
	}
	if _, err := os.Lstat(next); errors.Is(err, fs.ErrNotExist) {
		return syncDir(in.Dir)
	}
	if testHookAfterExchange != nil {
		testHookAfterExchange()
	}
	// The exchange already made the new tree live. This rename only parks
	// the old tree where rollback can find it. Before, the code reported
	// the failure and returned. That left the new tree live and never
	// applied, with the only copy of the old tree under a name that the
	// next upload deletes. To undo the exchange is the recoverable answer:
	// the box goes back to the tree that it ran, and the refusal means what it says.
	if err := os.Rename(next, in.Dir+".prev"); err != nil {
		if uerr := exchange(next, in.Dir); uerr != nil {
			return fmt.Errorf("new tree is live, never applied, and the old one is stuck at %s: %w (undo: %v)", next, err, uerr)
		}
		os.RemoveAll(next)
		return fmt.Errorf("the old tree could not be moved to %s, so the new one was not kept: %w", in.Dir+".prev", err)
	}
	return syncDir(in.Dir)
}

// syncDir flushes the directory that holds path. Thus the renames that
// made a generation live are on the medium, not only in the page cache. A
// ship that survives the reboot that it triggers must be the ship that
// was logged, not the ship before it.
func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// errNoPrev is a rollback that found nothing at Dir.prev to put back.
// No retry can change that, so pf ship deadman stops waiting on it.
var errNoPrev = errors.New("no previous tree to restore")

// rollbackResult says how far a rollback got. err is never nil: it is
// the reason the rollback ran, followed by what happened.
type rollbackResult struct {
	// restored is true when the previous tree is live again. It is true
	// from the moment the exchange succeeds, whatever fails after it.
	// From then on, a second run of the rollback would swap the refused
	// tree directly back in.
	restored bool
	// applied is true when the re-apply of the restored tree succeeded.
	applied bool
	// stateErr is the failure of the before hook (pf rollback -with-state).
	stateErr error
	err      error
}

// rollback puts Dir.prev back, with the operator lists of the live tree
// mirrored into it (mirrorLists). It keeps the refused tree at Dir.failed
// and applies the old tree again. The floor goes back with it: it names
// the generation that is live. If it stayed advanced over a tree that was
// withdrawn, it would refuse the version of that tree forever after.
func (in *Installer) rollback(floor int64, applyErr error) rollbackResult {
	return in.rollbackThen(floor, applyErr, nil)
}

// rollbackThen is rollback with before, run one time after the previous
// tree is live and before it is applied, still under the apply lock. pf
// rollback -with-state puts the state back there. Thus the apply that
// follows compiles from the state that it is meant to run with. A failure
// of before does not stop the apply (the tree is already swapped, and an
// unapplied tree is worse). It is reported in stateErr.
func (in *Installer) rollbackThen(floor int64, applyErr error, before func() error) rollbackResult {
	prev, failed := in.Dir+".prev", in.Dir+".failed"
	if _, err := os.Lstat(prev); err != nil {
		return rollbackResult{err: fmt.Errorf("%v; %w", applyErr, errNoPrev)}
	}
	release, err := in.Lock()
	if err != nil {
		return rollbackResult{err: fmt.Errorf("%v; restore: %v", applyErr, err)}
	}
	// The lists of prev are older than the lists of the operator. An
	// exchange without the mirror would silently allow again what was
	// revoked after the upgrade, and remove blocks added after it. That is
	// a fail-open. Thus a mirror that fails stops the rollback here, before
	// anything moves: restored stays false, pf rollback exits non-zero, and
	// pf ship deadman keeps ship.pending and retries.
	if err := mirrorLists(in.Dir, prev); err != nil {
		release()
		return rollbackResult{err: fmt.Errorf("%v; restore: %v", applyErr, err)}
	}
	var res rollbackResult
	err = os.RemoveAll(failed)
	if err == nil {
		err = exchange(prev, in.Dir)
		res.restored = err == nil
	}
	if err == nil {
		err = os.Rename(prev, failed)
	}
	if err == nil {
		err = restoreVersion(in.VersionPath, floor)
	}
	if err == nil && before != nil {
		res.stateErr = before()
	}
	release()
	if err != nil {
		res.err = fmt.Errorf("%v; restore: %v", applyErr, err)
		return res
	}
	if err := in.Apply(); err != nil {
		res.err = fmt.Errorf("%v; previous tree restored, its re-apply failed too: %v", applyErr, err)
		return res
	}
	res.applied = true
	res.err = fmt.Errorf("%v; previous tree restored and re-applied", applyErr)
	return res
}

// readVersion is the replay floor: the higher of the file at p and the
// stamp that the live tree carries. When a missing file read as 0, the
// whole defence depended on one unlink. Thus the code must tell "never
// shipped" from "shipped, and the record is gone". The live tree is the
// evidence. A Pi is provisioned by a copy of the repo to Dir, so the
// existence of the tree proves nothing. A tree that has taken a ship
// carries the stamp that the ship wrote into it. A tree that has not
// carries nothing. The higher of the two also closes the window between
// the exchange and the floor write: a tree that got ahead of its file
// names its own floor.
func readVersion(p, dir string) (int64, error) {
	var file int64
	raw, err := os.ReadFile(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		if file, err = parseVersion(p, raw); err != nil {
			return 0, err
		}
	}
	stamp, err := readStamp(dir)
	if err != nil {
		return 0, err
	}
	return max(file, stamp), nil
}

func parseVersion(p string, raw []byte) (int64, error) {
	s := strings.TrimSpace(string(raw))
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%s: unreadable version %q", p, s)
	}
	return v, nil
}

// stampName is the floor as the live tree carries it. The file at
// VersionPath stays the record that the operator sees, but it is a
// second object. It can be unlinked. Between the exchange and the write
// that publishes it, it is one generation behind. The same rename that
// publishes the tree publishes the copy inside the tree. Thus the copy
// cannot disagree with the generation that it names.
const stampName = ".pf-ship-version"

// readStamp reads the floor from a tree. Absent is zero: a tree that is
// older than this, or that was never shipped. A symlink, a non-regular
// file or an unparseable number is an error. The alternative is a quiet
// fallback to a lower floor, and that is the defect that this exists to stop.
func readStamp(dir string) (int64, error) {
	if dir == "" {
		return 0, nil
	}
	p := filepath.Join(dir, stampName)
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, fmt.Errorf("%s: not a regular file", p)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0, err
	}
	return parseVersion(p, raw)
}

// writeStamp puts the floor inside a staged tree, before that tree is
// made live. Thus the number and the generation that it names go live
// together. syncTree flushes the directory entry that names it.
func writeStamp(dir string, v int64) error {
	p := filepath.Join(dir, stampName)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d\n", v)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncTree flushes each directory in a staged tree. Extract flushes each
// file that it writes. The directory entries that name those files are
// the other half. Both must be on the medium before the exchange
// publishes the tree and the box reboots into it.
func syncTree(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		serr := f.Sync()
		cerr := f.Close()
		if serr != nil {
			return serr
		}
		return cerr
	})
}

// repairVersion publishes the floor at p again when it disagrees with
// the floor in force. Zero is the unshipped floor, and the absence of
// the file expresses it. Thus there is nothing to repair.
func repairVersion(p string, v int64) error {
	if v == 0 {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err == nil {
		if cur, perr := parseVersion(p, raw); perr == nil && cur == v {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeVersion(p, v)
}

func writeVersion(p string, v int64) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := stageVersion(dir, v)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	// The floor decides what the box accepts after the reboot that a ship
	// usually causes. Thus the directory entry that names it must be on
	// the medium before this returns.
	return syncDir(p)
}

// stageVersion writes the floor to a new name in dir and returns it.
// os.CreateTemp is O_EXCL on a name that nothing else knows. There is no
// shared name where a second writer can collide, and no name to plant a
// symlink at in advance. The fixed p+".tmp" that this opened before was
// both. To unlink it first would only add a second race.
func stageVersion(dir string, v int64) (string, error) {
	f, err := os.CreateTemp(dir, ".pf-ship-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	err = func() error {
		if err := f.Chmod(0644); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "%d\n", v); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// restoreVersion puts the floor back to its value before this attempt.
// A floor of zero is what an unshipped box reads. Thus the code removes
// the file for it, and does not write a zero that the reader would
// have to treat as a version.
func restoreVersion(p string, v int64) error {
	if v == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeVersion(p, v)
}

// copyIn copies an untrusted upload into the work dir through one
// descriptor. It follows no symlink and reads only a regular file.
// Verification then sees only the copy.
func copyIn(src, dst string, max int64) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", filepath.Base(src))
	}
	if st.Size() > max {
		return fmt.Errorf("%s: %d bytes, cap %d", filepath.Base(src), st.Size(), max)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, max+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("%s: grew past cap %d", filepath.Base(src), max)
	}
	return err
}

// carry copies rel from the live tree over the new one when the live tree
// has it. It refuses symlinks at all points on the path. Files that a
// login account (uid >= 1000) owned become owned by root.
// mergeKept rewrites a carried file with what merge takes from the
// shipped copy. It keeps the mode of the carried file.
func mergeKept(path string, shipped []byte, merge func(kept, shipped []byte) ([]byte, bool, error)) error {
	kept, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, changed, err := merge(kept, shipped)
	if err != nil || !changed {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, st.Mode().Perm())
}

func carry(from, to, rel string) error {
	src := from
	for c := range strings.SplitSeq(rel, "/") {
		src = filepath.Join(src, c)
		st, err := os.Lstat(src)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", src)
		}
	}
	dst := filepath.Join(to, filepath.FromSlash(rel))
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return copyTree(src, dst)
}

func copyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case st.IsDir():
		if err := os.Mkdir(dst, 0700); err != nil {
			return err
		}
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
	case st.Mode().IsRegular():
		if err := copyIn(src, dst, 1<<62); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: not a regular file or directory", src)
	}
	if err := os.Chmod(dst, st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		uid, gid := int(sys.Uid), int(sys.Gid)
		if uid >= 1000 {
			uid, gid = 0, 0
		}
		return os.Lchown(dst, uid, gid)
	}
	return nil
}
