package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/alert"
	"pi-fortress/internal/fetch"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/ship"
)

func runShip(args []string, stdout, stderr io.Writer) int {
	code := 2
	if len(args) > 0 {
		switch args[0] {
		case "bundle":
			return runShipBundle(args[1:], stdout, stderr)
		case "install":
			return runShipInstall(args[1:], stdout, stderr)
		case "lint":
			return runShipLint(args[1:], stdout, stderr)
		case "confirm":
			return runShipConfirm(args[1:], stdout, stderr)
		case "deadman":
			return runShipDeadman(args[1:], stdout, stderr)
		case "-h", "--help", "help":
			code = 0
		}
	}
	fmt.Fprintln(stderr, "usage: pf ship bundle -o FILE [flags] | pf ship install [flags] | pf ship confirm [-wait D] | pf ship deadman | pf ship lint FILE (docs/signed_ship.md)")
	return code
}

func runShipBundle(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("ship bundle", stderr)
	out := fs.String("o", "", "bundle file to write")
	root := fs.String("root", ".", "tree to bundle")
	version := fs.Int64("version", time.Now().Unix(), "monotonic version; the Pi refuses one not above its last install")
	sha := fs.String("sha", "", "source revision, for the log")
	exclude := fs.String("exclude-name", ".git .vagrant", "base names skipped at any depth")
	keep := fs.String("keep", "", "paths not shipped whose Pi copy is carried over")
	seed := fs.String("seed", "", "paths shipped whose Pi copy wins when present")
	omit := fs.String("omit", "", "paths not shipped")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *out == "" {
		fmt.Fprintln(stderr, "pf ship bundle: -o is required")
		return 2
	}
	opt := ship.BundleOptions{
		Version: *version, SHA: *sha,
		ExcludeNames: strings.Fields(*exclude),
		Keep:         strings.Fields(*keep),
		Seed:         strings.Fields(*seed),
		Omit:         strings.Fields(*omit),
	}
	for _, p := range []string{*out, *out + ".sig", *out + ".tmp"} {
		if rel, err := filepath.Rel(*root, p); err == nil && !strings.HasPrefix(rel, "..") {
			opt.Omit = append(opt.Omit, filepath.ToSlash(rel))
		}
	}
	tmp := *out + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fail(stderr, err)
	}
	m, err := ship.Build(f, *root, opt)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, *out)
	}
	if err != nil {
		os.Remove(tmp)
		return fail(stderr, fmt.Errorf("pf ship bundle: %w", err))
	}
	fmt.Fprintf(stdout, "%s version=%d sha=%s files=%d\n", *out, m.Version, m.SHA, len(m.Files))
	return 0
}

// runShipInstall is pi-fortress-ship.service: one upload per run. systemd
// starts it again while the directory is not empty.
func runShipInstall(args []string, _, stderr io.Writer) int {
	in := ship.Defaults()
	fs := newFlags("ship install", stderr)
	fs.StringVar(&in.Incoming, "incoming", in.Incoming, "pfship upload directory (untrusted)")
	fs.StringVar(&in.Dir, "dir", in.Dir, "live tree")
	fs.StringVar(&in.Signers, "signers", in.Signers, "ssh allowed_signers; missing refuses every bundle")
	fs.StringVar(&in.Namespace, "namespace", ship.Namespace, "ssh-keygen -Y verify -n: signature namespace this install expects")
	fs.StringVar(&in.Principal, "principal", ship.Principal, "ssh-keygen -Y verify -I: signer identity this install expects")
	fs.StringVar(&in.Log, "log", in.Log, "JSONL row per attempt")
	fs.StringVar(&in.VersionPath, "version-file", in.VersionPath, "last installed version")
	fs.StringVar(&in.PendingPath, "pending-file", ship.DefaultPendingPath, "armed confirm-or-revert state; pf ship confirm/deadman read the same path")
	fs.DurationVar(&in.PendingTTL, "confirm-deadline", ship.DefaultPendingTTL, "how long an upgrade has to be confirmed before pf ship deadman reverts it (PF_SHIP_CONFIRM_DEADLINE)")
	fs.StringVar(&in.ReleasesDir, "releases", ship.DefaultReleasesDir, "kept bundle+state.tar per version, for pf rollback's state guard and -with-state")
	fs.StringVar(&in.StateVersionPath, "state-version-file", ship.DefaultStateVersionPath, "on-disk state schema version")
	fs.StringVar(&in.EtcDir, "etc-dir", "/etc/pi-fortress", "snapshotted into state.tar")
	fs.StringVar(&in.LibDir, "lib-dir", "/var/lib/pi-fortress", "snapshotted into state.tar")
	skipDoctor := fs.Bool("skip-post-upgrade-doctor", false, "do not run pf doctor --post-upgrade after apply, and do not arm the confirm timer (testing only)")
	settleFor := postUpgradeSettleFlag(fs)
	pf := fs.String("pf", "/usr/local/sbin/pf", "pf binary that runs apply")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if v := os.Getenv("PF_SHIP_CONFIRM_DEADLINE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			in.PendingTTL = d
		} else {
			fmt.Fprintf(stderr, "pf ship install: PF_SHIP_CONFIRM_DEADLINE=%q: %v; using -confirm-deadline\n", v, err)
		}
	}
	in.Stderr = stderr
	in.Merge = map[string]func([]byte, []byte) ([]byte, bool, error){"vm/policy/sources.json": fetch.MergeSeed}
	in.Apply = func() error {
		cmd := exec.Command(applyPF(in.Dir, *pf), "apply")
		cmd.Stdout, cmd.Stderr = stderr, stderr
		return cmd.Run()
	}
	if !*skipDoctor {
		// The same binary that just applied examines itself. If an
		// upgrade broke DNS, the uplink or the fence sockets, pf rolls it
		// back immediately. The upgrade does not stay live until an
		// operator runs pf doctor by hand (docs/signed_ship.md,
		// "Confirm or revert").
		in.PostUpgradeCheck = func() error {
			cmd := exec.Command(applyPF(in.Dir, *pf), postUpgradeArgs(*settleFor)...)
			cmd.Stdout, cmd.Stderr = stderr, stderr
			return cmd.Run()
		}
	} else {
		in.PendingPath = ""
	}
	in.SelfLock = func() (func(), error) {
		l, err := admin.TryLock(shipLockPath)
		if err != nil {
			return nil, err
		}
		return l.Release, nil
	}
	in.Lock = func() (func(), error) {
		deadline := time.Now().Add(10 * time.Minute)
		for {
			l, err := admin.TryLock(admin.ApplyLockPath)
			if err == nil {
				return l.Release, nil
			}
			if !errors.Is(err, admin.ErrLocked) || time.Now().After(deadline) {
				return nil, err
			}
			time.Sleep(2 * time.Second)
		}
	}
	in.Alert = shipAlert(stderr)
	row, ok := in.Run()
	if ok && row.Result != "ok" {
		return 1
	}
	return 0
}

// postUpgradeSettleFlag adds -post-upgrade-settle to the ship install
// flags. It is for tests and labs. A short window makes a bad build
// roll back sooner. On a real box, a short window can roll back a good
// build whose units start slowly. Keep the default there.
func postUpgradeSettleFlag(fs *flag.FlagSet) *time.Duration {
	return fs.Duration("post-upgrade-settle", postUpgradeSettle, "settle window that pf doctor --post-upgrade gets after apply (tests and labs only)")
}

// postUpgradeArgs is the doctor command line that ship install runs
// after apply. It gives --settle only when the window is not the
// default. Thus the production command line does not change.
func postUpgradeArgs(settle time.Duration) []string {
	args := []string{"doctor", "--post-upgrade"}
	if settle != postUpgradeSettle {
		args = append(args, "--settle", settle.String())
	}
	return args
}

// shipAlert posts a ship row to the alert webhook.
//
// An alert that never left the box is more important to the operator
// than the install log that says that it left. This is the notification
// that a release changed what the box runs. The return value is a
// sentinel, never the webhook. That is why this line can print it.
// PostMessage has already written the redacted detail, and this line
// tells which alert went missing. Both go to the writer that pf got.
// Before, the summary went there and the detail went to the stderr of
// the process. That split one failure across two streams, and the half
// that named the cause was the half that got lost.
func shipAlert(stderr io.Writer) func(msg string) {
	return func(msg string) {
		a := alert.Defaults()
		a.Stderr = stderr
		if err := a.PostMessage(alert.LoadURL(a.PolicyDirs), msg); err != nil {
			fmt.Fprintln(stderr, "pf ship: the release alert was not delivered:", err)
		}
	}
}

// shipLockPath excludes a second installer. On purpose, it is not the
// apply lock. swap must release the apply lock, so that the apply that
// it triggers can take it. That leaves the fixed Work, Dir.new and
// Dir.prev paths without a guard for the remainder of the attempt.
const shipLockPath = "/var/lib/pi-fortress/ship.lock"

// applyPF selects the pf that belongs to the tree that is now at dir.
//
// apply installs /usr/local/sbin/pf from the tree as one of its first
// steps. Thus, after a defective release fails and the previous tree
// is swapped back, that path holds the binary that the rollback undoes.
// The re-apply of the rollback would then use that binary. This
// function resolves the path for each call. Thus each apply runs the
// binary of the generation that it applies, and the restored tree
// also restores its executable, together with all other files.
func applyPF(dir, installed string) string {
	own := filepath.Join(dir, "vm", "pi", "pf")
	if st, err := os.Stat(own); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
		return own
	}
	return installed
}

// shipInstallerFlags is the pending/log file set that pf ship confirm
// and pf ship deadman share with pf ship install. All three must agree
// on the location of the armed state and the log. If not, a confirm on
// one path would not touch the pending file of an install at another.
// The alert hook is the same as that of pf ship install.
func shipInstallerFlags(fs *flag.FlagSet, stderr io.Writer) *ship.Installer {
	in := ship.Defaults()
	fs.StringVar(&in.Dir, "dir", in.Dir, "live tree")
	fs.StringVar(&in.VersionPath, "version-file", in.VersionPath, "last installed version")
	fs.StringVar(&in.Log, "log", in.Log, "JSONL row per attempt")
	fs.StringVar(&in.PendingPath, "pending-file", ship.DefaultPendingPath, "armed confirm-or-revert state")
	fs.StringVar(&in.ReleasesDir, "releases", ship.DefaultReleasesDir, "kept bundle+state.tar per version")
	in.Stderr = stderr
	in.Alert = shipAlert(stderr)
	return in
}

// shipConfirmWait is how long pf ship confirm waits for the ship lock
// by default. An install holds the lock for minutes. It can wait up to
// 10 min for the apply lock. The full apply downloads the feeds. pf doctor
// --post-upgrade gets up to 90 s. A failed apply adds the apply of the
// rollback. pi-fortress-ship.service stops an install after 45 min
// (TimeoutStartSec). Thus no install holds the lock for longer. The
// dead-man window does not limit the wait: the install arms it only at
// its end, and the confirm examines the deadline after the wait.
const shipConfirmWait = 45 * time.Minute

// shipLockPoll is how frequently a waiting pf ship confirm tries the
// ship lock again. It is a variable, so that a test can make it short.
var shipLockPoll = time.Second

// runShipConfirm is pf ship confirm: disarm the dead-man timer of an
// upgrade that has proven itself. It does nothing more than remove the
// pending file and log that it did.
//
// make pi-ship returns after the upload, while the install still runs.
// On 2026-10-29, a confirm typed at once found the ship lock held and
// failed. Now it waits for the holder. Then it confirms only what the
// holder left pending (shipWaitOutcome).
func runShipConfirm(args []string, _, stderr io.Writer) int {
	fs := newFlags("ship confirm", stderr)
	in := shipInstallerFlags(fs, stderr)
	wait := fs.Duration("wait", shipConfirmWait, "how long to wait for a ship install, rollback or dead-man run that holds the ship lock (0: fail at once)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	// The mark comes before the first try of the lock. Thus the rows of
	// a holder that this run waits for are all after it.
	mark := jsonl.ShipLogSize(in.Log)
	release, waited, err := shipExclusiveWait(in, *wait, func() {
		fmt.Fprintf(stderr, "pf ship confirm: waiting for the ship install to finish (up to %s; Ctrl-C stops only this wait)\n", *wait)
	})
	if err != nil {
		return fail(stderr, fmt.Errorf("pf ship confirm: %w", err))
	}
	defer release()
	if waited {
		done, err := shipWaitOutcome(in, jsonl.ShipsAfter(in.Log, mark), time.Now())
		if err != nil {
			return fail(stderr, fmt.Errorf("pf ship confirm: %w", err))
		}
		if done != "" {
			fmt.Fprintln(stderr, "pf ship confirm:", done)
			return 0
		}
	}
	row, ok, err := in.Confirm()
	if err != nil {
		return fail(stderr, err)
	}
	if !ok {
		fmt.Fprintln(stderr, "pf ship confirm: nothing pending")
		return 0
	}
	fmt.Fprintf(stderr, "pf ship confirm: version %d sha=%s confirmed\n", row.Version, row.SHA)
	return 0
}

// shipWaitOutcome decides what a pf ship confirm that waited for the
// ship lock can do now. The caller holds the lock. rows are what the
// holder logged during the wait. A busy row is an install that found
// the lock held and changed nothing, so it does not count.
//   - No row: the holder changed nothing (for example, a dead-man run
//     with nothing due). The usual confirm follows.
//   - ok: the usual confirm follows only if ship.pending names that
//     version and its deadline has not passed. Nothing pending: the
//     usual confirm says so.
//   - confirm: another confirm did the work. done says so.
//   - Any other row: a failed install, a rollback or a dead-man revert.
//     err says what occurred. Nothing is confirmed.
func shipWaitOutcome(in *ship.Installer, rows []jsonl.Ship, now time.Time) (done string, err error) {
	var last *jsonl.Ship
	for i := range rows {
		if rows[i].Result != "busy" {
			last = &rows[i]
		}
	}
	if last == nil {
		return "", nil
	}
	path := in.PendingPath
	if path == "" {
		path = ship.DefaultPendingPath
	}
	switch last.Result {
	case "ok":
		p, ok, err := ship.ReadPending(path)
		switch {
		case err != nil:
			return "", fmt.Errorf("version %d sha=%s is installed, but %v; nothing confirmed", last.Version, last.SHA, err)
		case !ok:
			return "", nil
		case p.Version != last.Version:
			return "", fmt.Errorf("version %d sha=%s is installed, but ship.pending names version %d; nothing confirmed", last.Version, last.SHA, p.Version)
		case !now.Before(p.Deadline):
			return "", fmt.Errorf("version %d sha=%s is installed, but its dead-man deadline %s has passed; nothing confirmed, pf ship deadman reverts it to %d", last.Version, last.SHA, p.Deadline.Format(time.RFC3339), p.PrevVersion)
		}
		return "", nil
	case "confirm":
		return fmt.Sprintf("version %d sha=%s was confirmed by another pf ship confirm during this wait", last.Version, last.SHA), nil
	}
	return "", fmt.Errorf("nothing confirmed: during this wait, ship.jsonl got %s version=%d sha=%s: %s; %s", last.Result, last.Version, last.SHA, last.Reason, pendingNow(path))
}

// pendingNow tells what ship.pending holds, for a confirm that did not
// confirm. An older upgrade can still be armed after an install that
// failed before its swap.
func pendingNow(path string) string {
	p, ok, err := ship.ReadPending(path)
	switch {
	case err != nil:
		return err.Error()
	case !ok:
		return "nothing is pending"
	}
	return fmt.Sprintf("ship.pending still names version %d (deadline %s)", p.Version, p.Deadline.Format(time.RFC3339))
}

// runShipDeadman is pf ship deadman. ship-deadman.timer runs it
// (OnBootSec/OnUnitActiveSec, persistent). If the deadline of an armed
// upgrade has passed with no confirm, roll back to the version that it
// replaced. Nothing pending, or a deadline not yet due, is a silent
// no-op. That is the usual case, and it runs each minute.
func runShipDeadman(args []string, _, stderr io.Writer) int {
	fs := newFlags("ship deadman", stderr)
	in := shipInstallerFlags(fs, stderr)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	// An install, a rollback or another dead-man run in progress owns the
	// tree. The timer runs again in one minute.
	release, err := shipExclusive(in)
	if errors.Is(err, admin.ErrLocked) {
		return 0
	}
	if err != nil {
		return fail(stderr, fmt.Errorf("pf ship deadman: %w", err))
	}
	defer release()
	in.Lock = func() (func(), error) {
		l, err := admin.TryLock(admin.ApplyLockPath)
		if err != nil {
			return nil, err
		}
		return l.Release, nil
	}
	pf := "/usr/local/sbin/pf"
	in.Apply = func() error {
		cmd := exec.Command(applyPF(in.Dir, pf), "apply")
		cmd.Stdout, cmd.Stderr = stderr, stderr
		return cmd.Run()
	}
	row, ok, err := in.Deadman(time.Now())
	if err != nil {
		return fail(stderr, err)
	}
	if !ok {
		return 0
	}
	fmt.Fprintf(stderr, "pf ship deadman: version %d: %s\n", row.Version, row.Reason)
	return 0
}

// shipExclusive holds the ship lock for a full confirm, dead-man run or
// rollback. pf ship install holds the same lock as SelfLock. Each of
// them reads ship.pending and .prev, and then acts on what it read. On
// 2026-09-27, the dead-man timer and a pf ship deadman run by hand both
// read the same pending upgrade on the Pi. One of them found that the
// other had already taken .prev. The lock is beside the pending file.
// With the default path, that is shipLockPath itself.
func shipExclusive(in *ship.Installer) (func(), error) {
	path := shipLockPath
	if in.PendingPath != "" {
		path = filepath.Join(filepath.Dir(in.PendingPath), filepath.Base(shipLockPath))
	}
	l, err := admin.TryLock(path)
	if errors.Is(err, admin.ErrLocked) {
		return nil, fmt.Errorf("another ship install, rollback or dead-man run holds %s: %w", path, err)
	}
	if err != nil {
		return nil, err
	}
	return l.Release, nil
}

// shipExclusiveWait is shipExclusive, but while another run holds the
// lock, it tries again until bound has passed. It calls waiting one time,
// when it starts to wait. waited true tells the caller that a holder
// ran before it. Thus the state can differ from the state at the start.
func shipExclusiveWait(in *ship.Installer, bound time.Duration, waiting func()) (release func(), waited bool, err error) {
	release, err = shipExclusive(in)
	if !errors.Is(err, admin.ErrLocked) || bound <= 0 {
		return release, false, err
	}
	waiting()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		time.Sleep(min(shipLockPoll, time.Until(deadline)))
		release, err = shipExclusive(in)
		if !errors.Is(err, admin.ErrLocked) {
			return release, true, err
		}
	}
	return nil, true, fmt.Errorf("the ship lock is still held after %s; nothing confirmed. The dead-man window starts only when the install ends. Look at journalctl -u pi-fortress-ship, then run pf ship confirm again", bound)
}

// runShipLint is release-lint: refuse a bundle that ships the lab marker file or an
// unconditional -lab-echo. scripts/release.sh runs it on each bundle
// that make release builds, before it signs a bundle or SHA256SUMS.
func runShipLint(args []string, _, stderr io.Writer) int {
	fs := newFlags("ship lint", stderr)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: pf ship lint FILE")
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return fail(stderr, err)
	}
	defer f.Close()
	if err := ship.LintBundle(f); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stderr, "pf ship lint: %s ok\n", fs.Arg(0))
	return 0
}
