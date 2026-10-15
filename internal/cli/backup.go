package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/audit"
	"pi-fortress/internal/backup"
	"pi-fortress/internal/base"
	"pi-fortress/internal/tui"
)

const etcDir = "/etc/pi-fortress"

func runBackup(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("backup", stderr)
	policy := fs.String("policy", "", "policy directory (default: as apply resolves it)")
	etc := fs.String("etc", etcDir, "configuration directory")
	out := fs.String("out", "", "write here instead of stdout")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	c := backup.Config{EtcDir: *etc, PolicyDir: *policy}
	if c.PolicyDir == "" {
		c.PolicyDir = base.PolicyDir()
	}

	w := io.Writer(os.Stdout)
	var staged *os.File
	if *out == "" {
		// A backup on the SD card that is about to fail is not a backup.
		// Output to stdout makes the useful form the default:
		// ssh pi sudo pf backup > pf-backup.tar.gz. A tarball that goes
		// into a terminal helps nobody.
		if tui.IsTerminal(os.Stdout.Fd()) {
			return fail(stderr, fmt.Errorf("pf backup: stdout is a terminal; redirect it or pass -out FILE"))
		}
	} else {
		// The file that this writes over is usually the last good backup.
		// An operator usually takes a backup immediately before a risky step.
		// If the code truncates the destination first and then cannot read a
		// source, the operator has neither archive. Thus the code builds the
		// new archive beside the old one. It renames the new archive into
		// place only when it is complete.
		f, err := os.CreateTemp(filepath.Dir(*out), ".pf-backup-")
		if err != nil {
			return fail(stderr, err)
		}
		defer func() {
			if staged != nil {
				staged.Close()
				os.Remove(staged.Name())
			}
		}()
		staged = f
		w = f
	}
	man, err := c.Write(w)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf backup: %w", err))
	}
	if staged != nil {
		// A buffered filesystem reports a write that did not fit at Close.
		// Thus the error from Close is the error of the archive. Do not
		// discard it on return.
		if err := staged.Chmod(0600); err != nil {
			return fail(stderr, err)
		}
		if err := staged.Close(); err != nil {
			return fail(stderr, fmt.Errorf("pf backup: %w", err))
		}
		if err := os.Rename(staged.Name(), *out); err != nil {
			return fail(stderr, err)
		}
		staged = nil
	}
	fmt.Fprintf(stderr, "pf backup: %d files from %s and %s\n", len(man.Files), c.EtcDir, c.PolicyDir)
	for _, e := range man.Excluded {
		fmt.Fprintf(stderr, "  not included: %s (%s)\n", e.What, e.Why)
	}
	return 0
}

func runRestore(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("restore", stderr)
	in := fs.String("in", "", "archive to read, or - for stdin")
	policy := fs.String("policy", "", "policy directory (default: as apply resolves it)")
	etc := fs.String("etc", etcDir, "configuration directory")
	apply := fs.Bool("apply", false, "write the files; without it nothing is changed")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *in == "" {
		return fail(stderr, fmt.Errorf("pf restore: -in is required"))
	}
	r := io.Reader(os.Stdin)
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return fail(stderr, err)
		}
		defer f.Close()
		r = f
	}
	arc, err := backup.Read(r)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf restore: %w", err))
	}
	pol := *policy
	if pol == "" {
		pol = base.PolicyDir()
	}
	// Plan reads the live tree to find what changes. Apply renames a
	// batch of files into it. A pf apply between the two compiles a
	// generation that is part archive and part the old tree. Nobody chose
	// that generation, and no backup contains it. Thus the plan and the
	// write are one critical section, under the lock that apply takes.
	// The dry run stays outside the lock: it writes nothing. To refuse an
	// inspection because an apply runs gives no safety.
	//
	// admin.TryLock is not re-entrant. Each call opens a new fd, which is a
	// new open file description. Thus a second acquire in this process gets
	// EWOULDBLOCK. But no code below takes the lock: Plan, Apply and the
	// audit append never touch it. At its end, restore tells the operator
	// to run pf apply. It does not run pf apply itself. If the lock is held,
	// restore exits 75 (EX_TEMPFAIL), the same as pf apply. It does not wait.
	if *apply {
		lock, err := admin.TryLock(applyLockPath)
		if err != nil {
			fail(stderr, fmt.Errorf("pf restore: %w", err))
			if errors.Is(err, admin.ErrLocked) {
				return 75
			}
			return 1
		}
		defer lock.Release()
	}
	plan, err := arc.Plan(*etc, pol)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf restore: %w", err))
	}

	fmt.Fprintf(stdout, "archive taken %s on %s", arc.Manifest.Taken, arc.Manifest.Host)
	if arc.Manifest.Revision != "" {
		fmt.Fprintf(stdout, " by pf %.12s", arc.Manifest.Revision)
		if arc.Manifest.Dirty {
			fmt.Fprint(stdout, " (modified tree)")
		}
	}
	fmt.Fprintln(stdout)
	for _, w := range plan.Warnings {
		fmt.Fprintln(stdout, "warning: "+w)
	}
	for _, c := range plan.Changes {
		fmt.Fprintf(stdout, "  %-8s %s\n", c.Kind, c.Path)
	}
	changed := plan.Changed()
	for _, e := range arc.Manifest.Excluded {
		fmt.Fprintf(stdout, "  not in this archive: %s -> %s\n", e.What, e.Redo)
	}
	if !*apply {
		fmt.Fprintf(stdout, "%d files would change; nothing written. Re-run with -apply.\n", len(changed))
		return 0
	}
	done, aerr := plan.Apply()
	logRestore(*in, arc, done, aerr)
	if aerr != nil {
		return fail(stderr, fmt.Errorf("pf restore: wrote %d of %d files: %w", len(done), len(changed), aerr))
	}
	fmt.Fprintf(stdout, "%d files written. Run pf apply to compile and load them.\n", len(done))
	return 0
}

// logRestore is the first CLI path that writes to the audit log. Restore
// is the correct path to start with. It can undo a security decision, for
// example a removed never_block entry, or a list from before a threat was
// added. It does this with files that look the same as files that an
// operator wrote by hand. It leaves no other trace of the restore.
func logRestore(src string, arc *backup.Archive, done []backup.Change, err error) {
	e := audit.Entry{
		Verb:  "restore",
		Role:  "admin",
		Actor: audit.Actor(nil, os.Getuid()),
		OK:    err == nil,
		Args: map[string]string{
			"from":  src,
			"taken": arc.Manifest.Taken,
			"host":  arc.Manifest.Host,
			"files": fmt.Sprint(len(done)),
		},
	}
	if err != nil {
		e.Err = err.Error()
	}
	_ = audit.New(audit.DefaultPath).Append(e)
}
