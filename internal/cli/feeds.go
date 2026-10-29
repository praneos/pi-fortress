package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/base"
	"pi-fortress/internal/feedstage"
)

// pf feeds is the root half of the feed download. pf feeds run copies the
// inputs of the download, starts pi-fortress-feeds.service (pf fetch as
// pf-feeds, no capability) and waits for it, then imports the staged lists
// into generated/ through the check of internal/feedstage. Root does not
// download a feed and does not parse a feed body: it reads only the staged
// lines. pf apply and the Feeds screen of the TUI call it.

const feedsUsage = "usage: pf feeds run [-policy DIR] [-fresh DURATION] | pf feeds import -run ID [-policy DIR]"

// feedsHost is what pf feeds uses of the box. A test replaces it.
type feedsHost struct {
	geteuid  func() int
	inputDir string
	stateDir string
	// lock takes the apply lock, or uses the descriptor that pf apply or
	// the TUI gave to this process.
	lock func() (release func(), err error)
	// start runs systemctl start of the download unit. A oneshot start
	// returns when the service has ended, and fails when it failed.
	start func() ([]byte, error)
	// uid gives the uid of pf-feeds, the owner of each staged file.
	uid func() (int, error)
}

var newFeedsHost = func() feedsHost {
	return feedsHost{
		geteuid:  os.Geteuid,
		inputDir: feedstage.InputDir,
		stateDir: feedstage.StateDir,
		lock:     func() (func(), error) { return applyLockOrInherited(applyLockPath) },
		start: func() ([]byte, error) {
			return exec.Command("systemctl", "start", feedstage.Unit).CombinedOutput()
		},
		uid: func() (int, error) {
			u, err := user.Lookup(feedstage.Account)
			if err != nil {
				return -1, err
			}
			return strconv.Atoi(u.Uid)
		},
	}
}

func runFeeds(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("feeds", stderr)
	policy := fs.String("policy", "", "policy directory")
	fresh := fs.Duration("fresh", 0, "run: a feed whose last good copy is younger than this is not downloaded again; 0 always downloads")
	run := fs.String("run", "", "import: the run id of the staged set")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, feedsUsage)
	if !ok {
		return code
	}
	h := newFeedsHost()
	if h.geteuid() != 0 {
		fmt.Fprintf(stderr, "pf feeds: root only; the download itself runs as %s in %s\n", feedstage.Account, feedstage.Unit)
		return 2
	}
	p := *policy
	if p == "" {
		p = base.PolicyDir()
	}
	switch {
	case verb == "run" && *run == "" && *fresh >= 0 && *fresh <= 24*time.Hour:
		return feedsRun(h, p, *fresh, stdout, stderr)
	case verb == "import" && *fresh == 0 && feedstage.ValidRun(*run):
		release, err := h.lock()
		if err != nil {
			return lockExit(stderr, err)
		}
		defer release()
		return feedsImport(h, p, *run, nil, time.Now(), stdout, stderr)
	}
	fmt.Fprintln(stderr, feedsUsage)
	return 2
}

func lockExit(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "pf feeds: %v\n", err)
	if errors.Is(err, admin.ErrLocked) {
		return 75
	}
	return 1
}

// feedsRun is pf feeds run: inputs, request, the unit, the import.
func feedsRun(h feedsHost, policy string, fresh time.Duration, stdout, stderr io.Writer) int {
	release, err := h.lock()
	if err != nil {
		return lockExit(stderr, err)
	}
	defer release()
	start := time.Now()
	run, err := feedstage.NewRun()
	if err == nil {
		err = writeFeedInputs(h.inputDir, policy, feedstage.Request{Fresh: fresh, Run: run})
	}
	if err != nil {
		fmt.Fprintf(stderr, "pf feeds run: %v\n", err)
		return 1
	}
	out, startErr := h.start()
	if startErr != nil {
		msg := strings.TrimSpace(admin.Printable(string(out)))
		fmt.Fprintf(stderr, "pf feeds run: %s: %v %s\n", feedstage.Unit, startErr, msg)
	}
	return feedsImport(h, policy, run, startErr, start, stdout, stderr)
}

// feedsImport imports the staged set of run into generated/, prints the
// report and writes the audit entry. startErr is the result of the unit,
// or nil.
func feedsImport(h feedsHost, policy, run string, startErr error, start time.Time, stdout, stderr io.Writer) int {
	gen := filepath.Join(policy, "generated")
	fields := map[string]string{"policy": policy, "out": gen}
	res, err := importStage(h, policy, gen, run)
	switch {
	case errors.Is(err, feedstage.ErrNoRun):
		res.Report = []string{"FAIL download: " + feedstage.Unit + " wrote no set for this run; the lists stay as they were (journalctl -u pi-fortress-feeds)"}
		if werr := feedstage.WriteReport(gen, res.Report); werr != nil {
			fmt.Fprintf(stderr, "pf feeds: %v\n", werr)
		}
		fields["stage"] = "none"
	case errors.Is(err, feedstage.ErrRefused):
		fields["refused"] = res.Refused
	case err != nil:
		// Any other error (the stage is not a directory, the account is
		// gone, a write failed): the report must not keep the OK lines of
		// an earlier run. The reason is fixed text; the error itself goes
		// to stderr and the audit entry.
		res.Report = []string{"FAIL import: the import of the stage stopped on an error; pf feeds run prints the error"}
		if werr := feedstage.WriteReport(gen, res.Report); werr != nil {
			fmt.Fprintf(stderr, "pf feeds: %v\n", werr)
		}
		fields["stage"] = "error"
	}
	if startErr != nil {
		fields["unit"] = "failed"
		if err == nil {
			err = fmt.Errorf("%s failed: %w", feedstage.Unit, startErr)
		}
	}
	if res.IPs >= 0 {
		fields["ips"] = strconv.Itoa(res.IPs)
	}
	if res.Domains >= 0 {
		fields["domains"] = strconv.Itoa(res.Domains)
	}
	for verb, n := range reportCounts(res.Report) {
		fields[verb] = strconv.Itoa(n)
	}
	logTool("fetch", fields, time.Since(start), err)
	for _, l := range res.Report {
		fmt.Fprintln(stdout, feedstage.Clean(l))
	}
	if res.Imported {
		fmt.Fprintf(stdout, "imported %s ips, %s domains -> %s\n", orNone(res.IPs), orNone(res.Domains), gen)
	}
	if err != nil {
		fmt.Fprintf(stderr, "pf feeds: %s\n", feedstage.Clean(err.Error()))
		return 1
	}
	return 0
}

func importStage(h feedsHost, policy, gen, run string) (feedstage.Result, error) {
	uid, err := h.uid()
	if err != nil {
		return feedstage.Result{IPs: -1, Domains: -1}, fmt.Errorf("the account %s: %w", feedstage.Account, err)
	}
	limits, err := feedstage.ReadLimits(policy)
	if err != nil {
		return feedstage.Result{IPs: -1, Domains: -1}, err
	}
	return feedstage.Import(feedstage.Config{StateDir: h.stateDir, OutDir: gen, Limits: limits, Run: run, UID: uid})
}

func orNone(n int) string {
	if n < 0 {
		return "unchanged"
	}
	return strconv.Itoa(n)
}

// reportCounts counts the FAIL, STALE and TRUNCATED lines of a report,
// for the audit entry, under the names that pf fetch used.
func reportCounts(report []string) map[string]int {
	names := map[string]string{"FAIL": "fails", "STALE": "stale", "TRUNCATED": "truncated"}
	out := map[string]int{}
	for _, l := range report {
		verb, _, _ := strings.Cut(l, " ")
		if name, ok := names[verb]; ok {
			out[name]++
		}
	}
	return out
}

// writeFeedInputs writes the inputs of the download into dir: a copy of
// each file of feedstage.InputFiles that policy has (a file that policy no
// longer has goes), the request, and one time the seed. dir is root's: the
// unit reads it through a read-only bind.
func writeFeedInputs(dir, policy string, req feedstage.Request) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	for _, name := range feedstage.InputFiles() {
		b, err := os.ReadFile(filepath.Join(policy, name))
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := writeFileAtomic(dir, name, b, time.Time{}); err != nil {
			return err
		}
	}
	if err := seedCopies(dir, filepath.Join(policy, "generated", "feeds")); err != nil {
		return err
	}
	return writeFileAtomic(dir, feedstage.RequestFile, req.Bytes(), time.Time{})
}

// seedCopies copies the last-good copies of an earlier release (feeds/ in
// generated/) into dir/seed, one time. The download reads a copy there
// when its own cache has none. Each copy keeps its time, which is the age
// of the copy.
func seedCopies(dir, from string) error {
	seed := filepath.Join(dir, feedstage.SeedName)
	if _, err := os.Lstat(seed); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ents, err := os.ReadDir(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(dir, ".seed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".list") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := writeFileAtomic(tmp, e.Name(), b, info.ModTime()); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	return os.Rename(tmp, seed)
}

// writeFileAtomic writes name in dir with one rename, mode 0644. A
// non-zero mtime is set on the file.
func writeFileAtomic(dir, name string, b []byte, mtime time.Time) error {
	f, err := os.CreateTemp(dir, ".in-")
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	err = errors.Join(werr, f.Close(), os.Chmod(f.Name(), 0644))
	if err == nil && !mtime.IsZero() {
		err = os.Chtimes(f.Name(), mtime, mtime)
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// applyLockOrInherited holds the apply lock for pf feeds. pf apply and the
// TUI take the lock and then start pf feeds, which inherits the open
// descriptor (admin.TryLock opens it without CLOEXEC). That descriptor is
// then the lock: a second flock on a new descriptor would fail against
// its own parent. With no such descriptor, pf feeds takes the lock itself,
// so a pf feeds run by hand cannot run beside an apply.
func applyLockOrInherited(path string) (func(), error) {
	if inheritedLock(path) {
		return func() {}, nil
	}
	l, err := admin.TryLock(path)
	if err != nil {
		return nil, err
	}
	return l.Release, nil
}

// inheritedLock says if this process has a descriptor open on the lock
// file at path, and the lock is held.
func inheritedLock(path string) bool {
	want, err := os.Lstat(path)
	if err != nil || !want.Mode().IsRegular() {
		return false
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	for _, e := range ents {
		got, err := os.Stat(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && os.SameFile(want, got) {
			return admin.Held(path)
		}
	}
	return false
}
