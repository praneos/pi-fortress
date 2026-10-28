// Package cli is the pf command table and dispatch: one entry per subcommand,
// its flags, and the daemon and tool entry points behind it. cmd/pf calls
// Main.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/tui"
)

type Command struct {
	Name string
	Help string
	Run  func(args []string, stdout, stderr io.Writer) int
}

var aliases = map[string]string{
	"egress": "engine",
}

func Commands() []Command {
	cmds := []Command{
		{"apply", "refresh feeds (pf feeds run), compile policy, load nft + dnsmasq, restart fence (--local: nft + dnsmasq only)", runApply},
		{"backup", "policy lists + env files as a tar.gz on stdout; no secrets, no CA", runBackup},
		{"restore", "read a backup: a diff by default, -apply to write it", runRestore},
		{"ship", "bundle (desktop) | install|confirm|deadman (Pi, root): signed tree ship without sudo", runShip},
		{"rollback", "swap .prev back in, the release before this one; -with-state, -force (root)", runRollback},
		{"install", "root: fresh box -> running gateway from a signed release bundle (install.sh)", runInstall},
		{"upgrade", "root: fetch, verify and ship a newer release bundle; -confirm disarms the dead-man timer", runUpgrade},
		{"dns", "forwarding resolver for one segment: sinkhole, nft set, query log (-check validates)", runDNS},
		{"doctor", "walk each segment: link, address, resolver, leases, DNS", runDoctor},
		{"status", "addresses, routes, nft sets, services", runStatus},
		{"fetch", "download blocklist feeds (not as root; pi-fortress-feeds.service runs it as pf-feeds)", runFetch},
		{"feeds", "run|import (root): the feed download as pf-feeds, then the checked import of its lists", runFeeds},
		{"compile", "merge local + generated - never_block into nft/dnsmasq files", runCompile},
		{"render", "house.env + segments.d + DoT keys -> nftables.conf, apply.env", runRender},
		{"nftsets", "save|restore|policy: carry the resolved-address sets across a ruleset reload", runNFTSets},
		{"observe", "once|run|show|reset: DNS + conntrack first-seen", runObserve},
		{"monitor", "once|run|show|avg: cpu, memory, temp, Wi-Fi, per-process CPU/RSS", runMonitor},
		{"alert", "once|run|show|watch: strip.jsonl -> webhook; wg: handshake age", runAlert},
		{"enroll", "mint|list|peek|migrate|delete|seal|unseal|state slotted secrets", runEnroll},
		{"unlock", "enter the passphrase that opens the sealed credential store (-state, -lock)", runUnlock},
		{"claim", "issue a one-time claim code for a slot, without the TUI (-slot)", runClaim},
		{"tui", "management screens at the seat or over ssh (sudo)", runTUI},
		{"www", "agent-NIC HTTP: setup.sh + ca.pem", runWWW},
		{"engine", "TLS engine on :8080 (-init-ca mints the CA; ca status|rotate|promote|retire changes it)", runEngine},
		{"broker", "credential broker on a unix socket", runBroker},
	}
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })
	return cmds
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: pf <command> [flags] [args]")
	fmt.Fprintln(w)
	for _, c := range Commands() {
		fmt.Fprintf(w, "  %-9s %s\n", c.Name, c.Help)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "pf <command> -h for flags")
}

func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	name := args[0]
	switch name {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "version", "-version", "--version":
		printVersion(stdout)
		return 0
	}
	if a, ok := aliases[name]; ok {
		name = a
	}
	for _, c := range Commands() {
		if c.Name == name {
			return c.Run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "pf: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("pf "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) (int, bool) {
	err := fs.Parse(args)
	if err == nil {
		return 0, true
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0, false
	}
	return 2, false
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, err)
	return 1
}

// applyLockPath is admin.ApplyLockPath in a variable. Thus a test can
// examine the verbs that take it without /run/pi-fortress and root.
// Each verb in this package that writes the configuration tree must use
// this one name. If two verbs hold two different locks, it is the same
// as no lock.
var applyLockPath = admin.ApplyLockPath

// /opt/pi-fortress is the tree that pf ship and pf install publish.
// provision.sh makes the copy under /usr/local/lib one time and never
// refreshes it.
var scriptDirs = []string{"/vagrant/vm/pi", "/opt/pi-fortress/vm/pi", "/usr/local/lib/pi-fortress"}

// scriptSearch is scriptDirs with the directory of this pf in front of
// it. A pf from a signed release is beside the apply.sh of that release.
// It must run that apply.sh. pf ship already selects the new binary from
// the staged tree. But before, the search used only the fixed installed
// locations. Thus the new binary ran the apply.sh of the previous
// generation. That apply.sh installs its own pf again and undoes the swap.
// An ordinary installed pf has no apply.sh beside it and falls through.
func scriptSearch() []string {
	exe, err := os.Executable()
	if err != nil {
		return scriptDirs
	}
	return scriptSearchFrom(exe)
}

// scriptSearchFrom is the pure half. Thus a test can assert the order
// without a fake os.Executable.
func scriptSearchFrom(exe string) []string {
	return append([]string{filepath.Dir(exe)}, scriptDirs...)
}

// apply.sh and status.sh are still shell. Replace the process, so that
// signals, tty and exit code go directly through. If exec itself is
// refused, use a child process as a fallback.
func runScript(name string, args []string, stderr io.Writer) int {
	for _, dir := range scriptSearch() {
		p := dir + "/" + name + ".sh"
		if _, err := os.Stat(p); err != nil {
			continue
		}
		bash, err := exec.LookPath("bash")
		if err != nil {
			return fail(stderr, err)
		}
		argv := append([]string{bash, p}, args...)
		if err := syscall.Exec(bash, argv, os.Environ()); err == nil {
			return 0
		}
		cmd := exec.Command(bash, append([]string{p}, args...)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return fail(stderr, err)
		}
		return 0
	}
	fmt.Fprintf(stderr, "pf %s: %s.sh not found in %v\n", name, name, scriptSearch())
	return 1
}

func applyUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: pf apply [--local | --refresh | --render-nft]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  (no flag)     fetch feeds, compile policy, load nft + dnsmasq, restart the fence")
	fmt.Fprintln(w, "  --local       compile and reload nft + dnsmasq only; no feed fetch")
	fmt.Fprintln(w, "  --refresh     --local plus the feed download; the unattended timer path")
	fmt.Fprintln(w, "  --render-nft  print the ruleset that would be loaded and exit, changing nothing")
}

// checkApplyArgs is the pure half of the refusal. apply is the most
// destructive operation of pf, and it gets its argv raw. Before, a word
// that nobody validated went to a shell loop. That loop ignored words
// that it did not know and ran a full apply. This function examines the
// full invocation. Thus pf answers -h and a typo before it takes the
// production lock and before the exec. Neither one costs the operator
// a reconfigured box or a held lock.
func checkApplyArgs(args []string) (help bool, err error) {
	mode := ""
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			return true, nil
		case "--local", "--refresh", "--render-nft":
			if mode != "" && mode != a {
				return false, fmt.Errorf("pf apply: %s and %s are different modes; pick one", mode, a)
			}
			mode = a
		default:
			return false, fmt.Errorf("pf apply: unknown argument %q; pf apply -h lists what it takes", a)
		}
	}
	return false, nil
}

// The lock descriptor has no CLOEXEC. Thus it stays open through the
// exec into apply.sh, and it is released when the script exits. If the
// lock is held, pf exits 75 (EX_TEMPFAIL), the same as apply.sh.
// fetch.service retries on that code.
func runApply(args []string, stdout, stderr io.Writer) int {
	help, err := checkApplyArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		applyUsage(stderr)
		return 2
	}
	if help {
		applyUsage(stdout)
		return 0
	}
	lock, err := admin.TryLock(applyLockPath)
	if err != nil {
		fail(stderr, fmt.Errorf("pf apply: %w", err))
		if errors.Is(err, admin.ErrLocked) {
			return 75
		}
		return 1
	}
	defer lock.Release()
	return runScript("apply", args, stderr)
}

// tuiCheck is the pure part of pf tui's start-up refusal: a message
// and exit code, or ok.
func tuiCheck(uid int, inTTY, outTTY bool) (string, int) {
	switch {
	case uid != 0:
		return "pf tui: run it as root: sudo pf tui", 2
	case !inTTY || !outTTY:
		return "pf tui: stdin and stdout must be a terminal", 2
	}
	return "", 0
}

// runTUI has no -policy flag on purpose. apply.sh selects the policy
// tree itself. It would apply nothing that a TUI saved to another tree.
func runTUI(args []string, _, stderr io.Writer) int {
	fs := newFlags("tui", stderr)
	idle := fs.Duration("idle", 15*time.Minute, "exit after this long without a keypress (0 = never)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *idle < 0 {
		fmt.Fprintln(stderr, "pf tui: -idle must not be negative")
		return 2
	}
	if msg, code := tuiCheck(os.Getuid(), tui.IsTerminal(os.Stdin.Fd()), tui.IsTerminal(os.Stdout.Fd())); code != 0 {
		fmt.Fprintln(stderr, msg)
		return code
	}
	term, err := tui.Open(os.Stdin, os.Stdout)
	if err != nil {
		return fail(stderr, err)
	}
	app := tui.New(admin.Defaults(), term)
	app.Idle = *idle
	if err := app.Run(); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func runStatus(args []string, _, stderr io.Writer) int {
	return runScript("status", args, stderr)
}
