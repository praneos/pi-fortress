// Package admin is the data and action layer behind pf tui. Its scope is
// files under /etc/pi-fortress and /var/lib/pi-fortress, unit state, and
// the few subprocesses that an operator needs. It has no terminal and no
// listener.
package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/monitor"
	"pi-fortress/internal/secrets"

	"pi-fortress/internal/base"
)

const (
	ApplyLockPath  = "/run/pi-fortress/apply.lock"
	RebootFlagPath = "/var/run/reboot-required"
	HouseDNSUnit   = "pi-fortress-dns-house"
	maxTailBytes   = 1 << 20
)

const (
	// AgentDNSUnit is pf dns. It serves all segments. Before, dnsmasq also had
	// a unit here, while dnsmasq could serve DNS. Apply deletes that unit.
	AgentDNSUnit = "pi-fortress-dns-agent-go"
	stubDNSUnit  = "pi-fortress-dns-stub@"
)

// Units is the list for a box with no DoT stubs. The list that the code
// queries comes from Config.units, because the stubs that exist depend on
// what apply wrote.
var Units = []string{
	"nftables", AgentDNSUnit, HouseDNSUnit,
	"pi-fortress-engine", "pi-fortress-broker", "pi-fortress-www",
	"pi-fortress-observe", "pi-fortress-monitor", "pi-fortress-alert",
}

// etcDir is the directory where apply puts the per-instance stub config
// files. It comes from house.env and is not hard-coded. Thus a test, or a
// lab that points at a checkout, sees its own tree.
func (c *Config) etcDir() string {
	if c.HouseEnv != "" {
		return filepath.Dir(c.HouseEnv)
	}
	return "/etc/pi-fortress"
}

// units is the health list for this box, not for the default box. The
// fixed list did not include the DoT stubs. Thus a failed stub was not
// visible on the screen that an operator opens when DNS does not work.
func (c *Config) units() []string {
	out := make([]string, 0, len(Units)+2)
	for _, u := range Units {
		out = append(out, u)
		if u != AgentDNSUnit {
			continue
		}
		// apply writes one config file for each stub instance that it configures.
		// It removes these files when it removes the stubs. Thus a file is the
		// sign that its instance exists.
		for _, inst := range []string{"main", "house"} {
			if exists(filepath.Join(c.etcDir(), "dns-stub-"+inst+".json")) {
				out = append(out, stubDNSUnit+inst)
			}
		}
	}
	return out
}

type Config struct {
	PolicyDir   string
	HouseEnv    string
	HouseHosts  string
	HouseLeases string
	SegmentsDir string
	NetEnvPath  string
	// NetEnvLocal is the operator overlay that apply sources after the base
	// file. It is the only net.env that a seat writes. Refer to NetKeys.
	NetEnvLocal string
	SecretsPath string
	ObservePath string
	OffsetPath  string
	DNSLogPath  string
	HouseDNSLog string
	StripLog    string
	AlertLast   string
	MonitorDir  string
	UseLog      string
	WWWDir      string
	CACertPath  string
	BrokerAdmin string
	LockPath    string
	RebootFlag  string
	PfCmd       []string
	Net         map[string]string
	Store       *secrets.Store
	AuditPath   string

	// Audit records each verb that makes a change. Nil disables it. A test
	// wants this, and a front end that did not opt in gets this.
	Audit *audit.Log
	// Now is the clock for the dates in the fetch report. Nil means time.Now.
	Now func() time.Time
	// Actor overrides the operator name in the audit log. If Actor is empty,
	// audit.Actor gives the name. That is the correct answer for a process that
	// sudo started. A front end that has better data can set Actor.
	Actor string

	// Exec runs argv to completion. Stream runs argv and copies the output to
	// w. Both are hooks, so tests never touch systemctl or journalctl.
	Exec func(ctx context.Context, argv []string) ([]byte, error)
	// Ifaces lists the interfaces of the box. Nil reads the interfaces of the
	// host. It is a hook, so the screen of a test does not depend on the
	// machine that runs the test.
	Ifaces func() []Iface
	Stream func(ctx context.Context, argv []string, w io.Writer) error
}

func Defaults() *Config {
	c := &Config{
		HouseEnv:    "/etc/pi-fortress/house.env",
		HouseHosts:  "/etc/pi-fortress/house.hosts",
		HouseLeases: "/var/lib/pi-fortress/house.leases",
		SegmentsDir: "/etc/pi-fortress/segments.d",
		SecretsPath: "/etc/pi-fortress/broker/secrets.env",
		ObservePath: "/var/lib/pi-fortress/observe.json",
		OffsetPath:  "/var/lib/pi-fortress/dns.offset",
		DNSLogPath:  "/var/log/pi-fortress/dns.jsonl",
		HouseDNSLog: "/var/log/pi-fortress/dns-house.jsonl",
		StripLog:    "/var/log/pi-fortress/strip.jsonl",
		AlertLast:   "/var/lib/pi-fortress/alert.last",
		MonitorDir:  monitor.DefaultDir,
		UseLog:      "/var/log/pi-fortress/use.jsonl",
		WWWDir:      "/var/lib/pi-fortress/www",
		CACertPath:  "/var/lib/pi-fortress/engine/ca-cert.pem",
		BrokerAdmin: secrets.AdminSock,
		LockPath:    ApplyLockPath,
		RebootFlag:  RebootFlagPath,
		AuditPath:   audit.DefaultPath,
	}
	// This is the same override that apply.sh and the observer use. Thus the
	// TUI shows the segments of a box that keeps them in a different location.
	// Without it, the TUI shows none.
	if v := strings.TrimSpace(os.Getenv("PF_SEGMENTS_DIR")); v != "" {
		c.SegmentsDir = v
	}
	if v := strings.TrimSpace(os.Getenv("PI_FORTRESS_SECRETS")); v != "" {
		c.SecretsPath = v
	}
	c.PolicyDir = base.PolicyDir()
	c.NetEnvPath = firstFile(base.NetEnvPaths()...)
	c.NetEnvLocal = base.NetEnvLocal
	// The overlay also: apply sources it after the base. Thus PI_IP and
	// AGENT_IP here are the merged values that the box runs now. They are not
	// the values that the box had when it shipped.
	c.Net = base.LoadNetEnv()
	if exe, err := os.Executable(); err == nil {
		c.PfCmd = []string{exe}
	} else {
		c.PfCmd = []string{"/usr/local/sbin/pf"}
	}
	c.Store = secrets.Open(c.SecretsPath)
	c.Audit = audit.New(c.AuditPath)
	return c
}

func firstFile(paths ...string) string { return firstStat(false, paths) }

func firstStat(dir bool, paths []string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); p != "" && err == nil && st.IsDir() == dir {
			return p
		}
	}
	return ""
}

func (c *Config) netVal(key, fallback string) string {
	if v := strings.TrimSpace(c.Net[key]); v != "" {
		return v
	}
	return fallback
}

func (c *Config) store() *secrets.Store {
	if c.Store == nil {
		c.Store = secrets.Open(c.SecretsPath)
	}
	return c.Store
}

func (c *Config) exec(ctx context.Context, argv ...string) ([]byte, error) {
	if c.Exec != nil {
		return c.Exec(ctx, argv)
	}
	return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
}

func (c *Config) stream(ctx context.Context, w io.Writer, argv ...string) error {
	if c.Stream != nil {
		return c.Stream(ctx, argv, w)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = w, w
	// apply.sh forks nft, dnsmasq and curl. They inherit the output pipe. Thus
	// a cancel must reach the full group. If not, Run waits on the pipe until
	// the last grandchild exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	return cmd.Run()
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func timeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// WriteFile replaces path atomically. It keeps the mode and owner of an
// existing file. A new file gets mode. WriteFile refuses a symlink in place
// of the target or of the temp file. It never follows the symlink.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	var owner *syscall.Stat_t
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", path)
		}
		mode = fi.Mode().Perm()
		owner, _ = fi.Sys().(*syscall.Stat_t)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Before, the staging name was path + ".tmp". The code unlinked it first,
	// so that the exclusive create succeeded. But then the exclusive create
	// gave no protection against a different copy of this function. Two
	// writers of the same file each removed the staging file of the other.
	// A rename could then publish half of the edit of the other writer, or
	// fail because its own temp file was gone. CreateTemp picks a name that
	// only this writer knows. It removes nothing that it did not make.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := fill(f, data, mode, owner); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func fill(f *os.File, data []byte, mode os.FileMode, owner *syscall.Stat_t) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if owner != nil && (int(owner.Uid) != os.Getuid() || int(owner.Gid) != os.Getgid()) {
		if err := f.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
			return err
		}
	}
	return f.Sync()
}

// readLines returns "no lines" only for a file that does not exist. It
// returns all other read failures, because the caller usually writes the
// file back next. If a permission error or a bad block counts as an empty
// list, the edit publishes a list that holds only what the edit added. The
// edit reports success. Weeks later, the operator finds that the blocklist
// has one entry in it.
func readLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	text := strings.TrimRight(string(raw), "\n")
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

// editLockPath serialises configuration edits against each other. It is
// intentionally not the apply lock. Apply holds that lock for minutes at a
// time. An operator abandons an edit that must wait for it. What an edit
// must exclude is a different edit.
//
// The lock is in the policy directory, because all editors can already
// write there. The apply lock is under /run. An unprivileged front end and
// each test would need permission to create it there before they could
// change a list.
func (c *Config) editLockPath() string {
	if c.PolicyDir != "" {
		return filepath.Join(c.PolicyDir, ".pf-edit.lock")
	}
	if c.LockPath != "" {
		return c.LockPath + ".edit"
	}
	return ApplyLockPath + ".edit"
}

// withEditLock runs fn while it excludes all other configuration edits.
// Each edit reads the full file, changes one line, and writes the full file
// back. If two edits overlap, the second edit writes back the state that it
// read. The change of the first edit is then lost, and both edits report
// success. On a blocklist, the operator then loses a block that they added,
// and cannot see that it is missing.
// An edit is a read and a rename. Thus a wait is a matter of microseconds.
// A wait near this deadline is a stuck process, not contention.
func (c *Config) withEditLock(fn func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := TryLock(c.editLockPath())
		if err == nil {
			defer l.Release()
			return fn()
		}
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func writeLines(path string, lines []string) error {
	text := strings.Join(lines, "\n")
	if text != "" {
		text += "\n"
	}
	return WriteFile(path, []byte(text), 0644)
}

// Tail returns the last n non-empty lines of path. It reads at most 1 MiB
// from the end of the file. A missing file gives an empty tail, not an error.
func Tail(path string, n int) ([]string, error) {
	lines, _, err := tailCovering(path, n)
	return lines, err
}

// tailCovering returns the same lines. It also returns whether the file
// starts before them, because the byte window or the line count cut it.
// A caller that uses a tail to answer "when did this last occur" must know
// the difference between "not in the window" and "never". They look the
// same, and only one of them is a reason to delete something.
func tailCovering(path string, n int) (lines []string, partial bool, err error) {
	if n <= 0 {
		return nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	start := int64(0)
	if fi.Size() > maxTailBytes {
		start = fi.Size() - maxTailBytes
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if start > 0 {
		partial = true
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	var out []string
	for _, l := range bytes.Split(buf, []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, string(l))
		}
	}
	if len(out) > n {
		out, partial = out[len(out)-n:], true
	}
	return out, partial, nil
}
