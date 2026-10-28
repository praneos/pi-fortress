//go:build vagrant

package itest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/dnslog"
)

// sshHosts are the Host aliases of the loaded ssh config.
var sshHosts map[string]bool

// target is what the suite runs against, from PF_TARGET: vagrant (the
// VirtualBox lab), cloudlab (vm/cloudlab) or pi (a real Pi and its agent
// VM). A PF_SSH_CONFIG with no PF_TARGET counts as pi, the safe choice.
func target() string {
	if v := os.Getenv("PF_TARGET"); v != "" {
		return v
	}
	if os.Getenv("PF_SSH_CONFIG") != "" {
		return "pi"
	}
	return "vagrant"
}

var (
	// labReady is set after requireLab probed the lab. Before that, a sudo
	// refusal is the answer of the probe, not a subtest to skip.
	labReady bool
	// sudoDenied means the account of pi has no passwordless sudo at all.
	sudoDenied bool
	sudoMu     sync.Mutex
	sudoSkips  = map[string]bool{} // groups that skipped a subtest for sudo
)

// requireSudo keeps the old hard failure. The VirtualBox and cloud labs
// provision passwordless sudo. Thus a refusal there shows a broken lab,
// and must not go green. A real Pi often runs from an account that has
// only an allowlist. Thus it is off by default there.
func requireSudo() bool {
	if v := os.Getenv("PF_REQUIRE_SUDO"); v != "" {
		return v == "1"
	}
	return target() != "pi"
}

// sudoRefused finds a sudo refusal of a command, as against a failure of
// the command itself. The password messages come first, because an
// allowlisted account really gets them: sudo authenticates before it says
// whether the command matched. Thus an account with no password never
// reaches "is not allowed to execute", and reports a password that it
// cannot supply. Measured on the lab against vm/pi/sudoers.d/pf-itest,
// where a non-allowlisted command gives "a terminal is required" then "a
// password is required". The match list keeps the other messages for an
// account that has a password, and for a host with no sudoers entry at all.
func sudoRefused(s string) bool {
	for _, m := range []string{"sudo: a password is required", "sudo: a terminal is required", "sudo: no tty present", "is not allowed to execute", "is not in the sudoers file"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// skipNoSudo skips the subtest and names the command that sudo refused.
// Then it can be added to the allowlist of the account, if it is worth a run.
func skipNoSudo(t *testing.T, vm, cmd string) {
	t.Helper()
	group := t.Name()
	if p := strings.SplitN(group, "/", 3); len(p) > 1 {
		group = p[1]
	}
	sudoMu.Lock()
	sudoSkips[group] = true
	sudoMu.Unlock()
	t.Skipf("no sudo for %q on %s: allowlist it for this account, or PF_REQUIRE_SUDO=1 to fail instead", cmd, vm)
}

// labOnly wraps a group that seeds secrets, truncates logs or re-enrolls
// the agent: correct in a lab, not on a Pi in use. PF_E2E_DESTRUCTIVE=1
// runs them on a real Pi nevertheless, for a newly installed box that has
// no credential or log that anyone wants yet.
func labOnly(fn func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		if !destructiveOK() {
			t.Skip("lab only: it rewrites state a real Pi keeps (PF_E2E_DESTRUCTIVE=1 on a fresh box)")
		}
		fn(t)
	}
}

// destructiveOK is the question of labOnly, for a subtest that must hold
// back only a part of itself: may this run change state that the box keeps
// (stop a daemon, apply, write an env file, renew a lease)?
func destructiveOK() bool {
	return target() != "pi" || os.Getenv("PF_E2E_DESTRUCTIVE") == "1"
}

// hasCoreEcho reports whether the gateway answers pf-core-echo.test, the
// core host that echoes what the broker substituted. A lab gateway has it
// from provision.sh under PF_LAB=1. On a real Pi under
// PF_E2E_DESTRUCTIVE=1, installCoreEcho puts it there for the length of
// the run. The subtests that read it still ask. Thus a fixture that could
// not be installed makes them skip, not fail.
func hasCoreEcho(t *testing.T) bool {
	t.Helper()
	out, _ := ssh(t, 15*time.Second, "pi", "ls "+echoMarker+" 2>/dev/null")
	return strings.TrimSpace(out) != ""
}

// installCoreEcho lends the pf-core-echo.test fixture of the lab to a
// real Pi for the length of the run, and removes it again. Without it, the
// secrets group and two enroll subtests skip on hardware. They are the
// only proof that OAuth refresh capture and WebSocket frame scrubbing
// work.
//
// The gate is PF_E2E_DESTRUCTIVE=1, the same gate that labOnly puts on
// those groups. Without it, a real Pi operates exactly as before, and they
// skip. On a lab or cloudlab gateway, the marker is already there, and
// this is only a probe.
//
// The teardown is registered on the t of TestLab. Thus it runs after all
// groups, if they passed or failed. It fails the run if the box did not
// come back byte for byte.
func installCoreEcho(t *testing.T) {
	t.Helper()
	if target() != "pi" || os.Getenv("PF_E2E_DESTRUCTIVE") != "1" || sudoDenied {
		return
	}
	// run, not ssh: a sudo refusal inside ssh() calls t.Skipf. On the t
	// of TestLab, that would skip the full suite. Here a refusal is one
	// fixture that could not be installed.
	f, err := newEchoFixture(func(cmd string) (string, error) {
		return run(t, 5*time.Minute, "ssh", "-n", "-F", sshCfg, "-o", "BatchMode=yes", "pi", cmd)
	})
	t.Cleanup(func() {
		if err := f.remove(); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Logf("core echo fixture: %v\nthe secrets and enroll subtests that need pf-core-echo.test will skip", err)
		return
	}
	if f.owned {
		t.Logf("core echo fixture installed for this run (%s, %s in %s); it comes off in the teardown, baseline in %s",
			echoMarker, echoHostLine, f.state.Policy, echoBackupDir)
	}
}

// cloudlabOnly marks tests that need the Linux house or desk VM of the
// cloud lab (vm/cloudlab). A real house device or desktop is checked manually.
func cloudlabOnly(t *testing.T) {
	t.Helper()
	if target() != "cloudlab" {
		t.Skip("cloud lab only")
	}
}

func needHost(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if !sshHosts[n] {
			t.Skipf("no ssh Host %s", n)
		}
	}
}

func needReboot(t *testing.T) {
	t.Helper()
	if os.Getenv("PF_E2E_REBOOT") != "1" {
		t.Skip("reboots only with PF_E2E_REBOOT=1")
	}
}

func hostAliases(cfg string) map[string]bool {
	hosts := map[string]bool{}
	for line := range strings.SplitSeq(cfg, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.EqualFold(f[0], "Host") {
			continue
		}
		for _, h := range f[1:] {
			if !strings.ContainsAny(h, "*?!") {
				hosts[h] = true
			}
		}
	}
	return hosts
}

// mustFailOn runs cmd on host and fails the test if it succeeded. An ssh
// failure (255) or a timeout is not a failure of the command, so it also fails.
func mustFailOn(t *testing.T, host, cmd string) {
	t.Helper()
	out, err := ssh(t, 25*time.Second, host, cmd)
	failedAsExpected(t, host, cmd, out, err)
}

// mustFailAllOn is mustFailOn for commands that do not depend on each
// other. A dropped probe waits for its full timeout. Thus the commands
// run at the same time, and the wait is that of the slowest one. The
// checks then occur in the order of cmds, on the test goroutine.
func mustFailAllOn(t *testing.T, host string, cmds ...string) {
	t.Helper()
	outs := make([]string, len(cmds))
	errs := make([]error, len(cmds))
	var wg sync.WaitGroup
	for i, cmd := range cmds {
		wg.Go(func() { outs[i], errs[i] = sshNoSkip(t, 25*time.Second, host, cmd) })
	}
	wg.Wait()
	for i, cmd := range cmds {
		sudoSkip(t, host, cmd, errs[i])
		failedAsExpected(t, host, cmd, outs[i], errs[i])
	}
}

// mustFailOnEach is mustFailAllOn for one command on more than one host.
// The hosts run it at the same time.
func mustFailOnEach(t *testing.T, cmd string, hosts ...string) {
	t.Helper()
	outs := make([]string, len(hosts))
	errs := make([]error, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Go(func() { outs[i], errs[i] = sshNoSkip(t, 25*time.Second, host, cmd) })
	}
	wg.Wait()
	for i, host := range hosts {
		sudoSkip(t, host, cmd, errs[i])
		failedAsExpected(t, host, cmd, outs[i], errs[i])
	}
}

// failedAsExpected fails the test unless cmd itself failed on host.
func failedAsExpected(t *testing.T, host, cmd, out string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: %s: expected failure\n%s", host, cmd, out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() == 255 || ee.ExitCode() < 0 {
		t.Fatalf("%s: %s: ssh itself failed: %v", host, cmd, err)
	}
}

// eventually retries fn every 0.5 s until it returns "" or d has passed,
// then fails with fn's last message. Use it when fn only reads state.
func eventually(t *testing.T, d time.Duration, fn func() string) {
	t.Helper()
	eventuallyEvery(t, d, 500*time.Millisecond, fn)
}

// eventuallyEvery is eventually with its own interval. Use 2 s when fn
// sends traffic to a public host or runs a heavy command. Then a slow
// recovery does not send a request every 0.5 s.
func eventuallyEvery(t *testing.T, d, every time.Duration, fn func() string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		msg := fn()
		if msg == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(every)
	}
}

// piClock is the local time of the Pi, the --since for kernLog.
func piClock(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(pi(t, "date '+%Y-%m-%d %H:%M:%S'"))
}

// kernLog waits for a kernel log line on the Pi, at or after since, that
// has prefix and all of want. Pin the destination (DST=<ip> ) and also
// the port: a port alone matches all other traffic that the segment sent
// there in the window.
func kernLog(t *testing.T, since, prefix string, want ...string) {
	t.Helper()
	cmd := "sudo journalctl -k --no-pager -o cat --since '" + since + "' -g '" + prefix + "'"
	subs := append([]string{prefix}, want...)
	eventually(t, 20*time.Second, func() string {
		out, _ := ssh(t, 15*time.Second, "pi", cmd)
		if lineWith(out, subs...) {
			return ""
		}
		return fmt.Sprintf("no kernel line with %q since %s", subs, since)
	})
}

// unresolved gets an address of name from the resolver of the Pi, and
// removes it from the resolved set of the Pi. Thus the resolver gate has
// not seen a connection to it. The resolver of the Pi, not DNS_UPSTREAM:
// with DoT on, the output chain drops plaintext 53 to the upstream.
func unresolved(t *testing.T, set, name string) string {
	t.Helper()
	ip := firstIPv4(pi(t, "dig +short +time=3 +tries=2 "+name))
	if ip == "" {
		t.Fatalf("no address for %s from the Pi's resolver", name)
	}
	_, _ = ssh(t, 10*time.Second, "pi", "sudo nft delete element inet fortress "+set+" '{ "+ip+" }'")
	return ip
}

// reboot restarts host and waits until it answers with a new boot id.
func reboot(t *testing.T, host string) {
	t.Helper()
	const bootID = "cat /proc/sys/kernel/random/boot_id"
	before := strings.TrimSpace(mustSSH(t, host, bootID))
	_, _ = ssh(t, 15*time.Second, host, "sudo systemctl reboot")
	eventually(t, 6*time.Minute, func() string {
		out, err := ssh(t, 20*time.Second, host, bootID)
		if id := strings.TrimSpace(out); err != nil || id == "" || id == before {
			return host + " did not come back after a reboot"
		}
		return ""
	})
}

// Capability bits, for the bounding sets the sandboxed daemons keep.
// CapBnd in /proc/<pid>/status is that mask in hex, so the two net
// capabilities that a DHCP server keeps read 0x1400.
const (
	capNetBindService = 1 << 10
	capNetAdmin       = 1 << 12
)

// mainPID is the MainPID of the unit on the Pi, "0" when it is not running.
func mainPID(t *testing.T, unit string) string {
	t.Helper()
	return strings.TrimSpace(pi(t, "systemctl show -p MainPID --value "+unit+".service"))
}

// procStatus is one field of /proc/<pid>/status, first column only: Uid
// has four columns, and only the real uid is of interest here.
func procStatus(status, key string) string {
	for line := range strings.SplitSeq(status, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k != key {
			continue
		}
		if f := strings.Fields(v); len(f) > 0 {
			return f[0]
		}
		return ""
	}
	return ""
}

// unitSandbox asserts that the main process of unit runs as user, under a
// system-call filter, with exactly caps in its bounding set. It returns
// the PID, so that a caller can prove that the same process survived a
// reload. It also returns the allowed call list, so that the caller can
// say which re-adds it expects.
//
// Asserted against the live process and the merged view of systemd, not
// against the unit file, which apply_test.sh already reads. A directive
// that systemd ignored, or a drop-in that someone left behind, shows only
// here.
func unitSandbox(t *testing.T, unit, user string, caps uint64) (string, []string) {
	t.Helper()
	pid := mainPID(t, unit)
	if pid == "" || pid == "0" {
		t.Fatalf("%s has no main process (%s)", unit, strings.TrimSpace(pi(t, "systemctl is-active "+unit+".service || true")))
	}
	status := pi(t, "sudo cat /proc/"+pid+"/status")
	want := strings.TrimSpace(pi(t, "id -u "+user))
	if got := procStatus(status, "Uid"); got != want {
		t.Errorf("%s runs as uid %q, want %q (%s); the unit lost its User= or the daemon dropped to something else", unit, got, want, user)
	}
	// 2 is SECCOMP_MODE_FILTER. It says only that a filter is loaded.
	// MemoryDenyWriteExecute, RestrictNamespaces and
	// RestrictAddressFamilies each also load one, and all three were on
	// these units while SystemCallFilter was missing. Thus the list that
	// systemd merged decides. Seccomp only says that the list reached
	// the process.
	boxedStatus(t, unit, status, caps)
	filter := strings.Fields(pi(t, "systemctl show -p SystemCallFilter --value "+unit+".service"))
	for _, want := range []string{"recvmsg", "openat"} {
		if !slices.Contains(filter, want) {
			t.Errorf("%s allows no %s, so it has no SystemCallFilter at all (%d calls listed)", unit, want, len(filter))
		}
	}
	// The purpose of the filter: a daemon that never drops privilege has
	// no reason to make the calls that drop it.
	for _, no := range []string{"setuid", "setgroups", "capset"} {
		if slices.Contains(filter, no) {
			t.Errorf("%s still allows %s; @privileged is not denied", unit, no)
		}
	}
	got, err := strconv.ParseUint(procStatus(status, "CapBnd"), 16, 64)
	if err != nil {
		t.Fatalf("%s CapBnd unreadable: %v\n%s", unit, err, status)
	}
	if got != caps {
		t.Errorf("%s bounding set is %#x, want %#x", unit, got, caps)
	}
	return pid, filter
}

// procBoxed asserts the sandbox of the main process of unit, as the
// kernel sees it: a seccomp filter, no_new_privs, and exactly caps as its
// effective set. It returns the PID, or "" when the unit has no main
// process. It does not check the user, because www has a dynamic user.
func procBoxed(t *testing.T, unit string, caps uint64) string {
	t.Helper()
	pid := mainPID(t, unit)
	if pid == "" || pid == "0" {
		t.Errorf("%s has no main process (%s)", unit, strings.TrimSpace(pi(t, "systemctl is-active "+unit+".service || true")))
		return ""
	}
	boxedStatus(t, unit, pi(t, "sudo cat /proc/"+pid+"/status"), caps)
	return pid
}

// boxedStatus checks one /proc/<pid>/status: Seccomp 2 (a filter is
// loaded), NoNewPrivs 1, and CapEff equal to caps. A daemon with ambient
// capabilities has them in CapEff. A daemon with none has 0.
func boxedStatus(t *testing.T, unit, status string, caps uint64) {
	t.Helper()
	if got := procStatus(status, "Seccomp"); got != "2" {
		t.Errorf("%s has Seccomp %q, want 2 (a seccomp filter is loaded)", unit, got)
	}
	if got := procStatus(status, "NoNewPrivs"); got != "1" {
		t.Errorf("%s has NoNewPrivs %q, want 1", unit, got)
	}
	eff, err := strconv.ParseUint(procStatus(status, "CapEff"), 16, 64)
	if err != nil {
		t.Errorf("%s CapEff unreadable: %v", unit, err)
		return
	}
	if eff != caps {
		t.Errorf("%s effective capabilities are %#x, want %#x", unit, eff, caps)
	}
}

// unitPaths is a path list property of unit (InaccessiblePaths,
// ReadWritePaths) as systemd merged it, without the "-" and "+" prefixes.
func unitPaths(t *testing.T, unit, prop string) []string {
	t.Helper()
	var out []string
	for _, f := range strings.Fields(pi(t, "systemctl show -p "+prop+" --value "+unit+".service")) {
		out = append(out, strings.TrimLeft(f, "-+"))
	}
	return out
}

// noSeccompKill fails if the kernel reported a seccomp kill for any of
// comms at or after since. These units use the default action, which is
// kill, not EPERM. A daemon that dies restarts in two seconds and shows
// it here. An errno in a path that runs one time a month would not be
// seen until a device quietly stopped working.
func noSeccompKill(t *testing.T, since string, comms ...string) {
	t.Helper()
	var out string
	for _, cmd := range []string{
		"sudo journalctl -k --no-pager -o cat --since '" + since + "' -g SECCOMP",
		"sudo journalctl --no-pager -o cat --since '" + since + "' _AUDIT_TYPE_NAME=SECCOMP",
	} {
		o, _ := ssh(t, 20*time.Second, "pi", cmd)
		out += o
	}
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, "SECCOMP") {
			continue
		}
		for _, c := range comms {
			if strings.Contains(line, `comm="`+c+`"`) || strings.Contains(line, " "+c+" ") {
				t.Errorf("a syscall was filtered since %s, so the filter is too narrow:\n%s", since, line)
				return
			}
		}
	}
}

func lineWith(out string, subs ...string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		if !slices.ContainsFunc(subs, func(s string) bool { return !strings.Contains(line, s) }) {
			return true
		}
	}
	return false
}

func firstIPv4(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if line = strings.TrimSpace(line); ipv4(line) {
			return line
		}
	}
	return ""
}

// nextIP is ip with its last octet plus one: agent2 after agent.
func nextIP(ip string) string {
	i := strings.LastIndexByte(ip, '.')
	n, _ := strconv.Atoi(ip[i+1:])
	return ip[:i+1] + strconv.Itoa(n+1)
}

// floodCounts reads a resolver log and returns, for src, the queries that
// it recorded one at a time and the queries that a suppressed summary
// counted. Config (sinkhole) summaries do not count: they use a budget of
// their own. That is the purpose of the reserved bucket.
//
// It uses dnslog.Reader, so that the lab reads the log as pf observe
// does, in the shape that the box writes.
func floodCounts(log, src string) (logged, suppressed int) {
	var r dnslog.Reader
	fold := func(evs []dnslog.Event) {
		for _, ev := range evs {
			if ev.Src != src {
				continue
			}
			if ev.Act == dnslog.ActSuppressed {
				if !ev.Listed {
					suppressed += ev.N
				}
				continue
			}
			logged++
		}
	}
	for line := range strings.SplitSeq(log, "\n") {
		fold(r.Feed(strings.TrimSpace(line)))
	}
	fold(r.Flush())
	return logged, suppressed
}

// pfListeners returns the `ss -Hltnp` lines of pf processes listening on
// a port outside allowed.
func pfListeners(ss string, allowed ...string) []string {
	var bad []string
	for line := range strings.SplitSeq(ss, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.Contains(line, `(("pf",`) {
			continue
		}
		local := f[3]
		if !slices.Contains(allowed, local[strings.LastIndexByte(local, ':')+1:]) {
			bad = append(bad, line)
		}
	}
	return bad
}
