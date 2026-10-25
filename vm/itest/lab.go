//go:build vagrant

package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/testsupport"
)

var sshCfg string

func netenv(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testsupport.RepoRoot(t), "vm", "pi", "net.env"))
	if err != nil {
		t.Fatal(err)
	}
	env := base.ParseEnv(b)
	if p := os.Getenv("PF_LAB_ENV"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal("PF_LAB_ENV: ", err)
		}
		maps.Copy(env, base.ParseEnv(b))
	}
	return env
}

// requireLab loads the ssh config that the suite uses. PF_SSH_CONFIG
// names one (the cloud lab, or a real Pi and its agent: docs/cloud_lab.md).
// Without it, the suite uses the vagrant ssh-config of the VirtualBox lab.
func requireLab(t *testing.T) {
	t.Helper()
	cfg := os.Getenv("PF_SSH_CONFIG")
	if cfg != "" {
		b, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal("PF_SSH_CONFIG: ", err)
		}
		cfg = string(b)
	} else {
		cfg = vagrantSSHConfig(t)
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Fatal("ssh not on PATH")
	}
	dir := t.TempDir()
	sshCfg = filepath.Join(dir, "ssh.config")
	extra := "\nHost *\n  ControlMaster auto\n  ControlPath " + filepath.Join(dir, "cm-%r@%h:%p") + "\n  ControlPersist 60\n  ConnectTimeout 15\n  ServerAliveInterval 10\n"
	if err := os.WriteFile(sshCfg, []byte(cfg+extra), 0600); err != nil {
		t.Fatal(err)
	}
	sshHosts = hostAliases(cfg)
	for _, h := range []string{"pi", "agent"} {
		if !sshHosts[h] {
			t.Fatalf("ssh config has no Host %s", h)
		}
	}
	if out, err := ssh(t, 60*time.Second, "pi", "sudo -n true"); err != nil {
		// An unreachable Pi is a real failure and stays fatal. A sudo
		// refusal is not fatal: the sudo-free subtests still give results.
		// The others skip one at a time, and each names the command it needed.
		if requireSudo() || !sudoRefused(out+err.Error()) {
			t.Fatalf("pi: ssh with passwordless sudo: %v\n%s", err, out)
		}
		sudoDenied = true
	}
	labReady = true
	t.Cleanup(func() {
		sudoMu.Lock()
		defer sudoMu.Unlock()
		if len(sudoSkips) == 0 {
			return
		}
		t.Logf("unprivileged run (sudo -n denied: %v): %d group(s) skipped subtests for lack of sudo: %s. Allowlist those commands, or PF_REQUIRE_SUDO=1 to fail instead.",
			sudoDenied, len(sudoSkips), strings.Join(slices.Sorted(maps.Keys(sudoSkips)), " "))
	})
}

func vagrantSSHConfig(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("vagrant"); err != nil {
		t.Skip("vagrant not on PATH")
	}
	out, err := run(t, 30*time.Second, "vagrant", "status", "--machine-readable")
	if err != nil {
		t.Skip("vagrant status: ", err)
	}
	want := map[string]bool{"agent": false, "pi": false}
	for line := range strings.SplitSeq(out, "\n") {
		p := strings.Split(line, ",")
		if len(p) >= 4 && p[2] == "state" {
			if _, ok := want[p[1]]; ok {
				want[p[1]] = p[3] == "running"
			}
		}
	}
	for name, ok := range want {
		if !ok {
			t.Skip(name, "vm not running")
		}
	}
	cfg, err := run(t, 30*time.Second, "vagrant", "ssh-config")
	if err != nil {
		t.Fatal("vagrant ssh-config: ", err)
	}
	return cfg
}

func run(t *testing.T, d time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	// WithoutCancel, because t.Context() is cancelled immediately before
	// the Cleanup functions of a test run. A cleanup registered inside a
	// t.Run (an undo belongs there, next to the change that it reverses)
	// would otherwise get "context canceled", not a connection. Then a test
	// that closed ssh on the uplink could not open it again. The per call
	// timeout below is the real bound, and this does not change it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = testsupport.RepoRoot(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.ReplaceAll(stdout.String(), "\r", "")
	errb := strings.TrimSpace(stderr.String())
	if err == nil {
		// Half the suite ends in `|| true`. That hides a sudo refusal as an
		// empty result, which the caller then reads incorrectly as a real zero.
		if sudoRefused(errb) {
			return out, errors.New(errb)
		}
		return out, nil
	}
	if errb != "" {
		return out, fmt.Errorf("%w: %s", err, errb)
	}
	return out, err
}

func ssh(t *testing.T, d time.Duration, vm, cmd string) (string, error) {
	t.Helper()
	out, err := sshNoSkip(t, d, vm, cmd)
	sudoSkip(t, vm, cmd, err)
	return out, err
}

// sshNoSkip is ssh without the sudo skip. It does not stop the test, so
// a goroutine can call it. The caller then gives the error to sudoSkip
// on the test goroutine.
func sshNoSkip(t *testing.T, d time.Duration, vm, cmd string) (string, error) {
	t.Helper()
	if sshCfg == "" {
		return "", fmt.Errorf("ssh config not loaded")
	}
	return run(t, d, "ssh", "-n", "-F", sshCfg, "-o", "BatchMode=yes", vm, cmd)
}

// sudoSkip skips the test when err is a sudo refusal of cmd on vm.
func sudoSkip(t *testing.T, vm, cmd string, err error) {
	t.Helper()
	// All sudo paths go through here, also the paths that drop the error.
	// The probe of requireLab must see the refusal. Thus skips start only
	// after the lab is up.
	//
	// Only stderr, which run() folds into err even on exit 0. A Pi in setup
	// with an allowlist logs the refusals that it gives. The logs that this
	// suite greps are on that Pi. A match on stdout would let a log line
	// about an earlier command skip a subtest whose own sudo worked.
	if labReady && !requireSudo() && err != nil && sudoRefused(err.Error()) {
		skipNoSudo(t, vm, cmd)
	}
}

func mustSSH(t *testing.T, vm, cmd string) string {
	t.Helper()
	out, err := ssh(t, 45*time.Second, vm, cmd)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", vm, cmd, err, out)
	}
	return out
}

func agent(t *testing.T, cmd string) string {
	t.Helper()
	return mustSSH(t, "agent", cmd)
}

func pi(t *testing.T, cmd string) string {
	t.Helper()
	return mustSSH(t, "pi", cmd)
}

func httpCode(t *testing.T, url string) string {
	t.Helper()
	out, _ := ssh(t, 20*time.Second, "agent", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 "+url)
	return strings.TrimSpace(out)
}

func curlOK(code string) bool {
	return code == "200" || code == "301" || code == "302"
}

func digA(t *testing.T, name, server string) []string {
	t.Helper()
	return digOn(t, "agent", name, server)
}

// digOn resolves name at server from host and returns the IPv4 answers.
// Two tries, not one. A single lost datagram failed a four-minute run
// one time (the boxed-in resolver subtest, 2026-09-22), on a name that the
// group answers in milliseconds when asked again. A name that must give
// nothing costs four seconds, not two.
func digOn(t *testing.T, host, name, server string) []string {
	t.Helper()
	out, _ := ssh(t, 10*time.Second, host, "dig +short +time=2 +tries=2 "+name+" @"+server)
	var ips []string
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if ipv4(line) {
			ips = append(ips, line)
		}
	}
	return ips
}

// grepCount is how many lines of path on the Pi match pat. A file that is
// missing or unreadable, or a count that cannot be read, fails the test.
// As a 0, it passed all "must not appear" checks without a look.
func grepCount(t *testing.T, path, pat string) int {
	t.Helper()
	const missing = "pf-itest-missing"
	out, err := ssh(t, 15*time.Second, "pi", "sudo test -r "+path+" || { echo "+missing+"; exit 0; }; sudo grep -c "+pat+" "+path+" || true")
	if err != nil {
		t.Fatalf("grep -c %s %s on the Pi: %v\n%s", pat, path, err, out)
	}
	if strings.Contains(out, missing) {
		t.Fatalf("%s is missing or unreadable on the Pi, so a count of %s in it means nothing", path, pat)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	n, err := strconv.Atoi(strings.TrimSpace(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("grep -c %s %s on the Pi gave no count: %q", pat, path, out)
	}
	return n
}

func ipv4(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			n++
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return n == 3 && s != ""
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func seedLabSecrets(t *testing.T) {
	t.Helper()
	oatA := "sk-ant-oat01-" + strings.Repeat("A", 64)
	ortA := "sk-ant-ort01-" + strings.Repeat("B", 64)
	oatB := "sk-ant-oat01-" + strings.Repeat("C", 64)
	ortB := "sk-ant-ort01-" + strings.Repeat("D", 64)
	body := strings.Join([]string{
		"# pi-fortress lab seed",
		"a1b2c3d4e5f67890_GITHUB_TOKEN=lab_fence_github",
		"b0b1b2b3b4b5b6b7_CLAUDE_OAT=" + oatA,
		"b0b1b2b3b4b5b6b7_CLAUDE_ORT=" + ortA,
		"c0c1c2c3c4c5c6c7_CLAUDE_OAT=" + oatB,
		"c0c1c2c3c4c5c6c7_CLAUDE_ORT=" + ortB,
		"",
	}, "\n")
	b64 := base64.StdEncoding.EncodeToString([]byte(body))
	// The store of the operator is backed up one time, root-only, under
	// the state of the box. A second seed after a crashed run must not back
	// up the lab seed over the real store. Also, /tmp with a umask of 022
	// gave each local account a copy of the credentials.
	script := strings.Join([]string{
		"set -e",
		"umask 077",
		"mkdir -p " + secretsBackupDir,
		"chmod 0700 " + secretsBackupDir,
		"if [ ! -e " + secretsBackupDir + "/secrets.env ] && [ ! -e " + secretsBackupDir + "/absent ]; then if [ -f " + secretsPath + " ]; then cp -p " + secretsPath + " " + secretsBackupDir + "/secrets.env; else : > " + secretsBackupDir + "/absent; fi; fi",
		"mkdir -p /etc/pi-fortress/broker",
		"echo " + b64 + " | base64 -d > " + secretsPath,
		"chmod 600 " + secretsPath,
		"chown pf-broker:pf-fortress " + secretsPath + " 2>/dev/null || true",
	}, "; ")
	pi(t, "sudo sh -c "+shellQuote(script))
}

const (
	secretsPath      = "/etc/pi-fortress/broker/secrets.env"
	secretsBackupDir = "/var/lib/pi-fortress/itest-secrets"
)

// restoreLabSecrets restores the store that seedLabSecrets backed up. It
// checks that the store is byte for byte the backup, and only then
// deletes the backup. Any failure fails the test and leaves the backup.
func restoreLabSecrets(t *testing.T) {
	t.Helper()
	script := strings.Join([]string{
		"set -e",
		"d=" + secretsBackupDir,
		"if [ -e $d/secrets.env ]; then cat $d/secrets.env > " + secretsPath + "; elif [ -e $d/absent ]; then : > " + secretsPath + "; else echo \"no backup in $d\" >&2; exit 3; fi",
		"chmod 600 " + secretsPath,
		"chown pf-broker:pf-fortress " + secretsPath + " 2>/dev/null || true",
		"if [ -e $d/secrets.env ]; then cmp -s $d/secrets.env " + secretsPath + "; else [ ! -s " + secretsPath + " ]; fi",
		"rm -rf $d",
	}, "; ")
	if out, err := ssh(t, 20*time.Second, "pi", "sudo sh -c "+shellQuote(script)); err != nil {
		t.Errorf("the broker's secrets.env was not restored from %s (the backup is kept there): %v\n%s", secretsBackupDir, err, out)
	}
}

func runGroup(t *testing.T, name string, fn func(*testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		start := time.Now()
		if testing.Verbose() {
			fmt.Fprintf(os.Stderr, "==> %s\n", name)
		}
		fn(t)
		if testing.Verbose() {
			status := "PASS"
			if t.Failed() {
				status = "FAIL"
			}
			fmt.Fprintf(os.Stderr, "<== %s %s (%.1fs)\n", name, status, time.Since(start).Seconds())
		}
	})
}
