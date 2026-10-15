package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
)

func TestMainDispatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
		// stdout says which stream carries want; the rest report on stderr.
		stdout bool
		want   string
	}{
		{name: "no args", code: 2, want: "usage: pf"},
		{name: "help", args: []string{"help"}, stdout: true, want: "enroll"},
		{name: "unknown", args: []string{"bogus"}, code: 2, want: `unknown command "bogus"`},
		{name: "compile no flags", args: []string{"compile"}, code: 2, want: "usage: pf compile"},
		{name: "render no flags", args: []string{"render"}, code: 2, want: "usage: pf render"},
		{name: "egress alias -h", args: []string{"egress", "-h"}, want: "pf engine"},
		{name: "bad flag", args: []string{"observe", "-bogus"}, code: 2},
	} {
		var out, errb bytes.Buffer
		code := Main(tc.args, &out, &errb)
		got := errb.String()
		if tc.stdout {
			got = out.String()
		}
		if code != tc.code || !strings.Contains(got, tc.want) {
			t.Fatalf("%s: code=%d output=%q", tc.name, code, got)
		}
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	for _, c := range Commands() {
		if c.Help == "" {
			t.Fatalf("%s: empty help", c.Name)
		}
		if c.Name == "apply" || c.Name == "status" || c.Name == "enroll" {
			continue
		}
		var out, errb bytes.Buffer
		if code := Main([]string{c.Name, "-h"}, &out, &errb); code != 0 || !strings.Contains(errb.String(), "pf "+c.Name) {
			t.Fatalf("%s -h: code=%d stderr=%q", c.Name, code, errb.String())
		}
	}
}

func TestRunScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "status.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nexit 7\n"), 0755); err != nil {
		t.Fatal(err)
	}
	saved := scriptDirs
	scriptDirs = []string{filepath.Join(dir, "missing"), dir}
	t.Cleanup(func() { scriptDirs = saved })

	var errb bytes.Buffer
	if code := runScript("apply", nil, &errb); code != 1 || !strings.Contains(errb.String(), "apply.sh not found") {
		t.Fatalf("missing script: code=%d stderr=%q", code, errb.String())
	}
}

func TestTUIRefusals(t *testing.T) {
	cases := []struct {
		uid     int
		in, out bool
		want    int
		msg     string
	}{
		{1000, true, true, 2, "sudo"},
		{0, false, true, 2, "terminal"},
		{0, true, false, 2, "terminal"},
		{0, true, true, 0, ""},
	}
	for _, tc := range cases {
		msg, code := tuiCheck(tc.uid, tc.in, tc.out)
		if code != tc.want || !strings.Contains(msg, tc.msg) {
			t.Fatalf("%+v: %q %d", tc, msg, code)
		}
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"tui"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "pf tui:") {
		t.Fatalf("no tty or not root: code=%d stderr=%q", code, errb.String())
	}
}

// This lock prevents one failure: two applies that compile the same tree
// at the same time. Thus the test must run. With the real
// /run/pi-fortress, it skipped on each box that was not root. Thus it
// asserted nothing at the locations where the suite usually runs.
func TestApplyLockContention(t *testing.T) {
	orig := applyLockPath
	applyLockPath = filepath.Join(t.TempDir(), "apply.lock")
	t.Cleanup(func() { applyLockPath = orig })
	lock, err := admin.TryLock(applyLockPath)
	if err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	defer lock.Release()
	var errb bytes.Buffer
	if code := runApply(nil, nil, &errb); code != 75 || !strings.Contains(errb.String(), "another apply is running") {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
}

// When armed, allow.domains and core.hosts are the fence itself. For a
// missing file, the ordinary loaders give the empty set. Both daemons
// exit and do not start on that set. They exit before they bind anything.
func TestParanoidDaemonsRefuseAMissingPolicy(t *testing.T) {
	repo := filepath.Join("..", "..")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	var out, errb bytes.Buffer
	if code := Main([]string{"engine", "-init-ca", "-ca", caPath}, &out, &errb); code != 0 {
		t.Fatalf("init-ca: code=%d stderr=%q", code, errb.String())
	}
	secrets := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secrets, nil, 0600); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "nonexistent")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"engine allow", []string{"engine", "-paranoid", "-ca", caPath,
			"-allow", gone, "-core-hosts", filepath.Join(repo, "vm", "policy", "core.hosts"),
			"-listen", "127.0.0.1:0"}, "engine: -paranoid"},
		{"engine core", []string{"engine", "-paranoid", "-ca", caPath,
			"-allow", filepath.Join(repo, "vm", "policy", "allow.domains"), "-core-hosts", gone,
			"-listen", "127.0.0.1:0"}, "engine: -paranoid"},
		{"broker allow", []string{"broker", "-paranoid",
			"-policy", filepath.Join(repo, "vm", "policy", "core.hosts"),
			"-rules", filepath.Join(repo, "vm", "policy", "key_prefixes.rules"),
			"-secrets", secrets, "-allow", gone,
			"-agent-net", "10.77.0.0/24", "-sock", filepath.Join(dir, "b.sock")}, "broker: -paranoid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			errb.Reset()
			code := Main(tc.args, &out, &errb)
			if code == 0 || !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("code=%d stderr=%q", code, errb.String())
			}
		})
	}
}
