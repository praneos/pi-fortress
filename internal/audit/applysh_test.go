package audit

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/base"
)

// applyScript is the real vm/pi/apply.sh. The test runs the audit
// functions from it, not from a copy, because a copy becomes out of date.
// The purpose of the test is to show that this package can read back the
// line that the Pi writes.
const applyScript = "../../vm/pi/apply.sh"

// applyFuncs cuts the two audit functions out of apply.sh. The test cannot
// source the full script, because it reconfigures the box that it runs on.
// Thus the test extracts the functions by name and runs them against stub
// variables.
func applyFuncs(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(applyScript)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	var b strings.Builder
	for _, name := range []string{"audit_actor()", "audit_apply()"} {
		start := strings.Index(text, name)
		if start < 0 {
			t.Fatalf("%s no longer defines %s", applyScript, name)
		}
		// The functions have a closing brace in column one. That makes
		// this text cut safe.
		end := strings.Index(text[start:], "\n}\n")
		if end < 0 {
			t.Fatalf("%s: %s has no closing brace in column one", applyScript, name)
		}
		b.WriteString(text[start : start+end+3])
	}
	return b.String()
}

// runApplyAudit runs audit_apply with the variables that apply.sh would
// have set when it gets to the end. It returns all data written to the
// log.
func runApplyAudit(t *testing.T, env map[string]string, settled string) string {
	t.Helper()
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	script := "set -euo pipefail\n" +
		"AUDIT_LOG=\"${PF_AUDIT_LOG}\"\n" +
		applyFuncs(t) +
		"audit_apply " + settled + "\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PF_AUDIT_LOG="+log)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit_apply: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("audit_apply wrote no log: %v\n%s", err, out)
	}
	return string(raw)
}

func applyEntry(t *testing.T, raw string) Entry {
	t.Helper()
	line := strings.TrimSpace(raw)
	if strings.Contains(line, "\n") {
		t.Fatalf("audit_apply wrote more than one line:\n%s", raw)
	}
	var e Entry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("apply.sh wrote a line this package cannot read: %q: %v", line, err)
	}
	return e
}

func applyEnv(settledVars ...string) map[string]string {
	env := map[string]string{
		"INT_IF": "eth0", "WAN_IF": "wlan0", "HOUSE_IF": "eth1",
		"PARANOID": "0", "REFRESH": "0", "LOCAL_ONLY": "0",
		"SUDO_USER": "tester",
	}
	for i := 0; i+1 < len(settledVars); i += 2 {
		env[settledVars[i]] = settledVars[i+1]
	}
	return env
}

// pf apply starts apply.sh through syscall.Exec, which replaces the Go
// process. internal/admin records that an apply was requested. After that,
// no Go process is left to record the result. Thus apply.sh must write the
// result itself. That is the only way for the log to close that gap. It is
// only useful if the line parses as an Entry.
func TestApplyScriptWritesAnEntryThisPackageCanRead(t *testing.T) {
	e := applyEntry(t, runApplyAudit(t, applyEnv(), "0"))
	if e.Verb != "apply" || !e.OK || e.Err != "" {
		t.Fatalf("entry: %+v", e)
	}
	if e.Ev != "applied" {
		t.Fatalf("Ev should pair with the verb table's \"requested\": %+v", e)
	}
	if e.Actor != "sudo:tester" || e.Role != "admin" {
		t.Fatalf("actor/role: %+v", e)
	}
	if _, err := base.ParseISO(e.T); err != nil {
		t.Fatalf("timestamp %q is not the format Entry.T carries: %v", e.T, err)
	}
	if e.Args["int_if"] != "eth0" || e.Args["wan_if"] != "wlan0" || e.Args["house_if"] != "eth1" {
		t.Fatalf("args: %+v", e.Args)
	}
	if e.Args["mode"] != "full" {
		t.Fatalf("mode: %+v", e.Args)
	}
}

// An apply that finished, but did not put the box in the state that it
// described, exits non-zero. The record must show this. "applied" alone
// would claim more than occurred. The Go side prevents that failure: it
// writes "requested", not "applied", at the start.
func TestApplyScriptRecordsAnUnsettledBox(t *testing.T) {
	e := applyEntry(t, runApplyAudit(t, applyEnv(), "1"))
	if e.OK || e.Err != "not settled" {
		t.Fatalf("entry: %+v", e)
	}
}

// The mode tells apart the unattended timer path and an operator at the
// keyboard. A reader of this log who looks at an unexplained change wants
// to know this first.
func TestApplyScriptRecordsWhichModeRan(t *testing.T) {
	for _, c := range []struct{ refresh, local, want string }{
		{"0", "0", "full"},
		{"0", "1", "local"},
		{"1", "1", "refresh"},
	} {
		env := applyEnv("REFRESH", c.refresh, "LOCAL_ONLY", c.local)
		if got := applyEntry(t, runApplyAudit(t, env, "0")).Args["mode"]; got != c.want {
			t.Errorf("REFRESH=%s LOCAL_ONLY=%s recorded mode %q, want %q", c.refresh, c.local, got, c.want)
		}
	}
}

// The person who ran sudo sets SUDO_USER. Thus it is input, not a fact.
// The shell has no JSON writer. Thus the check that keeps a bad name out
// of the record also stops a quote or a backslash from making a line that
// no code can parse. If a value fails the check, the script uses the uid.
// The uid is the one identity that the script can really observe.
func TestApplyScriptRefusesAnActorItCannotWriteHonestly(t *testing.T) {
	for _, who := range []string{
		`",\"ok\":true,\"x\":\"`,
		`back\slash`,
		"two words",
		"",
		strings.Repeat("n", 65),
	} {
		raw := runApplyAudit(t, applyEnv("SUDO_USER", who), "0")
		e := applyEntry(t, raw)
		if !strings.HasPrefix(e.Actor, "uid:") {
			t.Errorf("SUDO_USER=%q was recorded as %q, want a uid fallback", who, e.Actor)
		}
	}
}

// A box that was just reconfigured must not show as failed because the
// code could not write its audit log. Each write in audit_apply can fail
// quietly. The callers of Log.Append make the same trade-off.
func TestApplyScriptSurvivesAnUnwritableLog(t *testing.T) {
	script := "set -euo pipefail\nAUDIT_LOG=/proc/definitely-not-writable/audit.jsonl\n" +
		applyFuncs(t) + "audit_apply 0\necho survived\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "REFRESH=0", "LOCAL_ONLY=0", "INT_IF=eth0", "WAN_IF=wlan0", "PARANOID=0")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "survived") {
		t.Fatalf("apply.sh would have died writing its own record: %v\n%s", err, out)
	}
}
