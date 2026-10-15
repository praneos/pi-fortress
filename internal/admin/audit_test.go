package admin

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/audit"
)

func auditCfg(t *testing.T) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c := &Config{
		PolicyDir:  dir,
		HouseHosts: filepath.Join(dir, "house.hosts"),
		HouseEnv:   filepath.Join(dir, "house.env"),
		AuditPath:  path,
		Audit:      audit.New(path),
		Actor:      "sudo:tester",
		Exec: func(context.Context, []string) ([]byte, error) {
			return nil, nil
		},
	}
	return c, path
}

func auditLines(t *testing.T, path string) []audit.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if l == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("audit line is not json: %q: %v", l, err)
		}
		out = append(out, e)
	}
	return out
}

// The table marks each verb that changes state, and no verb that only reads.
// The table is the source of truth for the audit log. This test catches a
// verb that someone adds without a decision about it.
func TestMutatingVerbsAreMarked(t *testing.T) {
	reads := map[string]bool{
		"status": true, "units": true, "ifaces": true, "sample": true,
		"enroll.stats": true, "leases": true, "stats": true, "house.list": true,
		"agent.list": true, "feeds": true, "slots": true, "logs": true,
		"house.env.get": true, "secrets.state": true, "segments": true, "segment.env": true,
		"net.env.get": true, "logs.list": true,
	}
	for _, v := range Verbs {
		if reads[v.Name] && v.Mutates {
			t.Errorf("%s reads but is marked as mutating", v.Name)
		}
		if !reads[v.Name] && !v.Mutates {
			t.Errorf("%s is not marked as mutating and is not a known read; if it changes nothing, add it to this test", v.Name)
		}
	}
}

func TestAuditRecordsAChange(t *testing.T) {
	c, path := auditCfg(t)
	if _, err := c.Call(RoleAdmin, "agent.add", Args{List: "allow.domains", Value: "example.com"}); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("%d lines, want 1", len(lines))
	}
	e := lines[0]
	if e.Verb != "agent.add" || e.Role != "admin" || e.Actor != "sudo:tester" || !e.OK {
		t.Fatalf("entry %+v", e)
	}
	if e.Args["list"] != "allow.domains" || e.Args["value"] != "example.com" {
		t.Fatalf("args %v", e.Args)
	}
	if e.T == "" || e.Ev != "verb" {
		t.Fatalf("entry %+v", e)
	}
}

// A read is most of the traffic and none of the record.
func TestAuditIgnoresReads(t *testing.T) {
	c, path := auditCfg(t)
	if _, err := c.Call(RoleAdmin, "feeds", Args{}); err != nil {
		t.Log(err)
	}
	if _, err := c.Call(RoleAdmin, "house.env.get", Args{}); err != nil {
		t.Log(err)
	}
	if n := len(auditLines(t, path)); n != 0 {
		t.Fatalf("%d lines for reads", n)
	}
}

// The refusal is the most valuable entry. An attempt that should not have
// occurred leaves no other trace.
func TestAuditRecordsARefusal(t *testing.T) {
	c, path := auditCfg(t)
	if _, err := c.Call(RoleOperator, "agent.add", Args{List: "allow.domains", Value: "x.test"}); err != ErrDenied {
		t.Fatalf("err %v, want ErrDenied", err)
	}
	lines := auditLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("%d lines, want the refusal", len(lines))
	}
	if lines[0].OK || lines[0].Err != ErrDenied.Error() || lines[0].Role != "operator" {
		t.Fatalf("entry %+v", lines[0])
	}
}

func TestAuditRecordsAFailure(t *testing.T) {
	c, path := auditCfg(t)
	// Not a member of the agent family, so listVerb refuses it.
	if _, err := c.Call(RoleAdmin, "agent.add", Args{List: "house.domains", Value: "x.test"}); err == nil {
		t.Fatal("accepted a list outside the family")
	}
	lines := auditLines(t, path)
	if len(lines) != 1 || lines[0].OK || lines[0].Err == "" {
		t.Fatalf("entries %+v", lines)
	}
}

// apply gives the process to apply.sh through syscall.Exec. Thus nothing
// downstream can say what changed. The entry must not imply that it did.
func TestApplyIsRecordedAsRequestedOnly(t *testing.T) {
	c, path := auditCfg(t)
	c.PfCmd = []string{"/nonexistent/pf"}
	c.LockPath = filepath.Join(t.TempDir(), "apply.lock")
	var sb strings.Builder
	c.Stream = func(context.Context, []string, io.Writer) error { return nil }
	_, _ = c.Call(RoleAdmin, "apply", Args{Out: &sb})
	lines := auditLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("%d lines", len(lines))
	}
	if !lines[0].OK {
		t.Fatalf("the stubbed apply failed, so this proves nothing: %+v", lines[0])
	}
	if lines[0].Ev != "requested" {
		t.Fatalf("a successful apply claims more than it can know: %+v", lines[0])
	}
}

func TestActorPrefersSudoUserAndSaysSo(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name string
		in   map[string]string
		uid  int
		want string
	}{
		{"sudo user", map[string]string{"SUDO_USER": "alice"}, 0, "sudo:alice"},
		{"no sudo user", map[string]string{}, 0, "uid:0"},
		{"non-root, no sudo", map[string]string{}, 1000, "uid:1000"},
		// The person who ran sudo sets SUDO_USER, so it is input.
		{"newline injection", map[string]string{"SUDO_USER": "a\nb"}, 0, "uid:0"},
		{"space", map[string]string{"SUDO_USER": "a b"}, 0, "uid:0"},
		{"empty", map[string]string{"SUDO_USER": "  "}, 0, "uid:0"},
		{"too long", map[string]string{"SUDO_USER": strings.Repeat("a", 65)}, 0, "uid:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audit.Actor(env(tc.in), tc.uid); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// Each entry must stay valid as one line of JSON when the code reads it
// back. The TUI tails the file, and Tail splits on newlines.
func TestAuditLineIsOneLine(t *testing.T) {
	c, path := auditCfg(t)
	_, _ = c.Call(RoleAdmin, "agent.add", Args{List: "allow.domains", Value: "a\nb\tc"})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "\n"); n != 1 {
		t.Fatalf("%d newlines for one entry: %q", n, raw)
	}
}

// The passphrase is the one argument that must never remain after the call.
// The entry is valuable: an unlock attempt, by whom, and whether it worked.
// That is probably the line with the highest value in this log. But the
// argument is not. Args.Secret exists so that a verb has a location for it
// that fields() does not read. This test asserts that this stays true.
func TestUnlockPassphraseNeverReachesTheAuditLog(t *testing.T) {
	c, path := auditCfg(t)
	c.BrokerAdmin = filepath.Join(t.TempDir(), "nothing.sock")
	pass := "correct-horse-battery-staple"
	// The broker does not run here, so the call fails. This is the important
	// case. An operator wants a record of a failed unlock most. A failed unlock
	// is also the most likely to carry a typo of the real passphrase.
	if _, err := c.Call(RoleAdmin, "secrets.unlock", Args{Secret: pass}); err == nil {
		t.Fatal("want an error with no broker listening")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), pass) {
		t.Fatalf("the passphrase is in the audit log:\n%s", raw)
	}
	entries := auditLines(t, path)
	if len(entries) != 1 || entries[0].Verb != "secrets.unlock" || entries[0].OK || entries[0].Args != nil {
		t.Fatalf("%+v", entries)
	}
}
