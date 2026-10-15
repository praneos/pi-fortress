package base

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// apply.sh sources net.env and then the net.env.local of the operator. Thus
// it builds the ruleset that it loads from the merge. All other readers of
// the pair must get the same values. If not, the firewall of the box and
// its daemons use different values.
func TestLoadEnvOverlayPutsTheOperatorFileOverTheBase(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := write("first.env", "PI_IP=10.77.0.1\nAGENT_NET=10.77.0.0/24\nFEED_REFRESH=0\n")
	second := write("second.env", "PI_IP=10.99.0.1\n")
	local := write("net.env.local", "PI_IP='10.88.0.1'\nFEED_REFRESH=1\n")

	got := LoadEnvOverlay([]string{first, second}, local)
	if got["PI_IP"] != "10.88.0.1" {
		t.Fatalf("PI_IP = %q, want the overlay's 10.88.0.1", got["PI_IP"])
	}
	if got["FEED_REFRESH"] != "1" {
		t.Fatalf("FEED_REFRESH = %q, want the overlay's 1", got["FEED_REFRESH"])
	}
	// A key that the overlay does not have keeps the value of the base. The
	// search order still stops at the first readable base.
	if got["AGENT_NET"] != "10.77.0.0/24" {
		t.Fatalf("AGENT_NET = %q, want the base's 10.77.0.0/24", got["AGENT_NET"])
	}

	// A missing overlay is the ordinary case, not a fault.
	got = LoadEnvOverlay([]string{first}, filepath.Join(dir, "absent.local"))
	if got["PI_IP"] != "10.77.0.1" {
		t.Fatalf("PI_IP without an overlay = %q, want 10.77.0.1", got["PI_IP"])
	}
	if got := LoadEnvOverlay(nil, ""); len(got) != 0 {
		t.Fatalf("LoadEnvOverlay(nil, \"\") = %v, want empty", got)
	}
}

// The engine gets its listen address, and the broker gets its agent
// subnet, from an EnvironmentFile. That is the one reader that cannot call
// LoadEnvOverlay. systemd does the overlay itself when the second file is
// named after the first. Thus the two units must name it.
func TestFenceUnitsReadTheOperatorOverlayAfterTheBase(t *testing.T) {
	root := testsupport.RepoRoot(t)
	for _, unit := range []string{"pf-engine.service", "pf-broker.service"} {
		t.Run(unit, func(t *testing.T) {
			body := testsupport.ReadFile(t, filepath.Join(root, "vm", "pi", unit))
			ibase := strings.Index(body, "EnvironmentFile=/etc/pi-fortress/net.env\n")
			if ibase < 0 {
				t.Fatalf("%s no longer reads /etc/pi-fortress/net.env", unit)
			}
			// "-" because a box without an overlay is the usual case. Without
			// "-", a missing EnvironmentFile makes the unit fail.
			ilocal := strings.Index(body, "EnvironmentFile=-"+NetEnvLocal+"\n")
			if ilocal < 0 {
				t.Fatalf("%s does not read %s, so an operator who overrides PI_IP or AGENT_NET there gets a fence built from one value and a daemon started with another", unit, NetEnvLocal)
			}
			if ilocal < ibase {
				t.Fatalf("%s reads %s before the base net.env, so the base wins and the override is lost", unit, NetEnvLocal)
			}
		})
	}
}

// The restart decision comes from the inputs of the fence. The units above
// read three env files at start. Thus a change to one of them is a policy
// change that the daemons see only after a restart.
func TestApplySnapshotsTheEnvFilesTheFenceUnitsRead(t *testing.T) {
	body := testsupport.ReadFile(t, filepath.Join(testsupport.RepoRoot(t), "vm", "pi", "apply.sh"))
	_, rest, ok := strings.Cut(body, "\nFENCE_INPUTS=(\n")
	if !ok {
		t.Fatal("apply.sh has no FENCE_INPUTS array")
	}
	list, _, ok := strings.Cut(rest, "\n)\n")
	if !ok {
		t.Fatal("apply.sh FENCE_INPUTS array is not closed")
	}
	for _, want := range []string{
		"/etc/pi-fortress/broker.env",
		"/etc/pi-fortress/engine.env",
		"/etc/pi-fortress/net.env",
		"${NET_ENV_LOCAL}",
	} {
		if !strings.Contains(list, want) {
			t.Fatalf("%s is not in FENCE_INPUTS, so changing it under --local never restarts the fence and the daemons keep the values they started with:\n%s", want, list)
		}
	}
}
