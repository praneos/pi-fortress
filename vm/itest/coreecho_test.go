package itest

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeGateway replaces the Pi. It records the commands that it gets and
// gives back canned output. Thus the full install/remove sequence runs
// without ssh.
type fakeGateway struct {
	probe   string
	verify  string
	cmds    []string
	fail    map[string]error
	decoded []string
}

// decode gets back the script that echoCmd encoded in base64. Thus the
// tests assert on what the gateway would really run, not on an opaque blob.
func decode(cmd string) string {
	_, rest, ok := strings.Cut(cmd, "echo ")
	if !ok {
		return cmd
	}
	b64, _, ok := strings.Cut(rest, " | ")
	if !ok {
		return cmd
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return cmd
	}
	return string(b)
}

func (g *fakeGateway) run(cmd string) (string, error) {
	g.cmds = append(g.cmds, cmd)
	script := decode(cmd)
	g.decoded = append(g.decoded, script)
	for frag, err := range g.fail {
		if strings.Contains(script, frag) || strings.Contains(cmd, frag) {
			return "", err
		}
	}
	switch {
	case strings.Contains(script, "printf 'policy=%s\\n'"):
		return g.probe, nil
	case strings.Contains(script, "echo-restore=none"):
		return g.verify, nil
	}
	return "", nil
}

// args returns the arguments echoCmd appended to the nth command.
func (g *fakeGateway) args(n int) []string {
	_, rest, _ := strings.Cut(g.cmds[n], "sudo sh -s --")
	var out []string
	for _, f := range strings.Fields(rest) {
		out = append(out, strings.Trim(f, "'"))
	}
	return out
}

// installArgs is args of the install command, at any position in the
// sequence (the dead-man is armed before it).
func (g *fakeGateway) installArgs(t *testing.T) []string {
	t.Helper()
	for i, script := range g.decoded {
		if script == echoInstallScript {
			return g.args(i)
		}
	}
	t.Fatalf("no install ran: %v", g.cmds)
	return nil
}

func (g *fakeGateway) ran(frag string) bool {
	return slices.ContainsFunc(g.decoded, func(s string) bool { return strings.Contains(s, frag) })
}

const (
	probeFreshPi   = "policy=/vagrant/vm/policy\nmarker=0\nbackup=0\nlisted=1\nstore=absent\n"
	probeLabGW     = "policy=/vagrant/vm/policy\nmarker=1\nbackup=0\nlisted=1\nstore=absent\n"
	probeKilledRun = "policy=/vagrant/vm/policy\nmarker=1\nbackup=1\nlisted=1\nstore=absent\n"
	probeHalfDone  = "policy=/vagrant/vm/policy\nmarker=0\nbackup=1\nlisted=0\nstore=absent\n"
	verifyOK       = "echo-restore=ok\n"
)

func TestTheCoreEchoFixtureInstallsOnAGatewayThatLacksIt(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if !f.owned {
		t.Fatal("a Pi without the marker is the suite's to install and to take away again")
	}
	if !g.ran("touch /etc/pi-fortress/lab") {
		t.Fatal("the install never wrote the marker")
	}
	if got := g.installArgs(t); !slices.Equal(got, []string{"/vagrant/vm/policy", "1", "0", "0"}) {
		t.Fatalf("install args %v: want save=1 (record the baseline), add=0 (core.hosts already lists it), had=0", got)
	}
	if g.cmds[len(g.cmds)-1] != echoApply {
		t.Fatalf("the install did not end in %q: %q", echoApply, g.cmds[len(g.cmds)-1])
	}
}

func TestTheCoreEchoFixtureLeavesALabGatewayAlone(t *testing.T) {
	g := &fakeGateway{probe: probeLabGW, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if f.owned {
		t.Fatal("a gateway carrying the marker with no backup dir is a lab box, not this suite's doing")
	}
	if len(g.cmds) != 1 {
		t.Fatalf("a lab gateway was changed: %v", g.cmds)
	}
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	if len(g.cmds) != 1 {
		t.Fatalf("the teardown took the lab's own fixture away: %v", g.cmds)
	}
}

func TestTheCoreEchoFixtureKeepsTheBaselineAKilledRunRecorded(t *testing.T) {
	g := &fakeGateway{probe: probeKilledRun, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if !f.owned {
		t.Fatal("a backup dir is this suite's own leftover: the next run has to finish the undo")
	}
	// save=0 is the full recovery. A new record would take the copy of
	// core.hosts that this suite already edited as the state to restore.
	// Then the fixture would never come off.
	if got := g.installArgs(t); !slices.Equal(got, []string{"/vagrant/vm/policy", "0", "0", "1"}) {
		t.Fatalf("install args %v: want save=0 (the recorded baseline stands), add=0, had=1", got)
	}
}

func TestTheCoreEchoFixtureFinishesAnInstallThatWasCutInHalf(t *testing.T) {
	g := &fakeGateway{probe: probeHalfDone, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if !f.owned {
		t.Fatal("backup recorded but no marker: the install stopped half way and this run finishes it")
	}
	if got := g.installArgs(t); !slices.Equal(got, []string{"/vagrant/vm/policy", "0", "1", "0"}) {
		t.Fatalf("install args %v: want save=0 (baseline stands), add=1 (the host line is gone), had=0", got)
	}
}

func TestTheCoreEchoFixtureRestoresAndThenProvesIt(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	n := len(g.cmds)
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	if !g.ran("rm -f /etc/pi-fortress/lab") {
		t.Fatal("the teardown never took the marker away")
	}
	if !g.ran(`cmp -s "$B/core.hosts"`) {
		t.Fatal("the teardown never proved core.hosts came back byte for byte")
	}
	if !slices.Contains(g.cmds[n:], echoApply) {
		t.Fatal("the teardown restored the files and never re-applied")
	}
	if f.owned {
		t.Fatal("a finished teardown leaves nothing to undo")
	}
	// Idempotent: a second remove is a no-op, not a second restore.
	n = len(g.cmds)
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	if len(g.cmds) != n {
		t.Fatalf("remove ran again after it was done: %v", g.cmds[n:])
	}
}

func TestACoreEchoTeardownThatDidNotPutTheBoxBackSaysSoAndKeepsTheBackup(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: "differs=/etc/pi-fortress/lab\ndiffers=/vagrant/vm/policy/core.hosts\n"}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	err = f.remove()
	if err == nil {
		t.Fatal("a box left holding the fixture must not pass as restored")
	}
	for _, want := range []string{"/etc/pi-fortress/lab", "/vagrant/vm/policy/core.hosts", echoBackupDir} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the failure does not name %s: %v", want, err)
		}
	}
	if !f.owned {
		t.Fatal("a failed teardown still owns the box: the next run has to finish it")
	}
}

func TestACoreEchoTeardownReportsAFailingApplyWithoutBlamingTheRestore(t *testing.T) {
	// apply.sh ends on settled(), which fails when a segment interface
	// has no address. That is a valid reason to fail the run. But it says
	// nothing about whether the files came back. Thus the verify still
	// runs, and the suite still releases the box after it proves clean.
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	g2 := &fakeGateway{verify: verifyOK, fail: map[string]error{echoApply: errors.New("the box is not in the state above")}}
	f.run = g2.run
	err = f.remove()
	if err == nil {
		t.Fatal("a failing apply went unreported")
	}
	if !strings.Contains(err.Error(), "pf apply --local") {
		t.Fatalf("the failure does not name the apply: %v", err)
	}
	if strings.Contains(err.Error(), "did not put the gateway back") {
		t.Fatalf("a clean verify was reported as an unrestored box: %v", err)
	}
	if !g2.ran(`cmp -s "$B/core.hosts"`) {
		t.Fatal("the failing apply stopped the verify from running at all")
	}
	if f.owned {
		t.Fatal("the verify proved the box back; only the apply failed")
	}
}

func TestACoreEchoVerifyThatSaidNothingIsAFailure(t *testing.T) {
	// Before, an empty verify meant "no differs, so we are fine". The
	// script always prints ok or none. Thus no output means it never ran.
	if d := echoDiffers(""); len(d) == 0 {
		t.Fatal("a silent verify passed")
	}
	if d := echoDiffers(verifyOK); len(d) != 0 {
		t.Fatalf("a clean verify was read as %v", d)
	}
	if d := echoDiffers("echo-restore=none\n"); len(d) != 0 {
		t.Fatalf("nothing to restore was read as %v", d)
	}
}

func TestACoreEchoProbeThatLostAKeyIsAnError(t *testing.T) {
	for name, out := range map[string]string{
		"no marker": "policy=/etc/pi-fortress\nbackup=0\nlisted=1\n",
		"no policy": "marker=0\nbackup=0\nlisted=1\n",
		"empty dir": "policy=\nmarker=0\nbackup=0\nlisted=1\n",
		"nothing":   "",
	} {
		if _, err := parseEchoState(out); err == nil {
			t.Fatalf("%s: parsed clean; a guessed baseline is how this suite would restore a box into a state it was never in", name)
		}
	}
	s, err := parseEchoState("policy=/etc/pi-fortress\nmarker=1\nbackup=0\nlisted=0\nnoise\n")
	if err != nil {
		t.Fatal(err)
	}
	if s != (echoState{Policy: "/etc/pi-fortress", Marker: true}) {
		t.Fatalf("%+v", s)
	}
}

func TestACoreEchoInstallThatFailedIsNotReportedAsReady(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, fail: map[string]error{"touch /etc/pi-fortress/lab": errors.New("read-only file system")}}
	f, err := newEchoFixture(g.run)
	if err == nil {
		t.Fatal("a failed install passed as done")
	}
	// Still owned: the baseline can already be recorded. Thus the
	// teardown must run in all cases.
	if f == nil || !f.owned {
		t.Fatal("a failed install must still be torn down")
	}
}

func TestTheCoreEchoScriptsCarryQuotesSafely(t *testing.T) {
	cmd := echoCmd(echoInstallScript, "/vagrant/vm/policy", "1", "0", "0")
	if strings.Contains(cmd, "\n") {
		t.Fatal("the command is not one line; ssh would carry only the first")
	}
	if decode(cmd) != echoInstallScript {
		t.Fatal("the script did not survive the round trip")
	}
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("shellQuote(%q) = %s", "a'b", got)
	}
}
