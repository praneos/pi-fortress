package itest

import (
	"encoding/base64"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func indexOf(cmds []string, frag string) int {
	return slices.IndexFunc(cmds, func(c string) bool { return strings.Contains(c, frag) })
}

// The echo reflects each credential that the broker substitutes. A store
// with a slot that this suite did not seed has a real key. Thus the
// fixture does not install at all, and nothing on the box changes.
func TestTheCoreEchoFixtureRefusesAStoreWithSomebodysKeys(t *testing.T) {
	for name, probe := range map[string]string{
		"a real slot":       "policy=/vagrant/vm/policy\nmarker=0\nbackup=0\nlisted=1\nslot=a1b2c3d4e5f67890\nslot=0123456789abcdef\nstore=read\n",
		"unreadable store":  "policy=/vagrant/vm/policy\nmarker=0\nbackup=0\nlisted=1\nstore=unreadable\n",
		"store not checked": "policy=/vagrant/vm/policy\nmarker=0\nbackup=0\nlisted=1\n",
	} {
		g := &fakeGateway{probe: probe, verify: verifyOK}
		f, err := newEchoFixture(g.run)
		if err == nil {
			t.Fatalf("%s: installed the echo over a store this suite did not seed", name)
		}
		if len(g.cmds) != 1 {
			t.Fatalf("%s: the gateway was changed: %v", name, g.cmds)
		}
		if f == nil || f.owned {
			t.Fatalf("%s: nothing was installed, so there is nothing to tear down", name)
		}
		if name == "a real slot" && (!strings.Contains(err.Error(), "0123456789abcdef") || strings.Contains(err.Error(), "a1b2c3d4e5f67890")) {
			t.Fatalf("the refusal does not name just the foreign slot: %v", err)
		}
	}
}

// This suite must still remove the leftover of a killed run, even when
// the store got a real slot after that run: refused, but owned.
func TestTheCoreEchoFixtureStillTearsDownAKilledRunItWillNotReinstall(t *testing.T) {
	g := &fakeGateway{probe: "policy=/vagrant/vm/policy\nmarker=1\nbackup=1\nlisted=1\nslot=0123456789abcdef\nstore=read\n", verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err == nil || len(g.cmds) != 1 {
		t.Fatalf("reinstalled over a real slot: %v %v", err, g.cmds)
	}
	if !f.owned {
		t.Fatal("the leftover fixture was disowned")
	}
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(g.cmds, echoApply) {
		t.Fatal("the leftover was never taken off")
	}
}

// Only the slots seedLabSecrets writes, or none, let the echo in.
func TestTheCoreEchoFixtureInstallsOverTheLabSeedOnly(t *testing.T) {
	probe := "policy=/vagrant/vm/policy\nmarker=0\nbackup=0\nlisted=1\nslot=a1b2c3d4e5f67890\nslot=b0b1b2b3b4b5b6b7\nslot=c0c1c2c3c4c5c6c7\nstore=read\n"
	g := &fakeGateway{probe: probe, verify: verifyOK}
	if _, err := newEchoFixture(g.run); err != nil {
		t.Fatal(err)
	}
	if !g.ran("touch /etc/pi-fortress/lab") {
		t.Fatal("the lab seed alone kept the echo out")
	}
}

// labSeedSlots is a copy of what lab.go seeds. If the seed changes
// without it, the fixture would refuse the own store of the suite.
func TestLabSeedSlotsMatchSeedLabSecrets(t *testing.T) {
	src, err := os.ReadFile("lab.go")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "func seedLabSecrets(")
	if i < 0 {
		t.Fatal("no seedLabSecrets in lab.go")
	}
	body := string(src[i:])
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	var seeded []string
	for _, m := range regexp.MustCompile(`"([0-9a-f]{16})_[A-Z][A-Z0-9_]*=`).FindAllStringSubmatch(body, -1) {
		if !slices.Contains(seeded, m[1]) {
			seeded = append(seeded, m[1])
		}
	}
	slices.Sort(seeded)
	want := slices.Clone(labSeedSlots)
	slices.Sort(want)
	if !slices.Equal(seeded, want) {
		t.Fatalf("seedLabSecrets seeds %v, labSeedSlots says %v", seeded, want)
	}
}

// The dead-man is armed before anything changes. It carries the same
// restore that the teardown runs. It lasts longer than the timeout of the
// suite. It is a timer on disk that a reboot during the run does not remove.
func TestTheCoreEchoDeadmanIsArmedBeforeTheInstall(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK}
	if _, err := newEchoFixture(g.run); err != nil {
		t.Fatal(err)
	}
	arm, install := indexOf(g.cmds, "enable --now "+echoDeadman+".timer"), slices.Index(g.decoded, echoInstallScript)
	if arm < 0 || install < 0 || arm > install {
		t.Fatalf("dead-man at %d, install at %d: %v", arm, install, g.cmds)
	}
	cmd := g.cmds[arm]
	for _, want := range []string{"+3000 seconds", "OnCalendar=%s", "Persistent=true", "/etc/systemd/system/" + echoDeadman + ".timer", "ExecStart=/bin/sh " + echoDeadmanScript, "systemctl stop " + echoDeadman + ".timer"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("the dead-man lacks %q: %s", want, cmd)
		}
	}
	m := regexp.MustCompile(`printf %s ([A-Za-z0-9+/=]+) \| base64 -d`).FindStringSubmatch(cmd)
	if m == nil {
		t.Fatalf("no restore script in the dead-man: %s", cmd)
	}
	if b, _ := base64.StdEncoding.DecodeString(m[1]); string(b) != echoRestoreScript+"\nexec /usr/local/sbin/pf apply --local\n" {
		t.Fatal("the dead-man does not run the teardown's restore and the re-apply")
	}
	if !strings.HasPrefix(cmd, "sudo sh -c '") || !strings.HasSuffix(cmd, "'") {
		t.Fatalf("the dead-man's script is not one quoted word: %s", cmd)
	}
}

func TestNoCoreEchoWithoutADeadman(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK, fail: map[string]error{"enable --now " + echoDeadman + ".timer": errors.New("no systemd")}}
	f, err := newEchoFixture(g.run)
	if err == nil || g.ran("touch /etc/pi-fortress/lab") {
		t.Fatalf("installed with no dead-man: %v", err)
	}
	if f.owned {
		t.Fatal("nothing was installed, so there is nothing to tear down")
	}
}

// The teardown stops the dead-man after the box is proved restored, and
// only then. A teardown that did not restore leaves it armed to try again.
func TestTheCoreEchoTeardownDisarmsOnlyWhenProvedBack(t *testing.T) {
	g := &fakeGateway{probe: probeFreshPi, verify: verifyOK}
	f, err := newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	if g.cmds[len(g.cmds)-1] != echoDisarmCmd {
		t.Fatalf("the dead-man was left armed after a clean teardown: %v", g.cmds)
	}

	g = &fakeGateway{probe: probeFreshPi, verify: "differs=/etc/pi-fortress/lab\n"}
	f, err = newEchoFixture(g.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.remove(); err == nil {
		t.Fatal("an unrestored box passed")
	}
	if slices.Contains(g.cmds, echoDisarmCmd) {
		t.Fatal("the dead-man was stopped though the box is not back")
	}
}
