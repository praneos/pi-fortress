package itest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The gateway answers pf-core-echo.test only when /etc/pi-fortress/lab
// exists. That one marker file is the full fixture: vm/pi/apply.sh:587
// and :593 change it into -lab-echo in broker.env and engine.env, :864
// into the address=/pf-core-echo.test/192.0.2.2 line that the resolver
// answers from, and :879 into "lab_echo": true for the paranoid forward
// oracle. Nothing else on the box reads it (vm/pi/provision.sh:33
// writes it under PF_LAB=1, vm/appliance/firstboot.sh:76 removes it,
// vm/appliance/hygiene.list:83 refuses to seal an image that has one).
//
// Thus there is no echo server to install and no rule to open. The broker
// makes the response in its own process
// (internal/broker/serve.go:171). The address is TEST-NET, and nothing
// ever dials it. 192.0.2.0/24 is already exempt from the direct-IP drop
// of the agent gate on all boxes, lab or not
// (internal/render/ruleset.go:399-400). To install the fixture on a real
// Pi, add the marker and the pf-core-echo.test line in core.hosts. To
// remove it, undo those two edits.
const (
	// echoBackupDir has the baseline that this suite must put back. It is
	// under /var/lib, not /tmp, so that it stays after the reboot that the
	// tui group can do. Then a run killed between install and remove also
	// leaves the next run something to recover from.
	echoBackupDir = "/var/lib/pi-fortress/e2e-echo"
	echoMarker    = "/etc/pi-fortress/lab"
	echoHostLine  = "pf-core-echo.test *"
	// echoApply is the light re-apply. It installs core.hosts again from
	// the policy tree, rewrites broker.env/engine.env from the marker,
	// restarts the resolver (vm/pi/apply.sh:1089), and restarts the fence
	// because broker.env and engine.env are fence inputs
	// (vm/pi/apply.sh:668-670, :1252).
	echoApply = "sudo /usr/local/sbin/pf apply --local"
	// echoDeadman is the on-box timer that removes the fixture if this
	// process never does. The echo reflects each live credential that the
	// broker substitutes, so it must not live longer than the run that
	// wanted it. echoDeadmanAfter is longer than the longest -timeout of
	// the suite (45m, the Makefile and vm/cloudlab/lab.sh). Thus it fires
	// only when the teardown could not run.
	echoDeadman       = "pf-itest-echo-restore"
	echoDeadmanAfter  = 50 * time.Minute
	echoDeadmanScript = "/var/lib/pi-fortress/itest-echo-restore.sh"
)

// labSeedSlots are the slots that seedLabSecrets (vm/itest/lab.go) writes:
// the only slots with credentials that this suite made up. A store with
// any other slot has the real key of a person, and the echo would give it
// to any client that asks pf-core-echo.test.
var labSeedSlots = []string{"a1b2c3d4e5f67890", "b0b1b2b3b4b5b6b7", "c0c1c2c3c4c5c6c7"}

// echoRunner runs one shell command on the gateway and returns its
// output. The suite injects ssh. The unit tests inject a fake. That is
// why each decision below is made here, not in the shell.
type echoRunner func(cmd string) (string, error)

// echoState is what echoProbeScript found on the gateway.
type echoState struct {
	// Policy is the POLICY of apply.sh: the tree from which core.hosts is
	// installed. /vagrant/vm/policy on a shipped Pi, where /vagrant is a
	// symlink to /opt/pi-fortress. /etc/pi-fortress otherwise
	// (vm/pi/apply.sh:96-110).
	Policy string
	// Marker is whether /etc/pi-fortress/lab exists.
	Marker bool
	// Backup is whether a previous run already recorded the baseline. It
	// is the only thing that tells a gateway that this suite changed from
	// a gateway that it must not touch.
	Backup bool
	// Listed is whether Policy/core.hosts already has the host line of
	// the fixture. The shipped vm/policy/core.hosts has it. A Pi whose
	// operator trimmed it does not.
	Listed bool
	// Slots are the slot ids that the broker store has, space-separated.
	// StoreRead is whether the store could be read at all (an absent store
	// has none). If the probe did not say, the store was not read.
	Slots     string
	StoreRead bool
}

// echoProbeScript reports the facts echoState holds. Read-only.
const echoProbeScript = `set -u
p=/etc/pi-fortress
if [ -f /vagrant/vm/pi/net.env ]; then p=/vagrant/vm/policy; fi
printf 'policy=%s\n' "$p"
if [ -e /etc/pi-fortress/lab ]; then printf 'marker=1\n'; else printf 'marker=0\n'; fi
if [ -f /var/lib/pi-fortress/e2e-echo/core.hosts ]; then printf 'backup=1\n'; else printf 'backup=0\n'; fi
if grep -qE '^[[:space:]]*pf-core-echo\.test([[:space:]]|$)' "$p/core.hosts" 2>/dev/null; then printf 'listed=1\n'; else printf 'listed=0\n'; fi
S=/etc/pi-fortress/broker/secrets.env
if [ ! -e "$S" ]; then printf 'store=absent\n'
elif [ -r "$S" ]; then
	sed -nE 's/^[[:space:]]*([0-9a-fA-F]{16})_[A-Z][A-Z0-9_]*[[:space:]]*=.*/slot=\1/p' "$S" | sort -u
	printf 'store=read\n'
else printf 'store=unreadable\n'; fi
`

// echoInstallScript writes the marker. When its arguments tell it to, it
// records the baseline and adds the host line. It decides nothing: save,
// add and the marker to remember are arguments. Thus echoInstallArgs is
// the part with the bookkeeping, and the part that the tests can reach.
const echoInstallScript = `set -eu
POLICY="$1"; SAVE="$2"; ADD="$3"; HAD="$4"
B=/var/lib/pi-fortress/e2e-echo
if [ "$SAVE" = 1 ]; then
	install -d -m 0700 "$B"
	cp -p "$POLICY/core.hosts" "$B/core.hosts"
	if [ -f /etc/pi-fortress/core.hosts ]; then cp -p /etc/pi-fortress/core.hosts "$B/etc-core.hosts"; fi
	printf '%s\n' "$POLICY" >"$B/policy"
	printf '%s\n' "$HAD" >"$B/marker"
fi
if [ "$ADD" = 1 ]; then printf '%s\n' 'pf-core-echo.test *' >>"$POLICY/core.hosts"; fi
touch /etc/pi-fortress/lab
chmod 0644 /etc/pi-fortress/lab
`

// echoRestoreScript puts the recorded baseline back. It reads the backup
// dir and takes no arguments: the run that must undo the change is not
// always the run that made it.
const echoRestoreScript = `set -eu
B=/var/lib/pi-fortress/e2e-echo
[ -f "$B/core.hosts" ] || exit 0
POLICY=$(cat "$B/policy")
cp -p "$B/core.hosts" "$POLICY/core.hosts"
if [ -f "$B/etc-core.hosts" ]; then cp -p "$B/etc-core.hosts" /etc/pi-fortress/core.hosts; fi
if [ "$(cat "$B/marker")" = 0 ]; then rm -f /etc/pi-fortress/lab; fi
`

// echoVerifyScript runs after the re-apply and proves that the box is
// restored: each file cmp-identical to the record, the marker as it was,
// and no -lab-echo left in the two env files that apply derives from it.
// The backup dir is removed only after that is true. Thus a half-restored
// box leaves the next run something to recover from, not a clean slate
// over a dirty box.
const echoVerifyScript = `set -u
B=/var/lib/pi-fortress/e2e-echo
if [ ! -f "$B/core.hosts" ]; then printf 'echo-restore=none\n'; exit 0; fi
POLICY=$(cat "$B/policy")
rc=0
cmp -s "$B/core.hosts" "$POLICY/core.hosts" || { printf 'differs=%s\n' "$POLICY/core.hosts"; rc=1; }
if [ -f "$B/etc-core.hosts" ]; then
	cmp -s "$B/etc-core.hosts" /etc/pi-fortress/core.hosts || { printf 'differs=%s\n' /etc/pi-fortress/core.hosts; rc=1; }
fi
if [ "$(cat "$B/marker")" = 1 ]; then
	[ -e /etc/pi-fortress/lab ] || { printf 'differs=%s\n' /etc/pi-fortress/lab; rc=1; }
else
	if [ -e /etc/pi-fortress/lab ]; then printf 'differs=%s\n' /etc/pi-fortress/lab; rc=1; fi
	for f in /etc/pi-fortress/broker.env /etc/pi-fortress/engine.env; do
		if grep -q -- '-lab-echo' "$f" 2>/dev/null; then printf 'differs=%s\n' "$f"; rc=1; fi
	done
fi
if [ "$rc" = 0 ]; then rm -rf "$B"; printf 'echo-restore=ok\n'; fi
exit "$rc"
`

// echoCmd wraps a script, so that ssh carries it as one word. The script
// goes as base64, not inline: it has quotes of both kinds. With a shell
// command made manually around them, an undo can run something different
// from what was read here.
func echoCmd(script string, args ...string) string {
	var b strings.Builder
	b.WriteString("echo ")
	b.WriteString(base64.StdEncoding.EncodeToString([]byte(script)))
	b.WriteString(" | base64 -d | sudo sh -s --")
	for _, a := range args {
		b.WriteString(" ")
		b.WriteString(shellQuote(a))
	}
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// parseEchoState reads the output of echoProbeScript. A missing or
// unreadable key is an error, not a false. A guess of "no marker" on a
// gateway that has one would make this suite record a baseline that never
// existed, and then "restore" the box into it.
func parseEchoState(out string) (echoState, error) {
	var s echoState
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "policy":
			s.Policy, seen[k] = v, true
		case "marker":
			s.Marker, seen[k] = v == "1", true
		case "backup":
			s.Backup, seen[k] = v == "1", true
		case "listed":
			s.Listed, seen[k] = v == "1", true
		case "slot":
			s.Slots = strings.TrimSpace(s.Slots + " " + strings.ToLower(v))
		case "store":
			s.StoreRead = v == "read" || v == "absent"
		}
	}
	for _, k := range []string{"policy", "marker", "backup", "listed"} {
		if !seen[k] {
			return echoState{}, fmt.Errorf("core echo probe: no %s in:\n%s", k, out)
		}
	}
	if s.Policy == "" {
		return echoState{}, fmt.Errorf("core echo probe: empty policy dir in:\n%s", out)
	}
	return s, nil
}

// echoOwned reports whether this suite is the reason that the gateway has
// the fixture, and thus whether the suite must remove it again. A lab
// gateway has the marker from provision.sh and has no backup dir. That
// gateway is not ours, and stays exactly as it is. A backup dir is the
// only proof that the suite changed the box. That lets the next run
// recover a run that was killed in the middle.
func echoOwned(s echoState) bool { return s.Backup || !s.Marker }

// echoInstallArgs is the bookkeeping: what the install must do, from what
// the probe found.
//
// save is 0 when a backup dir already exists. The recovery of a killed
// run depends on that rule. The recorded baseline is the state before the
// first run touched anything. A new record over a box that this suite
// already edited would keep the edit as the state to restore. The fixture
// would then never come off.
func echoInstallArgs(s echoState) []string {
	arg := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	return []string{s.Policy, arg(!s.Backup), arg(!s.Listed), arg(s.Marker)}
}

// foreignSlots are the slots of the store that this suite did not seed. A
// store that could not be read is one large unknown, and answers as such.
func foreignSlots(s echoState) []string {
	if !s.StoreRead {
		return []string{"(the store could not be read)"}
	}
	var out []string
	for _, id := range strings.Fields(s.Slots) {
		if !slices.Contains(labSeedSlots, id) {
			out = append(out, id)
		}
	}
	return out
}

// echoArmCmd arms the dead-man. At echoDeadmanAfter from now, the box runs
// the same restore as the teardown, then the light re-apply, whatever
// occurred to this process. The timer is a unit on disk with a calendar
// time and Persistent=true, not a transient systemd-run timer. The suite
// reboots the gateway in the middle of a run, and a transient timer died
// with it. The echo then stayed up with nothing to remove it. A timer that
// a killed run left behind is replaced, so the name is free. The backup
// dir stays for the probe of the next run. That probe then finishes the
// job, as it does for any killed run.
func echoArmCmd() string {
	restore := echoRestoreScript + "\nexec /usr/local/sbin/pf apply --local\n"
	script := strings.Join([]string{
		"set -eu",
		"systemctl stop " + echoDeadman + ".timer 2>/dev/null || true",
		"printf %s " + base64.StdEncoding.EncodeToString([]byte(restore)) + " | base64 -d > " + echoDeadmanScript,
		"chmod 0700 " + echoDeadmanScript,
		"T=$(date -d '+" + strconv.Itoa(int(echoDeadmanAfter.Seconds())) + " seconds' '+%F %T')",
		"printf '[Unit]\\nDescription=pi-fortress itest: take the core echo off if the run never did\\n[Service]\\nType=oneshot\\nExecStart=/bin/sh " + echoDeadmanScript + "\\nExecStartPost=/bin/systemctl disable " + echoDeadman + ".timer\\n' > /etc/systemd/system/" + echoDeadman + ".service",
		"printf '[Timer]\\nOnCalendar=%s\\nPersistent=true\\n[Install]\\nWantedBy=timers.target\\n' \"$T\" > /etc/systemd/system/" + echoDeadman + ".timer",
		"systemctl daemon-reload",
		"systemctl enable --now " + echoDeadman + ".timer",
	}, "\n")
	return "sudo sh -c " + shellQuote(script)
}

// echoDisarmCmd removes the dead-man after the teardown proved the box
// restored. Units that are already gone (a reboot, a timer that fired) are fine.
const echoDisarmCmd = "sudo sh -c 'systemctl disable --now " + echoDeadman + ".timer 2>/dev/null; rm -f /etc/systemd/system/" + echoDeadman + ".service /etc/systemd/system/" + echoDeadman + ".timer " + echoDeadmanScript + "; systemctl daemon-reload'"

// echoFixture makes pf-core-echo.test answer on a gateway that does not
// have it, and restores the gateway.
type echoFixture struct {
	run   echoRunner
	state echoState
	owned bool
}

// newEchoFixture probes the gateway. When this suite must install the
// fixture, it installs it. It is idempotent: when run two times, or after
// a run that was killed, it gets to the same box.
func newEchoFixture(run echoRunner) (*echoFixture, error) {
	out, err := run(echoCmd(echoProbeScript))
	if err != nil {
		return nil, fmt.Errorf("core echo probe: %w\n%s", err, out)
	}
	st, err := parseEchoState(out)
	if err != nil {
		return nil, err
	}
	f := &echoFixture{run: run, state: st, owned: echoOwned(st)}
	if !f.owned {
		return f, nil
	}
	if foreign := foreignSlots(st); len(foreign) > 0 {
		// Not installed. A backup dir is the leftover of a killed run, and
		// the teardown still removes it. Without a backup dir, nothing of
		// ours is on the box.
		f.owned = st.Backup
		return f, fmt.Errorf("core echo: not installed, the broker store holds slots this suite did not seed (%s), and the echo would reflect their credentials", strings.Join(foreign, " "))
	}
	// Armed before the change, never after. Otherwise, a run killed
	// between the two would leave the echo in operation with nothing to
	// remove it. No dead-man, no fixture.
	if out, err := f.run(echoArmCmd()); err != nil {
		f.owned = st.Backup
		return f, fmt.Errorf("core echo: no dead-man restore could be armed, so the fixture is not installed: %w\n%s", err, out)
	}
	if out, err := f.run(echoCmd(echoInstallScript, echoInstallArgs(st)...)); err != nil {
		return f, fmt.Errorf("core echo install: %w\n%s", err, out)
	}
	if out, err := f.run(echoApply); err != nil {
		return f, fmt.Errorf("core echo install: %s: %w\n%s", echoApply, err, out)
	}
	return f, nil
}

// remove restores each file that the install touched, byte for byte, and
// re-applies. Then it proves it. A gateway that had the fixture of its
// own does not change.
func (f *echoFixture) remove() error {
	if f == nil || !f.owned {
		return nil
	}
	if out, err := f.run(echoCmd(echoRestoreScript)); err != nil {
		return fmt.Errorf("core echo restore: %w\n%s", err, out)
	}
	// The exit code of the apply is kept, not obeyed. apply.sh ends on
	// settled(), which fails when a segment interface has no address.
	// That says nothing about whether the files came back. The verify
	// runs in all cases, and tells the operator which of the two it
	// was.
	var applyErr error
	if out, err := f.run(echoApply); err != nil {
		applyErr = fmt.Errorf("core echo restore: %s: %w\n%s", echoApply, err, out)
	}
	out, err := f.run(echoCmd(echoVerifyScript))
	if d := echoDiffers(out); len(d) > 0 {
		return errors.Join(applyErr, fmt.Errorf("core echo restore did not put the gateway back (%s); %s still holds the baseline", strings.Join(d, " "), echoBackupDir))
	}
	if err != nil {
		return errors.Join(applyErr, fmt.Errorf("core echo verify: %w\n%s", err, out))
	}
	// Proved restored, and the backup dir is gone with it. Thus the
	// dead-man has nothing left to do. An apply that fails still fails the
	// run, with its own cause, not with a restore that it did not break.
	f.owned = false
	if out, err := f.run(echoDisarmCmd); err != nil {
		applyErr = errors.Join(applyErr, fmt.Errorf("core echo: the box is back but the %s timer could not be stopped (it would only restore a box already restored): %w\n%s", echoDeadman, err, out))
	}
	return applyErr
}

// echoDiffers lists the paths that echoVerifyScript found not restored. A
// verify that reported neither ok nor none is itself a failure. The script
// always says one or the other. Thus no output means that it did not run.
func echoDiffers(out string) []string {
	var paths []string
	ok := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if p, found := strings.CutPrefix(line, "differs="); found {
			paths = append(paths, p)
		}
		if line == "echo-restore=ok" || line == "echo-restore=none" {
			ok = true
		}
	}
	if len(paths) == 0 && !ok {
		return []string{"(the verify script said nothing)"}
	}
	return paths
}
