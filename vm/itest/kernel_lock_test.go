//go:build vagrant

package itest

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	modlockUnit   = "pi-fortress-modlock.service"
	modlockTimer  = "pi-fortress-modlock.timer"
	modlockList   = "/etc/modules-load.d/pi-fortress-modlock.conf"
	rawioDropIn   = "/etc/systemd/system.conf.d/50-pi-fortress.conf"
	modsDisabled  = "/proc/sys/kernel/modules_disabled"
	capSysRawio   = 1 << 17
	kernelLockDoc = "docs/user_guide/pi_setup.md, Kernel locks"
)

// kernelLockTests check the two kernel locks of the gateway (lib/harden.sh
// harden_rawio, modlock.service). The group runs after ops, which reboots
// the gateway with PF_E2E_REBOOT=1. The first two subtests only read, and
// run on a real Pi too. The last one locks module loads at once in place
// of the 10 minutes of the timer, and runs a full apply: lab only.
func kernelLockTests(t *testing.T) {
	t.Run("PID 1 has no CAP_SYS_RAWIO, and root cannot open /dev/mem or /proc/kcore", kernelRawioTests)
	t.Run("the module lock timer is on, and the boot loaded the module list", kernelModlockTimerTests)
	t.Run("after the lock, a module load fails and a full apply still passes", labOnly(kernelModlockTests))
}

// The drop-in applies when PID 1 starts. A box that did not boot since the
// apply wrote it waits for a reboot, and the subtest says so.
func kernelRawioTests(t *testing.T) {
	mtime, err := strconv.ParseInt(strings.TrimSpace(pi(t, "stat -c %Y "+rawioDropIn+" 2>/dev/null || echo missing")), 10, 64)
	if err != nil {
		t.Fatalf("%s is missing: a full pf apply writes it", rawioDropIn)
	}
	btime, err := strconv.ParseInt(strings.TrimSpace(pi(t, "awk '$1 == \"btime\" {print $2}' /proc/stat")), 10, 64)
	if err != nil {
		t.Fatalf("no btime in /proc/stat: %v", err)
	}
	if mtime > btime {
		t.Skipf("%s is newer than this boot, so PID 1 has not read it yet: a reboot waits (PF_E2E_REBOOT=1 reboots gw in the ops group)", rawioDropIn)
	}
	status := pi(t, "cat /proc/1/status")
	bnd, err := strconv.ParseUint(procStatus(status, "CapBnd"), 16, 64)
	if err != nil {
		t.Fatalf("PID 1 CapBnd unreadable: %v\n%s", err, status)
	}
	if bnd&capSysRawio != 0 {
		t.Errorf("PID 1 still has CAP_SYS_RAWIO (CapBnd %#x) in a boot after %s was written", bnd, rawioDropIn)
	}
	if bnd&capNetAdmin == 0 {
		t.Errorf("PID 1 lost CAP_NET_ADMIN (CapBnd %#x); the drop-in must take out CAP_SYS_RAWIO only", bnd)
	}
	// sudo gets its capabilities inside the bounding set that sshd got
	// from PID 1. Thus root gets EPERM, the error of a missing CAP_SYS_RAWIO.
	for _, f := range []string{"/dev/mem", "/proc/kcore"} {
		if out, _ := ssh(t, 15*time.Second, "pi", "test -e "+f+" && echo yes"); strings.TrimSpace(out) != "yes" {
			t.Logf("%s does not exist on this kernel: nothing to open", f)
			continue
		}
		out, _ := ssh(t, 15*time.Second, "pi", "sudo head -c1 "+f+" 2>&1 >/dev/null; echo rc=$?")
		if !contains(out, "Operation not permitted") || contains(out, "rc=0") {
			t.Errorf("root opened %s, or failed with an error other than EPERM:\n%s", f, out)
		}
	}
}

func kernelModlockTimerTests(t *testing.T) {
	if strings.TrimSpace(pi(t, "grep -s '^MODULE_LOCK=' /etc/pi-fortress/net.env.local | tail -1")) == "MODULE_LOCK=0" {
		t.Skip("MODULE_LOCK=0 in net.env.local: the operator turned the module lock off")
	}
	if out := strings.TrimSpace(pi(t, "systemctl is-enabled "+modlockTimer+" 2>&1 || true")); out != "enabled" {
		t.Errorf("%s is %q, want enabled", modlockTimer, out)
	}
	// After it fires, a timer with no next time is "active" and "elapsed".
	if out := strings.TrimSpace(pi(t, "systemctl is-active "+modlockTimer+" 2>&1 || true")); out != "active" {
		t.Errorf("%s is %q, want active", modlockTimer, out)
	}
	if out := pi(t, "systemctl show -p TimersMonotonic --value "+modlockTimer); !contains(out, "OnBootUSec=10min") {
		t.Errorf("%s does not fire 10 minutes after boot: %s", modlockTimer, out)
	}
	p := showProps(t, modlockUnit, "LoadState", "Type", "User", "CapabilityBoundingSet", "AmbientCapabilities",
		"NoNewPrivileges", "ProtectKernelTunables", "ReadWritePaths", "PrivateNetwork", "ProtectKernelModules")
	for k, v := range map[string]string{
		"LoadState": "loaded", "Type": "oneshot", "User": "", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
		"NoNewPrivileges": "yes", "ProtectKernelTunables": "yes", "ReadWritePaths": modsDisabled,
		"PrivateNetwork": "yes", "ProtectKernelModules": "yes",
	} {
		if p[k] != v {
			t.Errorf("%s %s=%q, want %q", modlockUnit, k, p[k], v)
		}
	}
	// systemd-modules-load read the list of apply at this boot. A name that
	// the kernel does not have fails that unit at each boot.
	if out := strings.TrimSpace(pi(t, "systemctl show -p Result --value systemd-modules-load.service")); out != "success" {
		t.Errorf("systemd-modules-load.service result %q:\n%s", out, pi(t, "sudo journalctl -b -u systemd-modules-load.service --no-pager -o cat | tail -20"))
	}
	// Each module of the list is loaded, or is in the kernel image. A
	// module that apply added after the boot loads at the next boot, so this
	// is checked only when the list is older than the boot.
	fresh := strings.TrimSpace(pi(t, "[ \"$(stat -c %Y "+modlockList+")\" -gt \"$(awk '$1 == \"btime\" {print $2}' /proc/stat)\" ] && echo fresh || true"))
	if fresh == "fresh" {
		t.Logf("%s is newer than this boot; the loaded modules are not checked against it", modlockList)
		return
	}
	missing := strings.TrimSpace(pi(t, "for m in $(grep -v '^#' "+modlockList+"); do [ -d /sys/module/$m ] || grep -qs \"/$m\\.ko\" /lib/modules/$(uname -r)/modules.builtin || echo $m; done"))
	if missing != "" {
		t.Errorf("modules of %s are not loaded: %s", modlockList, strings.Join(strings.Fields(missing), " "))
	}
}

// The lock comes at once here, not after the 10 minutes of the timer: the
// test starts the unit itself. Then the kernel refuses a module that is not
// loaded, and a full apply needs no module that the boot did not load.
func kernelModlockTests(t *testing.T) {
	// A small module that nothing loads: a character set table.
	free := ""
	for _, m := range []string{"nls_koi8_r", "nls_koi8_u", "nls_cp866", "nls_iso8859_15", "nls_iso8859_2"} {
		if out, _ := ssh(t, 15*time.Second, "pi", "sudo modprobe -n -q "+m+" && [ ! -d /sys/module/"+m+" ] && echo free"); strings.TrimSpace(out) == "free" {
			free = m
			break
		}
	}
	if free == "" {
		t.Skip("no nls_* module of this kernel is both present and not loaded")
	}
	if strings.TrimSpace(pi(t, "cat "+modsDisabled)) != "1" {
		if out, err := ssh(t, 30*time.Second, "pi", "sudo systemctl start "+modlockUnit); err != nil {
			t.Fatalf("start %s: %v\n%s", modlockUnit, err, out)
		}
	}
	if out := strings.TrimSpace(pi(t, "systemctl show -p Result --value "+modlockUnit)); out != "success" {
		t.Errorf("%s result %q:\n%s", modlockUnit, out, pi(t, "sudo journalctl -u "+modlockUnit+" -n 20 --no-pager -o cat"))
	}
	if out := strings.TrimSpace(pi(t, "cat "+modsDisabled)); out != "1" {
		t.Fatalf("%s is %q after %s, want 1", modsDisabled, out, modlockUnit)
	}
	// A second run in the same boot changes nothing, and passes.
	if out, err := ssh(t, 30*time.Second, "pi", "sudo systemctl start "+modlockUnit); err != nil {
		t.Errorf("a second start of %s failed: %v\n%s", modlockUnit, err, out)
	}
	out, _ := ssh(t, 30*time.Second, "pi", "sudo modprobe "+free+" 2>&1; echo rc=$?")
	if contains(out, "rc=0") {
		t.Errorf("modprobe %s passed after the lock:\n%s", free, out)
	}
	if loaded, _ := ssh(t, 15*time.Second, "pi", "[ -d /sys/module/"+free+" ] && echo loaded"); strings.TrimSpace(loaded) == "loaded" {
		t.Errorf("%s is loaded after the lock", free)
	}
	// A full apply with the lock on: the ruleset, the units and the
	// module list need no module that the boot did not load.
	applied := piApply(t, "sudo /usr/local/sbin/pf apply 2>&1")
	if contains(applied, "kernel modules are locked") {
		t.Errorf("a full apply with the lock on wanted a module that is not loaded (%s):\n%s", kernelLockDoc, applied)
	}
	if out := strings.TrimSpace(pi(t, "systemctl is-active pi-fortress-broker pi-fortress-dns-agent-go pi-fortress-netgate | sort -u")); out != "active" {
		t.Errorf("after the apply with the lock on, a unit is not active: %q", out)
	}
}
