package doctor

import (
	"errors"
	"io/fs"
	"strings"
)

// KernelPaths are the files that the memory and psi rungs read. Tests
// point them at a temporary directory.
type KernelPaths struct {
	// Controllers lists the controllers that the cgroup2 root has.
	Controllers string
	// PSIMemory is there only when the kernel runs with PSI on.
	PSIMemory string
}

func DefaultKernelPaths() KernelPaths {
	return KernelPaths{
		Controllers: "/sys/fs/cgroup/cgroup.controllers",
		PSIMemory:   "/proc/pressure/memory",
	}
}

// cmdlineFix is the repair for both rungs. The firmware of Raspberry Pi OS
// reads the kernel command line from this file, and all of it must be on
// one line. pf does not edit the file: an error in it stops the boot.
func cmdlineFix(arg string) string {
	return `add "` + arg + `" to the end of the single line in /boot/firmware/cmdline.txt (do not add a new line), then reboot (docs/user_guide/pi_setup.md)`
}

// MemoryCgroupRung tells whether the kernel gives the memory controller to
// the units. The firmware of Raspberry Pi OS puts cgroup_disable=memory on
// the kernel command line. Then MemoryMax, MemoryHigh and MemoryMin in
// each pf unit have no effect, and systemd does not say so. A leak in one
// unit can then fill the RAM of the box, and the pressure alert cannot
// name the unit that uses the memory. This is a protection that is off
// with no sign, as with passwords for sshd. Thus it is a Warn, as that
// rung is.
func MemoryCgroupRung(p KernelPaths) Result {
	at := func(detail string, st Status) Result {
		return Result{Rung: "memory", Where: "pi", Detail: detail, Status: st}
	}
	b, err := readFile(p.Controllers)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return at(p.Controllers+" does not exist: the cgroup root is not cgroup2, so the memory caps of the units cannot be checked", Warn)
	case err != nil:
		return at("cannot read the cgroup controllers: "+err.Error(), Warn)
	}
	for _, c := range strings.Fields(string(b)) {
		if c == "memory" {
			return at("memory cgroup controller on: the memory caps of the units apply", OK)
		}
	}
	return at("the kernel has no memory cgroup controller (cgroup.controllers: "+strings.TrimSpace(string(b))+
		"), so MemoryMax and MemoryHigh of each unit have no effect and the pressure alert cannot name the unit; "+
		cmdlineFix(" cgroup_enable=memory"), Warn)
}

// PSIRung tells whether the kernel gives pressure stall information. The
// Raspberry Pi OS kernel has PSI, but it is off by default. pf alert then
// uses MemAvailable and the load in its place. That watch still works,
// but it cannot see how long tasks wait for memory. The rung is a Warn,
// for the same reason as MemoryCgroupRung.
func PSIRung(p KernelPaths) Result {
	at := func(detail string, st Status) Result {
		return Result{Rung: "psi", Where: "pi", Detail: detail, Status: st}
	}
	_, err := readFile(p.PSIMemory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return at(p.PSIMemory+" does not exist: PSI is off, so pf alert watches MemAvailable and the load, and cannot see how long tasks wait for memory; "+
			cmdlineFix(" psi=1"), Warn)
	case err != nil:
		return at("cannot read "+p.PSIMemory+": "+err.Error()+"; PSI is off or not usable; "+cmdlineFix(" psi=1"), Warn)
	}
	return at("PSI on: pf alert watches memory and CPU pressure", OK)
}
