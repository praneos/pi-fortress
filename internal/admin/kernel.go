package admin

import (
	"os"
	"strconv"
	"strings"
)

// The files of the two kernel locks (docs/user_guide/pi_setup.md "Kernel
// locks"). Both are world-readable.
const (
	PID1StatusPath      = "/proc/1/status"
	ModulesDisabledPath = "/proc/sys/kernel/modules_disabled"
)

// capSysRawio is bit 17 of a capability mask (linux/capability.h).
const capSysRawio = 1 << 17

// KernelLock is the state of the two kernel locks of the gateway. Each
// value is "yes", "no", or "?" when its file cannot be read.
type KernelLock struct {
	// RawIO is "yes" while PID 1 has CAP_SYS_RAWIO in its bounding set.
	// Then a root process can open /dev/mem and /proc/kcore. A boot after
	// apply wrote the drop-in of lib/harden.sh makes it "no".
	RawIO string
	// ModulesLocked is "yes" when kernel.modules_disabled is 1: the kernel
	// refuses each module load until the next boot (pi-fortress-modlock).
	ModulesLocked string
}

// KernelLock reads the two locks from PID1Status and ModulesDisabled.
func (c *Config) KernelLock() KernelLock {
	k := KernelLock{RawIO: "?", ModulesLocked: "?"}
	if mask, ok := capBnd(c.PID1Status); ok {
		k.RawIO = yesNo(mask&capSysRawio != 0)
	}
	if b, err := os.ReadFile(c.ModulesDisabled); c.ModulesDisabled != "" && err == nil {
		switch strings.TrimSpace(string(b)) {
		case "1":
			k.ModulesLocked = "yes"
		case "0":
			k.ModulesLocked = "no"
		}
	}
	return k
}

// capBnd is the CapBnd mask of a /proc/<pid>/status file.
func capBnd(path string) (uint64, bool) {
	if path == "" {
		return 0, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapBnd:"); ok {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return mask, err == nil
		}
	}
	return 0, false
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
