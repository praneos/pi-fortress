package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RebootPaths are the files that the reboot rung reads. Tests point them
// at a temporary directory.
type RebootPaths struct {
	// Flag and Pkgs are written by the kernel postinst hook of
	// unattended-upgrades (and update-notifier on Ubuntu). /var/run is a
	// tmpfs, so a reboot removes them.
	Flag, Pkgs string
	// OSRelease is the release of the running kernel (uname -r).
	OSRelease string
	// Modules holds one directory for each installed kernel release.
	Modules string
}

func DefaultRebootPaths() RebootPaths {
	return RebootPaths{
		Flag:      "/var/run/reboot-required",
		Pkgs:      "/var/run/reboot-required.pkgs",
		OSRelease: "/proc/sys/kernel/osrelease",
		Modules:   "/lib/modules",
	}
}

// rebootOverdue is the age of the flag at which the rung changes from a
// warning to a failure. unattended-upgrades on this box does not reboot
// (provision.sh sets Automatic-Reboot "false"). Thus a kernel or library
// fix that it installs is not active until an operator reboots. A week
// gives time for a planned reboot. After that, the fix is installed but
// not in use, and the doctor exit code must show it.
const rebootOverdue = 7 * 24 * time.Hour

// RebootRung reports updates that are installed but not active. It uses
// two signals:
//
//   - The reboot-required flag. Its age is the time since the last
//     package that asked for a reboot, because each such package writes
//     the flag again. The age is thus a lower limit.
//   - The running kernel against the installed kernels in Modules, of the
//     same flavor only. Raspberry Pi OS installs more than one flavor
//     (rpi-v8 and rpi-2712) at the same version, and only one of them can
//     run. A kernel that is installed again with the same release string
//     does not show here. The flag is the signal for that case.
//
// The kernel signal is always a warning. Only the age of the flag can
// make the rung fail.
func RebootRung(p RebootPaths, now time.Time) Result {
	at := func(detail string, st Status) Result {
		return Result{Rung: "reboot", Where: "pi", Detail: detail, Status: st}
	}
	running := ""
	if b, err := readFile(p.OSRelease); err == nil {
		running = strings.TrimSpace(string(b))
	}
	var why []string
	st := OK
	if fi, err := os.Stat(p.Flag); err == nil {
		st = Warn
		age := now.Sub(fi.ModTime())
		w := fmt.Sprintf("reboot pending for %s (since %s)", shortAge(age), fi.ModTime().Local().Format("2006-01-02 15:04"))
		if pkgs := rebootPkgs(p.Pkgs); pkgs != "" {
			w += " for " + pkgs
		}
		why = append(why, w)
		if age >= rebootOverdue {
			st = Fail
		}
	}
	if running != "" {
		newer, gone := kernelState(p.Modules, running)
		switch {
		case gone:
			why = append(why, "running kernel "+running+" is no longer installed")
		case newer != "":
			why = append(why, "running kernel "+running+", newer "+newer+" is installed")
		}
		if (gone || newer != "") && st == OK {
			st = Warn
		}
	}
	if st == OK {
		if running == "" {
			return at("no reboot pending", OK)
		}
		return at("no reboot pending, kernel "+running, OK)
	}
	detail := strings.Join(why, "; ") + "; the installed updates are not active until a reboot (sudo reboot; the agents lose the gateway while it starts)"
	if st == Fail {
		detail += fmt.Sprintf("; pending for more than %d days", int(rebootOverdue.Hours()/24))
	}
	return at(detail, st)
}

// rebootPkgs is the package list from reboot-required.pkgs: one name per
// line, maybe repeated. A long list is cut, so that the rung stays one
// line.
func rebootPkgs(path string) string {
	b, err := readFile(path)
	if err != nil {
		return ""
	}
	const show = 5
	seen := map[string]bool{}
	var names []string
	for _, l := range strings.Fields(string(b)) {
		if !seen[l] {
			seen[l] = true
			names = append(names, l)
		}
	}
	if len(names) > show {
		return strings.Join(names[:show], ", ") + fmt.Sprintf(" and %d more", len(names)-show)
	}
	return strings.Join(names, ", ")
}

// kernelState compares the running release with the installed releases
// of the same flavor. newer is the newest installed release above the
// running one. gone is true when other kernels are installed but the
// running one is not: on older Raspberry Pi OS, the kernel package
// replaces the modules of the running kernel in place. A directory
// counts as an installed kernel only if it has the kernel/ tree of the
// package. Thus a directory that a removed kernel leaves behind (for
// example, DKMS output) does not count.
func kernelState(modules, running string) (newer string, gone bool) {
	entries, err := os.ReadDir(modules)
	if err != nil {
		return "", false
	}
	runVer, runFlavor := splitRelease(running)
	if len(runVer) == 0 {
		return "", false
	}
	found, installed := false, false
	best := runVer
	for _, e := range entries {
		rel := e.Name()
		if fi, err := os.Stat(filepath.Join(modules, rel, "kernel")); err != nil || !fi.IsDir() {
			continue
		}
		installed = true
		if rel == running {
			found = true
			continue
		}
		ver, flavor := splitRelease(rel)
		if flavor != runFlavor || len(ver) == 0 {
			continue
		}
		if compareVersion(ver, best) > 0 {
			best, newer = ver, rel
		}
	}
	return newer, installed && !found
}

// splitRelease cuts a kernel release into its version, which sorts, and
// its flavor, which must be equal for two releases to compare:
//
//	6.1.0-25-arm64       -> [6 1 0 25] "arm64"          (Debian)
//	6.8.0-1012-raspi     -> [6 8 0 1012] "raspi"        (Ubuntu)
//	6.6.51+rpt-rpi-2712  -> [6 6 51] "+rpt-rpi-2712"    (Raspberry Pi OS)
//	6.1.21-v8+           -> [6 1 21] "v8+"              (older Raspberry Pi OS)
func splitRelease(r string) ([]int, string) {
	i := 0
	for i < len(r) && (r[i] >= '0' && r[i] <= '9' || r[i] == '.' || r[i] == '-') {
		i++
	}
	var ver []int
	for _, f := range strings.FieldsFunc(r[:i], func(c rune) bool { return c == '.' || c == '-' }) {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, ""
		}
		ver = append(ver, n)
	}
	return ver, r[i:]
}

func compareVersion(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return len(a) - len(b)
}

func shortAge(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 0:
		return "0m"
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

// CARestartPending is the marker that ca-restart.sh writes when the system
// CA bundle changed but a sealed store kept it from a broker restart.
// Each broker start removes it.
const CARestartPending = "/var/lib/pi-fortress/ca-restart-pending"

// CARestartRung warns while the marker is there: the broker still verifies
// origins against the old system roots. An automatic restart would lock
// the sealed store, so the restart is for an operator who can unlock. The
// marker is root-only; its modification time is the time of the change,
// so the rung needs no root. No marker, no rung.
func CARestartRung(path string) (Result, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return Result{}, false
	}
	return Result{Rung: "ca", Where: "fence", Status: Warn, Detail: fmt.Sprintf(
		"system CA bundle changed at %s; the broker still has the old roots, because the store is sealed. "+
			"When you can unlock: sudo systemctl restart pi-fortress-broker.service, then sudo pf unlock",
		fi.ModTime().Local().Format("2006-01-02 15:04"))}, true
}
