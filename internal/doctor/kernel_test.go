package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kernelBox is a fake cgroup2 root and /proc/pressure in a temporary
// directory. An empty controllers or psi string means that the file is
// not there.
func kernelBox(t *testing.T, controllers, psi string) KernelPaths {
	t.Helper()
	d := t.TempDir()
	p := KernelPaths{
		Controllers: filepath.Join(d, "cgroup.controllers"),
		PSIMemory:   filepath.Join(d, "pressure", "memory"),
	}
	if controllers != "" {
		if err := os.WriteFile(p.Controllers, []byte(controllers), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if psi != "" {
		if err := os.MkdirAll(filepath.Dir(p.PSIMemory), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.PSIMemory, []byte(psi), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestMemoryCgroupRung(t *testing.T) {
	for _, tc := range []struct {
		name, controllers string
		st                Status
		want              []string
		not               string
	}{
		{"memory present", "cpuset cpu io memory hugetlb pids rdma misc\n", OK, []string{"caps of the units apply"}, "cmdline.txt"},
		// The Raspberry Pi 5 with the stock firmware command line.
		{"memory absent", "cpuset cpu io pids\n", Warn, []string{
			"cpuset cpu io pids", "MemoryMax", "cannot name the unit",
			`" cgroup_enable=memory"`, "/boot/firmware/cmdline.txt", "then reboot",
		}, ""},
		{"not cgroup2", "", Warn, []string{"does not exist", "not cgroup2"}, "cmdline.txt"},
	} {
		r := MemoryCgroupRung(kernelBox(t, tc.controllers, ""))
		if r.Rung != "memory" || r.Where != "pi" || r.Status != tc.st {
			t.Errorf("%s: %s %s %v, want memory pi %v", tc.name, r.Rung, r.Where, r.Status, tc.st)
		}
		for _, w := range tc.want {
			if !strings.Contains(r.Detail, w) {
				t.Errorf("%s: %q has no %q", tc.name, r.Detail, w)
			}
		}
		if tc.not != "" && strings.Contains(r.Detail, tc.not) {
			t.Errorf("%s: %q has %q", tc.name, r.Detail, tc.not)
		}
	}
}

// A word that only contains "memory" is not the controller.
func TestMemoryCgroupRungMatchesTheWholeName(t *testing.T) {
	if r := MemoryCgroupRung(kernelBox(t, "cpu nomemory pids", "")); r.Status != Warn {
		t.Fatalf("%v %q", r.Status, r.Detail)
	}
}

func TestPSIRung(t *testing.T) {
	r := PSIRung(kernelBox(t, "", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"))
	if r.Rung != "psi" || r.Status != OK || strings.Contains(r.Detail, "cmdline.txt") {
		t.Errorf("present: %s %v %q", r.Rung, r.Status, r.Detail)
	}
	r = PSIRung(kernelBox(t, "", ""))
	if r.Rung != "psi" || r.Status != Warn {
		t.Errorf("absent: %s %v %q", r.Rung, r.Status, r.Detail)
	}
	for _, w := range []string{"PSI is off", "MemAvailable", `" psi=1"`, "/boot/firmware/cmdline.txt", "then reboot"} {
		if !strings.Contains(r.Detail, w) {
			t.Errorf("absent: %q has no %q", r.Detail, w)
		}
	}
}

func TestDefaultKernelPaths(t *testing.T) {
	p := DefaultKernelPaths()
	if p.Controllers != "/sys/fs/cgroup/cgroup.controllers" || p.PSIMemory != "/proc/pressure/memory" {
		t.Fatalf("%+v", p)
	}
}
