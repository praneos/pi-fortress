package doctor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// rebootBox is a fake /var/run, /proc and /lib/modules in a temporary
// directory. running is the release of the running kernel, and each of
// installed gets a modules directory with a kernel/ tree.
func rebootBox(t *testing.T, running string, installed ...string) RebootPaths {
	t.Helper()
	d := t.TempDir()
	p := RebootPaths{
		Flag:      filepath.Join(d, "reboot-required"),
		Pkgs:      filepath.Join(d, "reboot-required.pkgs"),
		OSRelease: filepath.Join(d, "osrelease"),
		Modules:   filepath.Join(d, "modules"),
	}
	if err := os.WriteFile(p.OSRelease, []byte(running+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, rel := range installed {
		if err := os.MkdirAll(filepath.Join(p.Modules, rel, "kernel"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func setFlag(t *testing.T, p RebootPaths, age time.Duration, now time.Time, pkgs string) {
	t.Helper()
	if err := os.WriteFile(p.Flag, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p.Flag, now.Add(-age), now.Add(-age)); err != nil {
		t.Fatal(err)
	}
	if pkgs != "" {
		if err := os.WriteFile(p.Pkgs, []byte(pkgs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRebootRungIsOKWithNoFlagAndTheNewestKernel(t *testing.T) {
	p := rebootBox(t, "6.1.0-26-arm64", "6.1.0-25-arm64", "6.1.0-26-arm64")
	r := RebootRung(p, time.Now())
	if r.Status != OK || !strings.Contains(r.Detail, "6.1.0-26-arm64") {
		t.Fatalf("got %v %q", r.Status, r.Detail)
	}
}

func TestRebootRungWarnsOnAFreshFlagWithItsPackages(t *testing.T) {
	now := time.Now()
	p := rebootBox(t, "6.1.0-26-arm64", "6.1.0-26-arm64")
	setFlag(t, p, 50*time.Hour, now, "libc6\nlibssl3\nlibc6\n")
	r := RebootRung(p, now)
	if r.Status != Warn {
		t.Fatalf("a two-day-old flag is %v, want warn: %q", r.Status, r.Detail)
	}
	for _, want := range []string{"2d", "libc6, libssl3", "sudo reboot"} {
		if !strings.Contains(r.Detail, want) {
			t.Fatalf("detail does not say %q: %q", want, r.Detail)
		}
	}
	if strings.Count(r.Detail, "libc6") != 1 {
		t.Fatalf("a repeated package is listed two times: %q", r.Detail)
	}
}

// A kernel fix that has waited more than a week for a reboot is not a fix.
// The doctor exit code must show it.
func TestRebootRungFailsWhenTheFlagIsOlderThanAWeek(t *testing.T) {
	now := time.Now()
	p := rebootBox(t, "6.1.0-26-arm64", "6.1.0-26-arm64")
	setFlag(t, p, 8*24*time.Hour, now, "")
	if r := RebootRung(p, now); r.Status != Fail {
		t.Fatalf("an eight-day-old flag is %v, want FAIL: %q", r.Status, r.Detail)
	}
}

func TestRebootRungWarnsOnANewerKernelOfTheSameFlavor(t *testing.T) {
	p := rebootBox(t, "6.1.0-25-arm64", "6.1.0-25-arm64", "6.1.0-26-arm64")
	r := RebootRung(p, time.Now())
	if r.Status != Warn || !strings.Contains(r.Detail, "newer 6.1.0-26-arm64") {
		t.Fatalf("got %v %q", r.Status, r.Detail)
	}
}

// Raspberry Pi OS installs the rpi-v8 and the rpi-2712 flavor at the same
// version, and only one of them runs. The other flavor is not a pending
// reboot, and a newer kernel of another flavor is not one either.
func TestRebootRungIgnoresOtherFlavors(t *testing.T) {
	p := rebootBox(t, "6.6.51+rpt-rpi-2712",
		"6.6.51+rpt-rpi-2712", "6.6.51+rpt-rpi-v8", "6.6.62+rpt-rpi-v8", "6.10.6+bpo-arm64")
	if r := RebootRung(p, time.Now()); r.Status != OK {
		t.Fatalf("another flavor made the rung %v: %q", r.Status, r.Detail)
	}
}

// Older Raspberry Pi OS replaces the modules of the running kernel in
// place. A modules directory that a removed kernel left behind, with no
// kernel/ tree, is not an installed kernel.
func TestRebootRungWarnsWhenTheRunningKernelIsGone(t *testing.T) {
	p := rebootBox(t, "6.1.21-v8+", "6.1.63-v8+")
	r := RebootRung(p, time.Now())
	if r.Status != Warn || !strings.Contains(r.Detail, "no longer installed") {
		t.Fatalf("got %v %q", r.Status, r.Detail)
	}

	p = rebootBox(t, "6.1.0-26-arm64", "6.1.0-26-arm64")
	if err := os.MkdirAll(filepath.Join(p.Modules, "6.1.0-27-arm64", "updates", "dkms"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := RebootRung(p, time.Now()); r.Status != OK {
		t.Fatalf("a leftover DKMS directory made the rung %v: %q", r.Status, r.Detail)
	}
}

// A box with no readable modules tree (a container, a test host) gives no
// kernel signal. It is not a box whose running kernel is gone.
func TestRebootRungSaysNothingAboutKernelsWithoutAModulesTree(t *testing.T) {
	p := rebootBox(t, "6.1.0-26-arm64")
	if r := RebootRung(p, time.Now()); r.Status != OK {
		t.Fatalf("got %v %q", r.Status, r.Detail)
	}
}

func TestSplitRelease(t *testing.T) {
	for _, c := range []struct {
		in     string
		ver    []int
		flavor string
	}{
		{"6.1.0-25-arm64", []int{6, 1, 0, 25}, "arm64"},
		{"6.8.0-1012-raspi", []int{6, 8, 0, 1012}, "raspi"},
		{"6.6.51+rpt-rpi-2712", []int{6, 6, 51}, "+rpt-rpi-2712"},
		{"6.1.21-v8+", []int{6, 1, 21}, "v8+"},
		{"6.1.21+", []int{6, 1, 21}, "+"},
	} {
		ver, flavor := splitRelease(c.in)
		if !reflect.DeepEqual(ver, c.ver) || flavor != c.flavor {
			t.Errorf("splitRelease(%q) = %v %q, want %v %q", c.in, ver, flavor, c.ver, c.flavor)
		}
	}
}
