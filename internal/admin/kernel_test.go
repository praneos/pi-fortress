package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// The two kernel locks come from /proc/1/status (bit 17 of CapBnd) and
// kernel.modules_disabled. A file that is missing or has no value gives
// "?", never "no".
func TestKernelLock(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	mods := filepath.Join(dir, "modules_disabled")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := &Config{PID1Status: status, ModulesDisabled: mods}
	for _, tc := range []struct {
		name, status, mods string
		want               KernelLock
	}{
		// The stock bounding set of PID 1 on the Pi, and no lock yet.
		{"before", "Name:\tsystemd\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n", "0\n", KernelLock{"yes", "no"}},
		// The same set less bit 17, after a boot with the drop-in, and the lock.
		{"after", "Name:\tsystemd\nCapBnd:\t000001fffffdffff\n", "1\n", KernelLock{"no", "yes"}},
		{"no CapBnd line", "Name:\tsystemd\n", "2\n", KernelLock{"?", "?"}},
		{"not hex", "CapBnd:\tzz\n", "", KernelLock{"?", "?"}},
	} {
		write(status, tc.status)
		write(mods, tc.mods)
		if got := c.KernelLock(); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if got := (&Config{PID1Status: filepath.Join(dir, "none"), ModulesDisabled: filepath.Join(dir, "none")}).KernelLock(); got != (KernelLock{"?", "?"}) {
		t.Errorf("missing files: %+v", got)
	}
	if got := (&Config{}).KernelLock(); got != (KernelLock{"?", "?"}) {
		t.Errorf("no paths: %+v", got)
	}
	if PID1StatusPath != "/proc/1/status" || ModulesDisabledPath != "/proc/sys/kernel/modules_disabled" {
		t.Errorf("the defaults read %q and %q", PID1StatusPath, ModulesDisabledPath)
	}
}
