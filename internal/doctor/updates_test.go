package doctor

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func keys(us []Update) string {
	var k []string
	for _, u := range us {
		k = append(k, u.Key)
	}
	return strings.Join(k, " ")
}

func TestRebootUpdates(t *testing.T) {
	d := t.TempDir()
	p := RebootPaths{Flag: d + "/flag", Pkgs: d + "/pkgs", OSRelease: d + "/osrelease", Modules: d + "/modules"}
	write(t, p.OSRelease, "6.18.50+rpt-rpi-2712\n")
	for _, rel := range []string{"6.18.39+rpt-rpi-2712", "6.18.50+rpt-rpi-2712", "6.18.55+rpt-rpi-v8"} {
		write(t, filepath.Join(p.Modules, rel, "kernel", "x"), "")
	}
	if got := keys(RebootUpdates(p)); got != "" {
		t.Fatalf("current kernel, no flag: %q", got)
	}
	// A newer kernel of the same flavor, and the flag.
	write(t, filepath.Join(p.Modules, "6.18.55+rpt-rpi-2712", "kernel", "x"), "")
	write(t, p.Flag, "*** System restart required ***\n")
	write(t, p.Pkgs, "libc6\nlibc6\n")
	us := RebootUpdates(p)
	if got := keys(us); got != "reboot-flag kernel:6.18.55+rpt-rpi-2712" {
		t.Fatalf("keys %q", got)
	}
	if !strings.Contains(us[0].Text, "libc6") || strings.Count(us[0].Text, "libc6") != 1 {
		t.Fatalf("flag text %q", us[0].Text)
	}
}

func eepromTree(t *testing.T, cur uint32) UpdatePaths {
	d := t.TempDir()
	p := UpdatePaths{BootTS: d + "/ts", Compatible: d + "/compatible", Firmware: d + "/fw",
		EEPROMConf: d + "/conf", Staged: d + "/boot/pieeprom.upd"}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], cur)
	write(t, p.BootTS, string(b[:]))
	write(t, p.Compatible, "raspberrypi,5-model-b\x00brcm,bcm2712\x00")
	write(t, p.EEPROMConf, "# comment\nFIRMWARE_RELEASE_STATUS=\"default\"\n")
	return p
}

func TestBootloaderUpdates(t *testing.T) {
	const cur = 1769002727 // 2026-01-21
	p := eepromTree(t, cur)
	dir := filepath.Join(p.Firmware, "bootloader-2712", "default")
	write(t, dir+"/pieeprom-2026-01-21.bin", "\x00\x01BUILD_TIMESTAMP=1769002727\x00")
	if got := BootloaderUpdates(p); len(got) != 0 {
		t.Fatalf("same image: %v", got)
	}
	// A newer image only in the latest release does not count: the box
	// follows default.
	write(t, filepath.Join(p.Firmware, "bootloader-2712", "latest", "pieeprom-2026-10-01.bin"), "BUILD_TIMESTAMP=1790000000")
	if got := BootloaderUpdates(p); len(got) != 0 {
		t.Fatalf("other release: %v", got)
	}
	write(t, dir+"/pieeprom-2026-09-25.bin", "junk BUILD_TIMESTAMP=1790351949\x00more")
	got := BootloaderUpdates(p)
	if keys(got) != "eeprom:1790351949" || !strings.Contains(got[0].Text, "2026-09-25 is available, 2026-01-21 runs") {
		t.Fatalf("available: %v", got)
	}
	// Staged: rpi-eeprom-update -a ran.
	write(t, p.Staged, "BUILD_TIMESTAMP=1790351949")
	got = BootloaderUpdates(p)
	if keys(got) != "eeprom-staged:1790351949" || !strings.Contains(got[0].Text, "at the next reboot") {
		t.Fatalf("staged: %v", got)
	}
	// After the flash, the old staged file can stay; it is not newer.
	q := eepromTree(t, 1790351949)
	q.Firmware, q.Staged = p.Firmware, p.Staged
	if got := BootloaderUpdates(q); len(got) != 0 {
		t.Fatalf("flashed: %v", got)
	}
	// A box with no EEPROM bootloader (the lab gateway).
	q.BootTS = q.BootTS + ".none"
	if got := BootloaderUpdates(q); len(got) != 0 {
		t.Fatalf("no eeprom: %v", got)
	}
	// A release name cannot leave the firmware tree.
	write(t, p.EEPROMConf, "FIRMWARE_RELEASE_STATUS=../../x\n")
	if rel := eepromRelease(p.EEPROMConf); rel != "default" {
		t.Fatalf("release %q", rel)
	}
}

func TestReleaseUpdates(t *testing.T) {
	d := t.TempDir()
	p := UpdatePaths{Lists: d + "/lists", OSRelease: d + "/os-release"}
	write(t, p.OSRelease, "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_CODENAME=trixie\n")
	rel := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: Debian\nSuite: %s\nCodename: trixie\n"
	write(t, p.Lists+"/archive.raspberrypi.com_debian_dists_trixie_InRelease", "Origin: Raspberry Pi Foundation\nSuite: trixie\n")
	write(t, p.Lists+"/deb.debian.org_debian_dists_trixie_InRelease", strings.Replace(rel, "%s", "stable", 1))
	if got := ReleaseUpdates(p); len(got) != 0 {
		t.Fatalf("stable: %v", got)
	}
	write(t, p.Lists+"/deb.debian.org_debian_dists_trixie_InRelease", strings.Replace(rel, "%s", "oldstable", 1))
	if got := keys(ReleaseUpdates(p)); got != "release:trixie:oldstable" {
		t.Fatalf("oldstable: %q", got)
	}
}

func TestPackageUpdates(t *testing.T) {
	sim := `NOTE: This is only a simulation!
Inst tzdata [2026c-0+deb13u1] (2026e-0+deb13u1 Debian:13-updates/stable-updates [all])
Inst openssl [3.5.1-1] (3.5.1-1+deb13u2 Debian-Security:13/stable-security [arm64])
Inst linux-image-rpi-2712 [1:6.18.50-1+rpt1] (1:6.18.55-1+rpt1 Raspberry Pi Foundation:stable [arm64])
Inst libnew (1.0-1 Debian-Security:13/stable-security [arm64])
Conf openssl (3.5.1-1+deb13u2 Debian-Security:13/stable-security [arm64])
Inst broken
`
	got := keys(PackageUpdates(sim))
	if got != "pkg:openssl=3.5.1-1+deb13u2 pkg:linux-image-rpi-2712=1:6.18.55-1+rpt1 pkg:libnew=1.0-1" {
		t.Fatalf("keys %q", got)
	}
	for _, u := range PackageUpdates(sim) {
		if u.Wait != PackageWait {
			t.Fatalf("%s waits %v", u.Key, u.Wait)
		}
	}
}
