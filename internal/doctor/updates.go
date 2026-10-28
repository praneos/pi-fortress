package doctor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UpdatePaths are the files that the update check reads. Tests point them
// at a temporary directory.
type UpdatePaths struct {
	Reboot RebootPaths
	// BootTS is the build time of the running bootloader, in seconds, as
	// 4 bytes big endian. Only a board with an EEPROM bootloader has it.
	BootTS string
	// Compatible names the SoC. It selects bootloader-<chip>.
	Compatible string
	// Firmware holds bootloader-<chip>/<release>/pieeprom-*.bin.
	Firmware string
	// EEPROMConf sets FIRMWARE_RELEASE_STATUS, the release to follow.
	EEPROMConf string
	// Staged is the image that "rpi-eeprom-update -a" puts on the boot
	// partition. The bootloader writes it to the EEPROM at the next boot.
	Staged string
	// Lists is the directory of the apt lists. OSRelease gives the
	// codename of the release.
	Lists, OSRelease string
}

func DefaultUpdatePaths() UpdatePaths {
	return UpdatePaths{
		Reboot:     DefaultRebootPaths(),
		BootTS:     "/proc/device-tree/chosen/bootloader/build-timestamp",
		Compatible: "/proc/device-tree/compatible",
		Firmware:   "/usr/lib/firmware/raspberrypi",
		EEPROMConf: "/etc/default/rpi-eeprom-update",
		Staged:     "/boot/firmware/pieeprom.upd",
		Lists:      "/var/lib/apt/lists",
		OSRelease:  "/etc/os-release",
	}
}

// Update is one thing that waits for the operator. Key does not change
// while the thing stays the same. A new key is a new thing to tell.
type Update struct {
	Key, Text string
	// Wait is how long the thing must stay before it is told.
	Wait time.Duration
}

// PackageWait is how long an update from an origin that
// unattended-upgrades installs can stay pending before it is told. apt
// gets new lists twice a day and unattended-upgrades runs once a day. So a
// normal update goes in less than about 25 hours after the lists show it.
const PackageWait = 36 * time.Hour

// RebootUpdates are the installed updates that are not active until a
// reboot. They use the signals of RebootRung.
func RebootUpdates(p RebootPaths) []Update {
	var out []Update
	if _, err := readFile(p.Flag); err == nil {
		t := "reboot needed"
		if pkgs := rebootPkgs(p.Pkgs); pkgs != "" {
			t += " for " + pkgs
		}
		out = append(out, Update{Key: "reboot-flag", Text: t})
	}
	b, err := readFile(p.OSRelease)
	if err != nil {
		return out
	}
	running := strings.TrimSpace(string(b))
	switch newer, gone := kernelState(p.Modules, running); {
	case gone:
		out = append(out, Update{Key: "kernel-gone:" + running, Text: "running kernel " + running + " is no longer installed; reboot"})
	case newer != "":
		out = append(out, Update{Key: "kernel:" + newer, Text: "kernel " + newer + " is installed but " + running + " runs; reboot"})
	}
	return out
}

// BootloaderUpdates tells a bootloader image that is newer than the one
// that runs. A staged image flashes at the next reboot. An image that is
// only in the package needs "rpi-eeprom-update -a" and a reboot. A box
// with no EEPROM bootloader gives nothing.
func BootloaderUpdates(p UpdatePaths) []Update {
	b, err := readFile(p.BootTS)
	if err != nil || len(b) != 4 {
		return nil
	}
	cur := int64(binary.BigEndian.Uint32(b))
	if ts, ok := imageTS(p.Staged); ok && ts > cur {
		return []Update{{Key: fmt.Sprintf("eeprom-staged:%d", ts),
			Text: "bootloader " + day(ts) + " is staged and flashes at the next reboot"}}
	}
	chip := ""
	if c, err := readFile(p.Compatible); err == nil {
		for _, f := range bytes.Split(c, []byte{0}) {
			if s, ok := strings.CutPrefix(string(f), "brcm,bcm"); ok {
				chip = s
			}
		}
	}
	if chip == "" {
		return nil
	}
	imgs, _ := filepath.Glob(filepath.Join(p.Firmware, "bootloader-"+chip, eepromRelease(p.EEPROMConf), "pieeprom-*.bin"))
	if len(imgs) == 0 {
		return nil
	}
	// The names hold the date, so the last name is the newest image.
	sort.Strings(imgs)
	if ts, ok := imageTS(imgs[len(imgs)-1]); ok && ts > cur {
		return []Update{{Key: fmt.Sprintf("eeprom:%d", ts),
			Text: "bootloader " + day(ts) + " is available, " + day(cur) + " runs: sudo rpi-eeprom-update -a, then reboot"}}
	}
	return nil
}

// eepromRelease is the release that rpi-eeprom-update follows. The old
// names "critical" and "stable" are links in the firmware tree.
func eepromRelease(conf string) string {
	b, err := readFile(conf)
	if err != nil {
		return "default"
	}
	rel := "default"
	for l := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "FIRMWARE_RELEASE_STATUS="); ok {
			if v = strings.Trim(v, `"'`); v != "" && !strings.ContainsAny(v, "/.") {
				rel = v
			}
		}
	}
	return rel
}

// imageTS is the BUILD_TIMESTAMP that a bootloader image holds.
func imageTS(path string) (int64, bool) {
	b, err := readFile(path)
	if err != nil {
		return 0, false
	}
	const tag = "BUILD_TIMESTAMP="
	i := bytes.Index(b, []byte(tag))
	if i < 0 {
		return 0, false
	}
	b = b[i+len(tag):]
	n := 0
	for n < len(b) && n < 12 && b[n] >= '0' && b[n] <= '9' {
		n++
	}
	ts, err := strconv.ParseInt(string(b[:n]), 10, 64)
	return ts, err == nil && ts > 0
}

func day(ts int64) string { return time.Unix(ts, 0).UTC().Format("2006-01-02") }

// ReleaseUpdates tells when the Debian release of the box is no longer
// "stable": a new major release is out, and the old one gets security
// fixes for a limited time only. The apt lists already hold the Suite, so
// the check needs no network.
func ReleaseUpdates(p UpdatePaths) []Update {
	code := osField(p.OSRelease, "VERSION_CODENAME")
	if code == "" {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(p.Lists, "*_dists_"+code+"_InRelease"))
	for _, f := range files {
		b, err := readFile(f)
		if err != nil {
			continue
		}
		origin, suite := "", ""
		for l := range strings.SplitSeq(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Origin: "); ok && origin == "" {
				origin = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(l, "Suite: "); ok && suite == "" {
				suite = strings.TrimSpace(v)
			}
		}
		if origin == "Debian" && strings.HasPrefix(suite, "old") {
			return []Update{{Key: "release:" + code + ":" + suite,
				Text: "Debian " + code + " is now " + suite + ": a new major release is out, and " + code + " gets security fixes for a limited time; plan the upgrade"}}
		}
	}
	return nil
}

func osField(path, key string) string {
	b, err := readFile(path)
	if err != nil {
		return ""
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// PackageUpdates reads the output of "apt-get -s dist-upgrade" and gives
// one Update for each package from an origin that unattended-upgrades
// installs (the security archive and the Raspberry Pi archive, which
// ships the kernel and the firmware). Such a package must not stay
// pending: when it does, unattended-upgrades fails or holds it. A line
// is:
//
//	Inst openssl [3.0.11-1] (3.0.13-1 Debian-Security:13/stable-security [arm64])
func PackageUpdates(sim string) []Update {
	var out []Update
	for l := range strings.SplitSeq(sim, "\n") {
		rest, ok := strings.CutPrefix(l, "Inst ")
		if !ok {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		i := strings.IndexByte(rest, '(')
		if name == "" || i < 0 {
			continue
		}
		ver, origins, _ := strings.Cut(rest[i+1:], " ")
		if ver == "" || !(strings.Contains(origins, "-security") || strings.Contains(origins, "Debian-Security") ||
			strings.Contains(origins, "Raspberry Pi")) {
			continue
		}
		out = append(out, Update{Key: "pkg:" + name + "=" + ver, Text: name + " " + ver, Wait: PackageWait})
	}
	return out
}
