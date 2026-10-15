// Package install is `pf install` and `pf upgrade`. It changes a stock Pi
// OS, Debian or Ubuntu box into a running gateway from a signed release
// bundle. It also moves an existing gateway to a newer one.
// docs/gateway_install.md is the runbook.
package install

import (
	"fmt"
	"os"
	"strings"
)

// Target is what install.sh and pf install must both agree a box is,
// before either of them touches it. Arch comes from the Go runtime (the
// binary that runs already answers that question). OS comes from
// /etc/os-release plus, on arm64, the device-tree model that apply.sh
// itself already gates on. (The os-release of Raspberry Pi OS is
// byte-for-byte that of Debian. Thus os-release alone cannot tell the
// two apart.)
type Target struct {
	Arch      string // "arm64" or "amd64", the two pf ships
	ID        string // /etc/os-release ID: "debian", "ubuntu"
	VersionID string // /etc/os-release VERSION_ID: "12", "13", "24.04"
	Codename  string // /etc/os-release VERSION_CODENAME: "bookworm", "trixie"
	Model     string // /proc/device-tree/model, trimmed of NULs; "" off a Pi
}

// Supported names what the message of install.sh and the refusal of pf
// install both promise: Raspberry Pi OS Lite 64-bit (bookworm/trixie) on
// arm64, Debian 12/13 or Ubuntu 24.04 on amd64. All else is refused, not guessed.
func (t Target) Supported() (label string, ok bool) {
	switch t.Arch {
	case "arm64":
		if strings.Contains(t.Model, "Raspberry Pi") && t.ID == "debian" && (t.Codename == "bookworm" || t.Codename == "trixie") {
			return fmt.Sprintf("Raspberry Pi OS Lite 64-bit (%s)", t.Codename), true
		}
		return "", false
	case "amd64":
		if t.ID == "debian" && (t.VersionID == "12" || t.VersionID == "13") {
			return fmt.Sprintf("Debian %s amd64", t.VersionID), true
		}
		if t.ID == "ubuntu" && t.VersionID == "24.04" {
			return "Ubuntu 24.04 amd64", true
		}
		return "", false
	default:
		return "", false
	}
}

// Refusal is the message that pf install prints and fails with when
// Supported is false: what was detected, and what is accepted. Thus
// nobody must file a report to learn either.
func (t Target) Refusal() string {
	model := t.Model
	if model == "" {
		model = "no Raspberry Pi model"
	}
	return fmt.Sprintf(
		"pf install: unsupported target arch=%s id=%s version=%s codename=%s (%s); "+
			"supported: Raspberry Pi OS Lite 64-bit bookworm/trixie on arm64, Debian 12/13 or Ubuntu 24.04 on amd64",
		orDash(t.Arch), orDash(t.ID), orDash(t.VersionID), orDash(t.Codename), model)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ParseOSRelease is the /etc/os-release format: KEY=VALUE lines, values
// optionally double-quoted, comments and blanks ignored. This is the shape
// that os-release(5) documents and that each distro that ships one follows.
func ParseOSRelease(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// DetectTarget reads the real files. The caller passes arch in
// (runtime.GOARCH at the call site); this function does not read it.
// Thus the full function stays a pure-enough transform of two file reads,
// and the tests of DetectTargetFrom can exercise it without a chroot.
func DetectTarget(arch string) (Target, error) {
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return Target{}, fmt.Errorf("pf install: /etc/os-release: %w", err)
	}
	model, _ := os.ReadFile("/proc/device-tree/model") // absent off a Pi; not an error
	return DetectTargetFrom(arch, string(osRelease), string(model)), nil
}

// DetectTargetFrom is the pure half DetectTarget calls into.
func DetectTargetFrom(arch, osRelease, model string) Target {
	kv := ParseOSRelease(osRelease)
	return Target{
		Arch:      arch,
		ID:        kv["ID"],
		VersionID: kv["VERSION_ID"],
		Codename:  kv["VERSION_CODENAME"],
		Model:     strings.TrimRight(strings.TrimSpace(strings.Trim(model, "\x00")), "\x00"),
	}
}
