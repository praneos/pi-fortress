package ship

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// labMarker is the file that apply.sh reads to enable lab-only wiring.
// No bundle entry goes to it: the bundle unpacks under
// /opt/pi-fortress. A script line puts it there: the touch of
// provision.sh under PF_LAB=1. Thus the lint checks that line.
const labMarker = "/etc/pi-fortress/lab"

// labEchoFlag is the argv piece that lets the fence reflect live
// tokens. It is meant to run only when labMarker exists.
const labEchoFlag = "-lab-echo"

// LintBundle reads a bundle tar from start to end and refuses two
// things. First, a script line that creates the lab marker without a
// PF_LAB test on the nearest preceding non-blank line. Second, a line
// that holds -lab-echo whose nearest preceding non-blank line does not
// test for the marker. It is a content check, not a signature or
// manifest check. release.sh runs it immediately after a bundle is
// built and before it is signed. release-lint runs it again over
// whatever is already in a dist directory.
//
// On purpose, the guard test is narrow. It does not parse shell. It
// only checks that the specific pattern that vm/pi/apply.sh already
// uses still holds: an `if [[ -f /etc/pi-fortress/lab ]]; then`
// directly above the line that sets the flag. All other cases (no
// guard, a guard several lines away, a guard on a different condition)
// fail loudly. The lint does not trust the bundle because the current
// apply.sh is written this way.
func LintBundle(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("lint: %w", err)
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != '\x00' {
			continue
		}
		if !lintableUnit(name) {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, 32<<20))
		if err != nil {
			return fmt.Errorf("lint: %s: %w", name, err)
		}
		if err := lintLabEcho(name, raw); err != nil {
			return err
		}
		if err := lintLabMarker(name, raw); err != nil {
			return err
		}
	}
	return nil
}

// lintableUnitSuffixes is what can enable -lab-echo at runtime: a
// shell script that writes it into an env file, a systemd unit or
// path/timer, or the env file itself. Documentation, Go source and
// tests mention the flag in prose, or as a registered flag name without
// a leading dash. They would otherwise give a false positive on the
// exact same substring.
var lintableUnitSuffixes = []string{".sh", ".service", ".timer", ".path", ".env", ".env.example", ".env.local.example"}

func lintableUnit(name string) bool {
	for _, suf := range lintableUnitSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

func lintLabEcho(name string, raw []byte) error {
	if !bytes.Contains(raw, []byte(labEchoFlag)) {
		return nil
	}
	prevNonBlank := ""
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		isComment := strings.HasPrefix(trimmed, "#")
		if !isComment && strings.Contains(line, labEchoFlag) && !strings.Contains(prevNonBlank, "-f /etc/pi-fortress/lab") {
			return fmt.Errorf("lint: %s: %q sets -lab-echo without an immediately preceding `-f /etc/pi-fortress/lab` guard", name, trimmed)
		}
		if trimmed != "" {
			prevNonBlank = line
		}
	}
	return nil
}

// lintLabMarker refuses a line that writes the lab marker (touch,
// install, cp or a redirect onto it), unless the nearest preceding
// non-blank line tests PF_LAB. provision.sh uses that pattern. If a
// release box ran such a line without a guard, it would enable the echo
// for each install.
func lintLabMarker(name string, raw []byte) error {
	if !bytes.Contains(raw, []byte(labMarker)) {
		return nil
	}
	prevNonBlank := ""
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") && writesLabMarker(trimmed) && !strings.Contains(prevNonBlank, "PF_LAB") {
			return fmt.Errorf("lint: %s: %q creates %s without an immediately preceding PF_LAB test", name, trimmed, labMarker)
		}
		if trimmed != "" {
			prevNonBlank = line
		}
	}
	return nil
}

func writesLabMarker(line string) bool {
	if !strings.Contains(line, labMarker) {
		return false
	}
	for _, w := range []string{">" + labMarker, "> " + labMarker, ">>" + labMarker, ">> " + labMarker} {
		if strings.Contains(line, w) {
			return true
		}
	}
	verb := false
	for _, f := range strings.Fields(line) {
		switch f {
		case "touch", "install", "cp", "mv", "ln", "tee":
			verb = true
		case labMarker, labMarker + ";":
			if verb {
				return true
			}
		}
	}
	return false
}
