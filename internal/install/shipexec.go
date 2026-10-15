package install

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"pi-fortress/internal/ship"
)

// ShipInstallArgs builds the argv for `pf ship install` with the
// public download identity (DistNamespace/DistPrincipal,
// docs/gateway_install.md "Two signers, on purpose"). pf install and pf
// upgrade both send their stage/swap/apply/doctor/pending/releases/
// state-gate work through the Installer of internal/ship this way. They
// do not duplicate its wiring.
func ShipInstallArgs(incoming, signers, dir string, extra ...string) []string {
	args := []string{
		"ship", "install",
		"-incoming", incoming,
		"-signers", signers,
		"-namespace", DistNamespace,
		"-principal", DistPrincipal,
		"-dir", dir,
	}
	return append(args, extra...)
}

// execShipInstall runs `pf ship install` as an ordinary child process
// (no systemd-run). pf install already runs synchronously in the
// foreground. A dropped connection would interrupt install.sh, not
// this step. Thus there is no dropped-session concern here, as there
// is for pf upgrade.
func execShipInstall(pfExe string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.Command(pfExe, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// currentPF is the pf binary of this process. pf install and pf upgrade
// are both compiled into the same executable that already implements
// `ship install`. Thus a new call to it by its own running path needs
// no separate install of a helper binary first.
func currentPF() (string, error) {
	return os.Executable()
}

// NewIncomingDir makes a new, root-only directory with a unique name
// under base (for example /var/lib/pi-fortress/upgrade or
// /var/lib/pi-fortress/install). Thus one pf upgrade/pf install run gets
// its own pf-bundle.tar/.sig pair that nothing else touches. This is the
// shape that the Incoming of ship.Installer expects. It is safe to run
// more than once concurrently, because each call gets a distinct name.
func NewIncomingDir(base string) (string, error) {
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	dir := filepath.Join(base, hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// PlaceBundle puts bundle and sig into dir under the names that the
// Incoming of ship.Installer expects (ship.BundleName / ship.SigName).
// It makes a hard link when possible, and a copy across devices.
func PlaceBundle(bundle, sig, dir string) (tar, sigOut string, err error) {
	tar = filepath.Join(dir, ship.BundleName)
	sigOut = filepath.Join(dir, ship.SigName)
	if err := linkOrCopy(bundle, tar); err != nil {
		return "", "", err
	}
	if err := linkOrCopy(sig, sigOut); err != nil {
		return "", "", err
	}
	return tar, sigOut, nil
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
