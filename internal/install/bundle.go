package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"pi-fortress/internal/ship"
)

// DistNamespace and DistPrincipal are the identity of the public release
// signer (docs/release.md "Signing"). Each pf-bundle-<ver>-<arch>.tar that
// the phase-0 build makes is signed the same way as SHA256SUMS: `ssh-keygen
// -Y sign -n pi-fortress-dist`. On purpose, this is not the Namespace
// ("pi-fortress-release") and Principal ("release") of internal/ship. That
// pair is the desktop-to-Pi push in signed_ship.md: a different key with a
// different blast radius. (The holder of that key can push directly to /opt
// on each Pi that trusts it, with no review.) If this package used it here,
// the public download key of a stock box would also be its ship-push key
// when pf install writes one allowed_signers line for both. This package
// must not make that decision quietly. They stay two files:
// /etc/pi-fortress/allowed_signers (ship pushes, signed_ship.md) and
// /etc/pi-fortress/release-signers (public bundles, this file).
const (
	DistNamespace = "pi-fortress-dist"
	DistPrincipal = "release@pi-fortress"
)

// DefaultSignersPath is where pf install and pf upgrade look for the
// public release key when -signers is not given. install.sh writes it
// from its embedded PF_SIGNER_PUBKEY before it runs pf install. Thus,
// when pf install or a later pf upgrade reads it, the box already
// trusts exactly the key that install.sh was built with.
const DefaultSignersPath = "/etc/pi-fortress/release-signers"

// VerifyBundle calls ssh-keygen -Y verify through a shell. It uses
// ship.KeygenVerify, the same call that internal/ship makes, for the same
// reason: this package does not implement SSHSIG parsing again (sk-ssh-ed25519
// hardware-key flags included). namespace and principal are
// DistNamespace and DistPrincipal for each caller in this tree. They are
// parameters only so that a test can use a throwaway key, and not touch
// the real namespace constants.
func VerifyBundle(signers, bundle, sig, namespace, principal string) error {
	st, err := os.Lstat(signers)
	if err != nil {
		return fmt.Errorf("%s: %w; every bundle is refused until it exists (docs/gateway_install.md)", signers, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&022 != 0 {
		return fmt.Errorf("%s must be a regular file, not group- or world-writable", signers)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && int(sys.Uid) != 0 {
		return fmt.Errorf("%s must be owned by root", signers)
	}
	return ship.KeygenVerify(sshKeygen, signers, principal, namespace, bundle, sig)
}

// sshKeygen is the absolute path that pf ship install also uses. pf
// install runs as root, and a bare name would resolve through the PATH
// of the caller. Tests set it to the ssh-keygen on their PATH.
var sshKeygen = ship.Defaults().Keygen

// stampName is a copy of the unexported constant of the same name in
// internal/ship (install.go): the floor as the live tree itself carries
// it. Thus a power cut between a swap and the write of the version file
// cannot reset the replay guard. Keep it in sync by hand. internal/ship
// owns that file, and this one does not touch it (AGENTS.md: minimal
// edits, other agents' files).
const stampName = ".pf-ship-version"

// CurrentFloor reads the version that this box last installed: the
// higher of the sidecar file and the stamp of the live tree. readVersion
// in internal/ship/install.go applies the same rule, for the same reason
// (a stamp can get ahead of the file across a crash). A missing file or
// tree is floor zero. That lets a first install continue.
func CurrentFloor(dir, versionPath string) (int64, error) {
	var file int64
	raw, err := os.ReadFile(versionPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		s := strings.TrimSpace(string(raw))
		if s != "" {
			file, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("%s: unreadable version %q", versionPath, s)
			}
		}
	}
	stamp, err := treeStamp(dir)
	if err != nil {
		return 0, err
	}
	return max(file, stamp), nil
}

// treeStamp is the version the tree at dir carries; zero for a tree
// that never took a ship, or no tree at all.
func treeStamp(dir string) (int64, error) {
	if dir == "" {
		return 0, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, stampName))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, nil
	case err != nil:
		return 0, err
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: unreadable stamp %q", filepath.Join(dir, stampName), s)
	}
	return v, nil
}

// CurrentFloor is also what pf install and pf upgrade compare the version
// of a newly opened bundle with, before they do anything else (except the
// network wizard). At or below the floor means "already installed" or "a
// downgrade". They handle that without `pf ship install`. To move the
// floor forward is now the job of internal/ship (writeVersion of pf ship
// install, called after its swap). This package only reads it.
