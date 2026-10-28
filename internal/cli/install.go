package cli

import (
	"io"
	"os"
	"runtime"

	"pi-fortress/internal/install"
)

func releaseURLEnv() string { return os.Getenv("PF_RELEASE_URL") }

// runInstall is `pf install`: docs/gateway_install.md. install.sh is the
// usual caller. (Before this runs, it has already downloaded the bundle
// and checked its signature.) But each flag here also works when run by
// hand, -bundle/-sig included, for the offline PF_BUNDLE path and for a
// local box.
func runInstall(args []string, stdout, stderr io.Writer) int {
	in := install.Defaults()
	in.Arch = runtime.GOARCH
	in.ReleaseURL = releaseURLEnv()
	in.Stdout, in.Stderr = stdout, stderr
	fs := newFlags("install", stderr)
	fs.StringVar(&in.Bundle, "bundle", "", "verified release bundle tar (install.sh sets this)")
	fs.StringVar(&in.Sig, "sig", "", "the bundle's .sig")
	fs.StringVar(&in.SignersPath, "signers", "", "public release allowed_signers ("+install.DefaultSignersPath+" if empty)")
	fs.StringVar(&in.WAN, "wan", "", "uplink interface (default: proposed from the default route)")
	fs.StringVar(&in.Agent, "agent", "", "agent-segment interface (default: proposed)")
	fs.StringVar(&in.House, "house", "", "optional house-segment interface")
	fs.BoolVar(&in.Yes, "yes", false, "non-interactive: fail rather than prompt if -wan/-agent were not both resolved")
	fs.StringVar(&in.Journal, "journal", "", "disk: keep the system journal on the disk across reboots; ram: in RAM only (default: ask, or ram without the wizard)")
	fs.StringVar(&in.Dir, "dir", in.Dir, "live tree")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if err := in.Run(); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// runUpgrade is `pf upgrade`: fetch (or take -bundle/-sig directly),
// verify, stage, swap and apply, under a transient systemd unit. Thus a
// lost SSH session cannot kill it half way. -confirm only execs
// `pf ship confirm`.
func runUpgrade(args []string, stdout, stderr io.Writer) int {
	u := install.DefaultUpgrade()
	u.Arch = runtime.GOARCH
	u.Stdout, u.Stderr = stdout, stderr
	fs := newFlags("upgrade", stderr)
	fs.StringVar(&u.Version, "version", "", "release tag to upgrade to, e.g. v0.1.0 (required)")
	fs.StringVar(&u.Bundle, "bundle", "", "local bundle tar instead of fetching")
	fs.StringVar(&u.Sig, "sig", "", "the bundle's .sig")
	fs.StringVar(&u.Sums, "sums", "", "the release's SHA256SUMS for -bundle (its .sig beside it); default: next to -bundle")
	fs.StringVar(&u.SignersPath, "signers", "", "public release allowed_signers ("+install.DefaultSignersPath+" if empty)")
	fs.StringVar(&u.Dir, "dir", u.Dir, "live tree")
	fs.BoolVar(&u.Confirm, "confirm", false, "disarm the post-upgrade dead-man timer (execs pf ship confirm)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if u.Bundle == "" && !u.Confirm {
		releaseURL, err := install.ResolveReleaseURL(releaseURLEnv(), install.ReleaseURLPath)
		if err != nil {
			return fail(stderr, err)
		}
		u.ReleaseURL = releaseURL
	}
	if err := u.Run(); err != nil {
		return fail(stderr, err)
	}
	return 0
}
