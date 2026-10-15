package install

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"pi-fortress/internal/ship"
)

// ReleaseURLPath is where pf upgrade looks for PF_RELEASE_URL when the
// environment does not set it. A box that install.sh set up keeps its
// release base URL here. Thus `pf upgrade` with no flags works later from
// a plain root shell, the same as apt does not need its sources.list again
// on each invocation.
const ReleaseURLPath = "/etc/pi-fortress/release.url"

// BuildUpgradeURL is the naming contract with the release build
// (make release emits
// pf-bundle-<ver>-{arm64,amd64}.tar plus .sig) and with install.sh, which
// builds the same two names for its first download. version is a release
// tag and is required: an asset's name carries its tag, so there is no
// fixed "latest" path to build. base loses one trailing slash.
func BuildUpgradeURL(base, version, arch string) (tarURL, sigURL string, err error) {
	if base == "" {
		return "", "", errors.New("pf upgrade: no release URL (PF_RELEASE_URL, or " + ReleaseURLPath + ")")
	}
	if version == "" || version == "latest" {
		return "", "", errors.New("pf upgrade: set -version to a release tag from the Releases page, e.g. -version v0.1.0")
	}
	if !validTag(version) {
		return "", "", fmt.Errorf("pf upgrade: -version %q is not a release tag (letters, digits and . _ + - only)", version)
	}
	if arch == "" {
		return "", "", errors.New("pf upgrade: no arch")
	}
	base = strings.TrimSuffix(base, "/")
	tarURL = fmt.Sprintf("%s/%s/%s", base, version, BundleAssetName(version, arch))
	return tarURL, tarURL + ".sig", nil
}

// SumsName is the release's checksum list (docs/release.md), signed
// with the same identity as each bundle.
const SumsName = "SHA256SUMS"

var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// validTag is valid_tag of install.sh: a release tag, and nothing that a
// URL path or a file name could read as more than one segment.
func validTag(v string) bool {
	return len(v) <= 128 && v != "latest" && tagRE.MatchString(v)
}

// BundleAssetName is the release asset that make release publishes for
// version and arch. SHA256SUMS lists the asset under this name.
func BundleAssetName(version, arch string) string {
	return fmt.Sprintf("pf-bundle-%s-%s.tar", version, arch)
}

// VerifyRelease is the check of install.sh: SHA256SUMS verified with the
// release identity, exactly one entry for name, the sha256 of tar equal
// to it, then the .sig of tar. The .sig alone proves only that the key
// signed those bytes at some time. The name in the signed list binds them
// to a tag and an arch. Thus it refuses an old signed bundle, or the
// bundle of the other arch, served under this name.
func VerifyRelease(signers, tar, sig, sums, sumsSig, name string) error {
	if err := VerifyBundle(signers, sums, sumsSig, DistNamespace, DistPrincipal); err != nil {
		return fmt.Errorf("SHA256SUMS signature verification failed; refusing a checksum list the release key did not sign: %w", err)
	}
	want, err := sumsEntry(sums, name)
	if err != nil {
		return err
	}
	have, err := sha256File(tar)
	if err != nil {
		return err
	}
	if have != want {
		return fmt.Errorf("%s does not match its SHA256SUMS entry; refusing a bundle that is not the release it is named for (another arch's or another tag's bundle under this name)", name)
	}
	if err := VerifyBundle(signers, tar, sig, DistNamespace, DistPrincipal); err != nil {
		return fmt.Errorf("refusing unverified bundle: %w", err)
	}
	return nil
}

func sumsEntry(sums, name string) (string, error) {
	f, err := os.Open(sums)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var hits []string
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if h := fields[0]; len(h) == 64 && strings.Trim(h, "0123456789abcdef") == "" {
			hits = append(hits, h)
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("SHA256SUMS: %w", err)
	}
	if len(hits) != 1 {
		return "", fmt.Errorf("the signed SHA256SUMS does not list %s exactly once; refusing a bundle its release does not name (wrong tag or arch, or another release's SHA256SUMS)", name)
	}
	return hits[0], nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ResolveReleaseURL is PF_RELEASE_URL if set, else the contents of
// ReleaseURLPath (first line, trimmed), else a refusal naming both.
// Either source must be https (CheckReleaseURL).
func ResolveReleaseURL(env, filePath string) (string, error) {
	u := env
	if u == "" {
		if raw, err := os.ReadFile(filePath); err == nil {
			u = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
		}
	}
	if u == "" {
		return "", fmt.Errorf("pf upgrade: no release URL: set PF_RELEASE_URL or write it to %s", filePath)
	}
	if err := CheckReleaseURL(u); err != nil {
		return "", fmt.Errorf("pf upgrade: %w", err)
	}
	return u, nil
}

// httpsOnlyRedirect is the CheckRedirect of the download client. GitHub
// sends each release asset through a redirect, and the Go default follows
// a redirect to plain http.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect to %s: releases are fetched over https only", req.URL.Redacted())
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// downloadFile GETs url into dst (0644). It refuses a non-200 status or a
// body over max bytes. That is the same order of magnitude as
// internal/ship.DefaultLimits.MaxTotal, because this is the same kind of
// bundle, only fetched over HTTP in place of the rsync of pfship.
func downloadFile(client *http.Client, url, dst string, max int64) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if n > max {
		return fmt.Errorf("%s: over %d bytes", url, max)
	}
	return nil
}

// FetchAndVerify downloads the tar and sig for version/arch, and the
// SHA256SUMS of the release and its .sig, from releaseURL into dir. It
// binds the tar to its tag and arch, verifies it (VerifyRelease), and
// returns the path of the tar. SHA256SUMS does not stay in dir. Nothing
// is staged or applied here, and a bad signature leaves no bundle. The
// dead-man design assumes that this refusal occurs before anything
// about the box changes. The two files go under
// ship.BundleName/ship.SigName, the names that the Incoming of
// ship.Installer expects. Thus dir can go directly to `pf ship install -incoming`.
func FetchAndVerify(client *http.Client, releaseURL, version, arch, signers, dir string) (tarPath string, err error) {
	tarURL, sigURL, err := BuildUpgradeURL(releaseURL, version, arch)
	if err != nil {
		return "", err
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: httpsOnlyRedirect}
	}
	tar := filepath.Join(dir, ship.BundleName)
	sig := filepath.Join(dir, ship.SigName)
	sums := filepath.Join(dir, SumsName)
	sumsSig := sums + ".sig"
	defer os.Remove(sums)
	defer os.Remove(sumsSig)
	sumsURL := strings.TrimSuffix(tarURL, BundleAssetName(version, arch)) + SumsName
	for _, f := range []struct {
		url, dst string
		max      int64
	}{
		{tarURL, tar, ship.DefaultLimits.MaxTotal + 1<<20},
		{sigURL, sig, 64 << 10},
		{sumsURL, sums, 1 << 20},
		{sumsURL + ".sig", sumsSig, 64 << 10},
	} {
		if err := downloadFile(client, f.url, f.dst, f.max); err != nil {
			os.Remove(tar)
			os.Remove(sig)
			return "", fmt.Errorf("pf upgrade: %w", err)
		}
	}
	if err := VerifyRelease(signers, tar, sig, sums, sumsSig, BundleAssetName(version, arch)); err != nil {
		os.Remove(tar)
		os.Remove(sig)
		return "", fmt.Errorf("pf upgrade: %w", err)
	}
	return tar, nil
}

// placeLocal is pf upgrade -bundle: the same binding that install.sh gives
// PF_BUNDLE. The tag comes from the file name. The name must be
// pf-bundle-<tag>-<arch>.tar for this arch (and match -version if
// given). SHA256SUMS and its .sig are beside it or at sums. All four are
// copied into dir first, and only the copies are checked and staged: the
// caller may still be able to write the originals.
func (u *Upgrade) placeLocal(dir string) (string, error) {
	name := filepath.Base(u.Bundle)
	suffix := "-" + u.Arch + ".tar"
	tag := strings.TrimSuffix(strings.TrimPrefix(name, "pf-bundle-"), suffix)
	if u.Arch == "" || !strings.HasPrefix(name, "pf-bundle-") || !strings.HasSuffix(name, suffix) || !validTag(tag) {
		return "", fmt.Errorf("pf upgrade: -bundle %s is not named pf-bundle-<tag>-%s.tar as published; the name, listed in the release's signed SHA256SUMS, is what binds a bundle to its tag and to this box's arch", name, u.Arch)
	}
	if u.Version != "" && u.Version != tag {
		return "", fmt.Errorf("pf upgrade: -version %s but -bundle is %s; refusing a bundle of another release", u.Version, name)
	}
	if u.Sig == "" {
		return "", errors.New("pf upgrade: -bundle needs -sig")
	}
	sumsSrc := u.Sums
	if sumsSrc == "" {
		sumsSrc = filepath.Join(filepath.Dir(u.Bundle), SumsName)
	}
	for _, p := range []string{sumsSrc, sumsSrc + ".sig"} {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("pf upgrade: no SHA256SUMS at %s (or no %s.sig); download both from the same release page as the bundle, or pass -sums", sumsSrc, sumsSrc)
		}
	}
	tar, sig := filepath.Join(dir, ship.BundleName), filepath.Join(dir, ship.SigName)
	sums := filepath.Join(dir, SumsName)
	defer os.Remove(sums)
	defer os.Remove(sums + ".sig")
	l := ship.DefaultLimits
	for _, f := range []struct {
		src, dst string
		max      int64
	}{
		{u.Bundle, tar, l.MaxTotal + l.MaxManifest + int64(2*l.MaxFiles)*1024 + 1<<20},
		{u.Sig, sig, 64 << 10},
		{sumsSrc, sums, 1 << 20},
		{sumsSrc + ".sig", sums + ".sig", 64 << 10},
	} {
		if err := copyOnce(f.src, f.dst, f.max); err != nil {
			return "", fmt.Errorf("pf upgrade: %w", err)
		}
	}
	if err := VerifyRelease(u.SignersPathOrDefault(), tar, sig, sums, sums+".sig", name); err != nil {
		return "", fmt.Errorf("pf upgrade: %w", err)
	}
	return tar, nil
}

// Upgrade is `pf upgrade`. It no longer stages, swaps or applies
// anything itself. It fetches (or takes) a verified bundle, puts it
// into a new incoming directory, and runs `pf ship install` on it
// with the public download identity. Thus an upgrade gets the same
// doctor, rollback, pending, releases and state-version gate as a
// desktop ship push (docs/signed_ship.md).
type Upgrade struct {
	Version     string // -version; a release tag, required
	Bundle, Sig string // -bundle/-sig: use these instead of fetching
	Sums        string // -sums: SHA256SUMS for -bundle; beside it if empty
	ReleaseURL  string // PF_RELEASE_URL, resolved by the caller
	SignersPath string // DefaultSignersPath if empty
	Arch        string // runtime.GOARCH at the real call site
	Confirm     bool   // -confirm: only exec `pf ship confirm`

	Dir string // live tree, passed to `pf ship install -dir`
	// UpgradeDir is the base for this run's incoming directory
	// (UpgradeDir/<unique>/); default /var/lib/pi-fortress/upgrade.
	UpgradeDir string

	Client         *http.Client
	Stdout, Stderr io.Writer

	// Wrap runs `pf ship install` under a transient systemd unit named
	// unit. Thus a dropped SSH session cannot kill it half way.
	// Overridable for tests. The
	// default execs systemd-run. When systemd-run is not on PATH (most
	// often a lab container image), it runs inline with a warning as a
	// fallback.
	Wrap func(unit, exe string, args []string, stdout, stderr io.Writer) error
	// RunConfirm execs `pf ship confirm`. Overridable for tests.
	RunConfirm func(stdout, stderr io.Writer) error
}

func DefaultUpgrade() *Upgrade {
	return &Upgrade{
		Dir:        "/opt/pi-fortress",
		UpgradeDir: "/var/lib/pi-fortress/upgrade",
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Wrap: func(unit, exe string, args []string, stdout, stderr io.Writer) error {
			if _, err := exec.LookPath("systemd-run"); err != nil {
				fmt.Fprintln(stderr, "pf upgrade: systemd-run not found; running inline (a dropped session would interrupt this)")
				cmd := exec.Command(exe, args...)
				cmd.Stdout, cmd.Stderr = stdout, stderr
				return cmd.Run()
			}
			argv := append([]string{"--unit=" + unit, "--wait", "--collect", "--", exe}, args...)
			cmd := exec.Command("systemd-run", argv...)
			cmd.Stdout, cmd.Stderr = stdout, stderr
			return cmd.Run()
		},
		RunConfirm: func(stdout, stderr io.Writer) error {
			cmd := exec.Command("pf", "ship", "confirm")
			cmd.Stdout, cmd.Stderr = stdout, stderr
			return cmd.Run()
		},
	}
}

func (u *Upgrade) out() io.Writer {
	if u.Stdout != nil {
		return u.Stdout
	}
	return os.Stdout
}

func (u *Upgrade) upgradeDir() string {
	if u.UpgradeDir != "" {
		return u.UpgradeDir
	}
	return "/var/lib/pi-fortress/upgrade"
}

// Run is the whole of `pf upgrade`: the root check, then doUpgrade.
// It is separate, so tests can run doUpgrade directly without root.
// The fetch/verify/incoming-dir/Wrap logic does not itself need
// privilege. Only the tree that it touches at the end needs it.
func (u *Upgrade) Run() error {
	if u.Confirm {
		return u.RunConfirm(u.out(), u.Stderr)
	}
	if os.Geteuid() != 0 {
		return errors.New("pf upgrade: must run as root")
	}
	return u.doUpgrade()
}

// SignersPathOrDefault is SignersPath, or DefaultSignersPath.
func (u *Upgrade) SignersPathOrDefault() string {
	if u.SignersPath == "" {
		return DefaultSignersPath
	}
	return u.SignersPath
}

func (u *Upgrade) doUpgrade() error {
	signers := u.SignersPathOrDefault()

	incoming, err := NewIncomingDir(u.upgradeDir())
	if err != nil {
		return fmt.Errorf("pf upgrade: %w", err)
	}
	defer os.RemoveAll(incoming)

	if u.Bundle != "" {
		_, err = u.placeLocal(incoming)
	} else {
		_, err = FetchAndVerify(u.Client, u.ReleaseURL, u.Version, u.Arch, signers, incoming)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(u.out(), "pf upgrade: SHA256SUMS and bundle signature verified")

	exe, err := currentPF()
	if err != nil {
		return fmt.Errorf("pf upgrade: %w", err)
	}
	args := ShipInstallArgs(incoming, signers, u.Dir)
	unit := "pf-upgrade-" + filepath.Base(incoming)
	if err := u.Wrap(unit, exe, args, u.out(), u.Stderr); err != nil {
		return fmt.Errorf("pf upgrade: %w", err)
	}
	fmt.Fprintln(u.out(), "pf upgrade: ship install finished; confirm within the dead-man window with `pf upgrade -confirm` (docs/gateway_install.md)")
	return nil
}
