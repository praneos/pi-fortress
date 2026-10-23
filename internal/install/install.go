package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pi-fortress/internal/render"
	"pi-fortress/internal/ship"
)

// AptPackages is the apt-get line of provision.sh (vm/pi/provision.sh).
// It is here again only so that pf install can print the next step,
// before it gives the real apt-get call to provision.sh. The package
// list is not duplicated logic, only an echo of it. provision.sh adds
// network-manager on a PF_LAB condition. A release install is never
// PF_LAB=1, so it is always wanted here.
var AptPackages = []string{
	"nftables", "dnsmasq", "wireguard", "wireguard-tools", "curl", "tcpdump",
	"iproute2", "ca-certificates", "dnsutils", "conntrack", "usb-modeswitch",
	"logrotate", "rsync", "python3", "chrony", "network-manager",
}

// Installer is `pf install`. Each path is a field, so tests can point it
// at a scratch directory in place of /etc and /opt.
type Installer struct {
	Arch string // runtime.GOARCH at the real call site

	Bundle, Sig string // from install.sh, or -bundle/-sig directly
	SignersPath string // public release key; DefaultSignersPath if empty

	WAN, Agent, House string // -wan/-agent/-house; empty means propose
	Yes               bool   // -yes: fail rather than prompt if WAN/Agent still empty after proposing

	Dir          string // /opt/pi-fortress
	VersionPath  string // /var/lib/pi-fortress/ship.version
	NetEnvLocal  string // /etc/pi-fortress/net.env.local
	HouseEnvPath string // /etc/pi-fortress/house.env
	LabMarker    string // /etc/pi-fortress/lab
	GatewayRole  string // /etc/pi-fortress/gateway.role; "" writes none
	SignersDest  string // where the verified signer file is kept for pf upgrade; "" keeps none
	ReleaseURL   string // PF_RELEASE_URL install.sh fetched from; "" for an offline bundle
	URLDest      string // ReleaseURLPath; "" keeps none
	InstalledPF  string // /usr/local/sbin/pf

	// WorkDir is a scratch tree. pf install extracts the bundle into it
	// only to give vm/pi/provision.sh a real tree to read from, before
	// ship.Installer (below) publishes the tree itself. Default
	// /var/lib/pi-fortress/install-work.
	WorkDir string
	// IncomingBase is the base directory for this run's fresh incoming
	// directory (IncomingBase/<unique>/), the shape ship.Installer's
	// Incoming expects; default /var/lib/pi-fortress/install.
	IncomingBase string

	// Stdin, when set, answers the wizard in place of TTY (tests). It is
	// never os.Stdin: under curl | sudo bash, that is the rest of the
	// script, or EOF, and each prompt would take its proposal.
	Stdin io.Reader
	// TTY opens the terminal of the operator for the wizard prompts:
	// /dev/tty. With no terminal (a headless run, no -wan/-agent/-yes),
	// the wizard refuses. It does not guess.
	TTY            func() (io.ReadCloser, error)
	Stdout, Stderr io.Writer

	// RunLink and RunRoute are `ip -j link` and `ip -j route show default`.
	// They are overridable, so a test can examine the wizard proposal
	// against fixture JSON without a real network stack.
	RunLink  func() ([]byte, error)
	RunRoute func() ([]byte, error)
	// RunProvision is vm/pi/provision.sh from the staged tree: apt
	// packages, the users and groups that apply.sh does not create itself
	// (docs/user_guide/pi_setup.md), policy defaults, and the pfship user
	// plus ship units (docs/signed_ship.md Setup) when a pubkey is
	// present. All of it is already idempotent. Thus pf install uses it
	// again, and does not keep a second copy of the same apt-get line and
	// useradd calls. Overridable, so install_test.go never runs apt-get.
	RunProvision func(src string, stdout, stderr io.Writer) error
	// RunPF runs the pf of the live tree (Dir/vm/pi/pf, else InstalledPF)
	// with args: pf apply and pf doctor --post-upgrade when the bundle is
	// the version that is already installed. It applies again and does not
	// skip, so a second pf install retries a first apply that failed.
	// Overridable, so install_test.go never execs a real pf.
	RunPF func(args []string, stdout, stderr io.Writer) error
	// HasDevice reports whether an interface is a hardware port
	// (SysfsHardware). docker0, br-*, virbr*, veth, tun/tap, VLAN
	// children, vnet and macvtap all report link_type ether. The
	// wizard must not propose them.
	HasDevice func(ifname string) bool
	// RunShipInstall execs `pf ship install` (the Installer of
	// internal/ship) on a newly built incoming directory, with the public
	// download identity: stage, swap (or, with no live tree yet, the
	// plain publish that the swap of ship.Installer already does for that
	// case), floor, apply and post-upgrade doctor. Overridable, so
	// install_test.go never execs a real pf binary.
	RunShipInstall func(args []string, stdout, stderr io.Writer) error
	// SSHIfaces names the interfaces that carry an inbound SSH session
	// now (LiveSSHIfaces). nil skips the check. Overridable, so a test
	// does not depend on the SSH sessions of the machine that runs it.
	SSHIfaces func() ([]string, error)
}

// Defaults fills each path with the real one. A test overwrites the paths
// that it must redirect.
func Defaults() *Installer {
	return &Installer{
		Dir:          "/opt/pi-fortress",
		VersionPath:  "/var/lib/pi-fortress/ship.version",
		NetEnvLocal:  "/etc/pi-fortress/net.env.local",
		HouseEnvPath: "/etc/pi-fortress/house.env",
		LabMarker:    "/etc/pi-fortress/lab",
		GatewayRole:  "/etc/pi-fortress/gateway.role",
		SignersDest:  DefaultSignersPath,
		URLDest:      ReleaseURLPath,
		InstalledPF:  "/usr/local/sbin/pf",
		SSHIfaces:    LiveSSHIfaces,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		RunLink: func() ([]byte, error) {
			return exec.Command("ip", "-j", "link").Output()
		},
		RunRoute: func() ([]byte, error) {
			return exec.Command("ip", "-j", "route", "show", "default").Output()
		},
		RunProvision: func(src string, stdout, stderr io.Writer) error {
			cmd := exec.Command("bash", filepath.Join(src, "vm/pi/provision.sh"))
			cmd.Env = append(os.Environ(), "SRC="+src, "PF_ALLOW_ANY_HOST=1", "PF_SHIP_APPLIES=1")
			cmd.Stdout, cmd.Stderr = stdout, stderr
			return cmd.Run()
		},
		RunShipInstall: func(args []string, stdout, stderr io.Writer) error {
			exe, err := currentPF()
			if err != nil {
				return err
			}
			return execShipInstall(exe, args, stdout, stderr)
		},
		HasDevice: SysfsHardware("/sys/class/net"),
		TTY: func() (io.ReadCloser, error) {
			return os.Open("/dev/tty")
		},
	}
}

// geteuid and detectTarget are the two host facts that Run reads before
// it touches anything. They are variables, so install_test.go can run Run
// unprivileged on any machine where the tests run.
var (
	geteuid      = os.Geteuid
	detectTarget = DetectTarget
)

// livePF is the pf that belongs to the tree at dir. This is the rule that
// applyPF of pf ship install uses: the vm/pi/pf of the tree when it is an
// executable regular file, else the installed one.
func livePF(dir, installed string) string {
	own := filepath.Join(dir, "vm", "pi", "pf")
	if st, err := os.Stat(own); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
		return own
	}
	if installed == "" {
		return "/usr/local/sbin/pf"
	}
	return installed
}

func (in *Installer) runPF(args ...string) error {
	if in.RunPF != nil {
		return in.RunPF(args, in.out(), in.Stderr)
	}
	cmd := exec.Command(livePF(in.Dir, in.InstalledPF), args...)
	cmd.Stdout, cmd.Stderr = in.out(), in.Stderr
	return cmd.Run()
}

func (in *Installer) out() io.Writer {
	if in.Stdout != nil {
		return in.Stdout
	}
	return os.Stdout
}

func (in *Installer) workDir() string {
	if in.WorkDir != "" {
		return in.WorkDir
	}
	return "/var/lib/pi-fortress/install-work"
}

func (in *Installer) incomingBase() string {
	if in.IncomingBase != "" {
		return in.IncomingBase
	}
	return "/var/lib/pi-fortress/install"
}

// Run is the whole of `pf install`. Root only. Each step is safe to run
// again (net.env.local and house.env are upserted, not truncated). A
// second `pf install` with the bundle already installed applies it
// again: pf apply and pf doctor --post-upgrade on the live tree, after
// the wizard saves its answers. Thus the same command, run again,
// completes a first install whose apply failed.
//
// Run copies the bundle one time into a root-only work directory. Only
// that copy is verified, extracted for provision.sh and given to
// pf ship install. -bundle names a path that the caller controls. To
// verify that path and then read it again would run whatever was
// swapped in between.
func (in *Installer) Run() error {
	if geteuid() != 0 {
		return errors.New("pf install: must run as root")
	}
	target, err := detectTarget(in.Arch)
	if err != nil {
		return err
	}
	label, ok := target.Supported()
	if !ok {
		return errors.New(target.Refusal())
	}
	fmt.Fprintf(in.out(), "pf install: target %s\n", label)

	if in.Bundle == "" || in.Sig == "" {
		return errors.New("pf install: -bundle and -sig are required; install.sh downloads and verifies these before running pf install")
	}
	if in.ReleaseURL != "" {
		if err := CheckReleaseURL(in.ReleaseURL); err != nil {
			return fmt.Errorf("pf install: %w", err)
		}
	}
	signers := in.SignersPath
	if signers == "" {
		signers = DefaultSignersPath
	}

	work := in.workDir()
	if err := os.RemoveAll(work); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(work), 0755); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := os.Mkdir(work, 0700); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	defer os.RemoveAll(work)
	bundle, sig, err := in.copyVerified(work, signers)
	if err != nil {
		return err
	}

	// Each answer is settled, and refused if it cannot work, before the
	// first file write. An agent segment on the uplink is a fence with
	// no inside. Nothing about it must reach the disk.
	if err := in.wizard(); err != nil {
		return err
	}
	if err := checkIfaces(in.WAN, in.Agent, in.House); err != nil {
		return err
	}
	if in.SSHIfaces != nil {
		ssh, err := in.SSHIfaces()
		if err != nil {
			fmt.Fprintf(in.out(), "pf install: warning: cannot tell which port carries this SSH session: %v\n", err)
		}
		if err := checkSSHPath(in.Agent, in.House, ssh); err != nil {
			return err
		}
	}

	if err := in.writeSettings(signers); err != nil {
		return err
	}

	floor, err := CurrentFloor(in.Dir, in.VersionPath)
	if err != nil {
		return fmt.Errorf("pf install: %w", err)
	}

	// A scratch extraction. It is removed after provision.sh reads what
	// it needs from it. The tree that pf ship install below publishes
	// is a separate extraction of the same verified copy, not this one
	// (docs/gateway_install.md "Known gaps"). Two extractions cost one
	// tar pass on a box that does this one time. In return, provision.sh
	// (apt packages, users, the pfship setup) runs before pf apply runs.
	// A new box needs that. An upgrade does not.
	next := filepath.Join(work, "tree")
	f, err := os.Open(bundle)
	if err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	m, err := ship.Extract(f, next, ship.DefaultLimits, 0)
	f.Close()
	if err != nil {
		return fmt.Errorf("pf install: reading bundle: %w", err)
	}
	if m.Version < floor {
		return fmt.Errorf("pf install: bundle version %d is older than the installed floor %d", m.Version, floor)
	}
	if m.Version == floor {
		return in.reapply(m.Version)
	}

	fmt.Fprintf(in.out(), "pf install: apt packages: %s\n", strings.Join(AptPackages, " "))
	if err := in.RunProvision(next, in.out(), in.Stderr); err != nil {
		return fmt.Errorf("pf install: vm/pi/provision.sh: %w", err)
	}

	incoming, err := NewIncomingDir(in.incomingBase())
	if err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	defer os.RemoveAll(incoming)
	if _, _, err := PlaceBundle(bundle, sig, incoming); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}

	// No pending file: a first install has no .prev to revert to. Thus a
	// confirm-or-revert timer would have nothing to roll back to.
	// pf doctor --post-upgrade still runs, and it still rolls back a
	// failed apply the ordinary way.
	args := ShipInstallArgs(incoming, signers, in.Dir, "-pending-file", "")
	if err := in.RunShipInstall(args, in.out(), in.Stderr); err != nil {
		return fmt.Errorf("pf install: ship install: %w", err)
	}
	fmt.Fprintf(in.out(), "pf install: version=%d sha=%s live at %s\n", m.Version, m.SHA, in.Dir)
	return nil
}

// copyVerified copies the bundle and its signature into work, and
// verifies the copy. It gives the paths of the copies.
func (in *Installer) copyVerified(work, signers string) (bundle, sig string, err error) {
	bundle, sig = filepath.Join(work, ship.BundleName), filepath.Join(work, ship.SigName)
	l := ship.DefaultLimits
	if err := copyOnce(in.Bundle, bundle, l.MaxTotal+l.MaxManifest+int64(2*l.MaxFiles)*1024+1<<20); err != nil {
		return "", "", fmt.Errorf("pf install: -bundle: %w", err)
	}
	if err := copyOnce(in.Sig, sig, 64<<10); err != nil {
		return "", "", fmt.Errorf("pf install: -sig: %w", err)
	}
	if err := VerifyBundle(signers, bundle, sig, DistNamespace, DistPrincipal); err != nil {
		return "", "", fmt.Errorf("pf install: %w", err)
	}
	fmt.Fprintln(in.out(), "pf install: bundle signature verified")
	return bundle, sig, nil
}

// writeSettings writes the release identity and the answers of the
// wizard to the box.
func (in *Installer) writeSettings(signers string) error {
	if err := SaveReleaseSigners(signers, in.SignersDest); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := SaveReleaseURL(in.ReleaseURL, in.URLDest); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := WriteNetEnvLocal(in.NetEnvLocal, in.WAN, in.Agent); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := WriteHouseEnv(in.HouseEnvPath, in.House); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if err := RemoveLabMarker(in.LabMarker); err != nil {
		return err
	}
	if err := WriteGatewayRole(in.GatewayRole); err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	fmt.Fprintf(in.out(), "pf install: wrote %s (INT_IF=%s WAN_IF=%s)\n", in.NetEnvLocal, in.Agent, in.WAN)
	return nil
}

// reapply is pf install, run again with the version already installed.
// pf ship install would refuse it as a replay. Before, this code skipped
// it, and a first install whose apply failed stayed unapplied
// permanently. The live tree must be that version. Do not apply blind
// when the floor names one version and the tree has a different version.
func (in *Installer) reapply(v int64) error {
	stamp, err := treeStamp(in.Dir)
	if err != nil {
		return fmt.Errorf("pf install: %w", err)
	}
	if stamp != v {
		return fmt.Errorf("pf install: version %d is the installed floor, but the tree at %s is version %d; "+
			"there is nothing of %d to re-apply. Install a newer release with pf upgrade -version, or, if %d is the release before this one, go back to it with pf rollback", v, in.Dir, stamp, v, v)
	}
	fmt.Fprintf(in.out(), "pf install: version %d is already installed; re-applying it\n", v)
	if err := in.runPF("apply"); err != nil {
		return fmt.Errorf("pf install: pf apply: %w; fix the cause and run pf install again", err)
	}
	if err := in.runPF("doctor", "--post-upgrade"); err != nil {
		return fmt.Errorf("pf install: pf doctor --post-upgrade: %w; fix the cause and run pf install again", err)
	}
	fmt.Fprintf(in.out(), "pf install: version=%d re-applied at %s\n", v, in.Dir)
	return nil
}

// checkIfaces refuses an interface plan that cannot be a fence: no
// uplink or agent NIC, a name that render refuses, or one port asked to
// be two segments. apply reads these names before render examines them.
// Thus the check occurs here, before the first write.
func checkIfaces(wan, agent, house string) error {
	if wan == "" || agent == "" {
		return fmt.Errorf("pf install: need both an uplink and an agent interface (wan=%q agent=%q); pass -wan and -agent", wan, agent)
	}
	for _, x := range [][2]string{{"-wan", wan}, {"-agent", agent}, {"-house", house}} {
		if x[1] != "" && !render.ValidIfaceName(x[1]) {
			return fmt.Errorf("pf install: %s %q is not an interface name (a letter, then up to 14 letters, digits, '.', '_' or '-')", x[0], x[1])
		}
	}
	if wan == agent {
		return fmt.Errorf("pf install: the uplink and the agent segment are both %s; they must be two different interfaces (pass -wan and -agent)", wan)
	}
	if house != "" && (house == wan || house == agent) {
		return fmt.Errorf("pf install: the house interface %s is already the uplink or the agent segment; pass a third interface to -house, or none", house)
	}
	return nil
}

// copyOnce copies src into dst, a new root-only file, through one
// descriptor. From then on, the code verifies and reads dst.
func copyOnce(src, dst string, max int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", src)
	}
	if st.Size() > max {
		return fmt.Errorf("%s: %d bytes, cap %d", src, st.Size(), max)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, max+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("%s: grew past cap %d", src, max)
	}
	return err
}

// wizard fills WAN/Agent/House when the caller did not pin them. It
// proposes from `ip -j link`/`route`. Then it prints the proposal
// (-yes), or it asks for a line to accept it, override it, or type
// "skip" for the optional house NIC.
func (in *Installer) wizard() error {
	if in.WAN != "" && in.Agent != "" {
		return nil // fully pinned, e.g. a scripted install; nothing to propose
	}
	link, err := in.RunLink()
	if err != nil {
		return fmt.Errorf("pf install: ip -j link: %w", err)
	}
	route, err := in.RunRoute()
	if err != nil {
		return fmt.Errorf("pf install: ip -j route show default: %w", err)
	}
	p, err := ProposeFor(link, route, in.WAN, in.HasDevice)
	if err != nil {
		return err
	}
	if in.WAN == "" {
		in.WAN = p.WAN
	}
	if in.Agent == "" {
		in.Agent = p.Agent
	}
	if in.Yes {
		if in.WAN == "" || in.Agent == "" {
			return fmt.Errorf("pf install: -yes given but could not propose both interfaces (wan=%q agent=%q); pass -wan and -agent", in.WAN, in.Agent)
		}
		fmt.Fprintf(in.out(), "pf install: -yes: wan=%s agent=%s (candidates: %s)\n", in.WAN, in.Agent, strings.Join(p.Candidates, " "))
		return nil
	}
	src := in.Stdin
	if src == nil {
		if in.TTY == nil {
			return in.noTerminal(errors.New("no terminal opener"))
		}
		tty, err := in.TTY()
		if err != nil {
			return in.noTerminal(err)
		}
		defer tty.Close()
		src = tty
	}
	r := bufio.NewReader(src)
	if in.WAN, err = promptIface(in.out(), r, "uplink (WAN)", in.WAN, p.Candidates); err != nil {
		return err
	}
	if in.Agent, err = promptIface(in.out(), r, "agent", in.Agent, p.Candidates); err != nil {
		return err
	}
	house, err := promptIface(in.out(), r, "house (optional, blank to skip)", in.House, HouseCandidates(p, in.WAN, in.Agent))
	if err != nil {
		return err
	}
	if house != "skip" {
		in.House = house
	} else {
		in.House = ""
	}
	return nil
}

// noTerminal is the wizard with nobody to ask: a piped or headless run
// that did not pin a port or pass -yes. If the wizard takes the
// proposal there, a new box can fence its uplink.
func (in *Installer) noTerminal(cause error) error {
	return fmt.Errorf("pf install: no terminal to answer the interface questions on (%v); "+
		"pass -wan <uplink> -agent <agent port> (and -house <port> for a home network), "+
		"or -yes to take the proposal wan=%s agent=%s", cause, in.WAN, in.Agent)
}

// promptIface asks for one interface. A bare Enter takes the proposal.
// End of input is not an answer, and it refuses.
func promptIface(w io.Writer, r *bufio.Reader, label, proposed string, candidates []string) (string, error) {
	fmt.Fprintf(w, "%s interface [%s] (candidates: %s): ", label, proposed, strings.Join(candidates, " "))
	line, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		fmt.Fprintln(w)
		return "", fmt.Errorf("pf install: no answer for the %s interface (%v); pass -wan and -agent, or -yes, to install without questions", label, err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return proposed, nil
	}
	return line, nil
}
