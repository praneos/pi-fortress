package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/ship"
)

// installRig is pf install against a scratch root: a throwaway signing
// key made in t.TempDir, all paths redirected, and a recorder in place
// of each exec (apt through provision.sh, pf ship install, pf apply/doctor).
type installRig struct {
	t     *testing.T
	root  string
	priv  string
	in    *Installer
	calls []string
	// shipped is the bundle pf ship install was handed, read when it ran.
	shipped []byte
	pfErr   map[string]error
}

func newInstallRig(t *testing.T) *installRig {
	t.Helper()
	oldEUID, oldDetect := geteuid, detectTarget
	geteuid = func() int { return 0 }
	detectTarget = func(arch string) (Target, error) {
		return Target{Arch: "amd64", ID: "debian", VersionID: "12"}, nil
	}
	t.Cleanup(func() { geteuid, detectTarget = oldEUID, oldDetect })

	root := t.TempDir()
	r := &installRig{t: t, root: root, pfErr: map[string]error{}}
	priv, line := signingKey(t, root, "dist")
	r.priv = priv
	signers := filepath.Join(root, "release-signers")
	if err := os.WriteFile(signers, []byte(line+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	in := Defaults()
	in.Arch = "amd64"
	in.SignersPath = signers
	in.WAN, in.Agent = "eth0", "eth1"
	in.Dir = filepath.Join(root, "opt", "pi-fortress")
	in.VersionPath = filepath.Join(root, "ship.version")
	in.NetEnvLocal = filepath.Join(root, "etc", "net.env.local")
	in.HouseEnvPath = filepath.Join(root, "etc", "house.env")
	in.LabMarker = filepath.Join(root, "etc", "lab")
	in.GatewayRole = filepath.Join(root, "etc", "gateway.role")
	in.SignersDest = filepath.Join(root, "etc", "kept-release-signers")
	in.URLDest = ""
	in.WorkDir = filepath.Join(root, "work")
	in.IncomingBase = filepath.Join(root, "incoming")
	in.Stdin = strings.NewReader("")
	in.Stdout, in.Stderr = io.Discard, io.Discard
	in.RunLink = func() ([]byte, error) { return nil, errors.New("ip must not run in this test") }
	in.RunRoute = in.RunLink
	in.SSHIfaces = func() ([]string, error) { return nil, nil }
	in.RunProvision = func(src string, _, _ io.Writer) error {
		if _, err := os.Stat(filepath.Join(src, "vm/pi/provision.sh")); err != nil {
			t.Errorf("provision.sh ran against %s, which is not the extracted tree: %v", src, err)
		}
		r.calls = append(r.calls, "provision")
		return nil
	}
	in.RunShipInstall = func(args []string, _, _ io.Writer) error {
		r.calls = append(r.calls, "ship")
		for i, a := range args {
			if a == "-incoming" && i+1 < len(args) {
				r.shipped, _ = os.ReadFile(filepath.Join(args[i+1], ship.BundleName))
			}
		}
		return nil
	}
	in.RunPF = func(args []string, _, _ io.Writer) error {
		name := strings.Join(args, " ")
		r.calls = append(r.calls, "pf "+name)
		return r.pfErr[name]
	}
	r.in = in
	return r
}

// bundle builds and signs a release bundle at version v, signed by key.
func (r *installRig) bundle(v int64, key string) (tarPath, sigPath string) {
	t := r.t
	src := filepath.Join(t.TempDir(), "src")
	for p, body := range map[string]string{
		"vm/pi/provision.sh": "#!/bin/bash\n",
		"vm/pi/apply.sh":     "#!/bin/bash\n# " + strconv.FormatInt(v, 10) + "\n",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(src, p)), 0755)
		if err := os.WriteFile(filepath.Join(src, p), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := ship.Build(&buf, src, ship.BundleOptions{Version: v, SHA: "test"}); err != nil {
		t.Fatal(err)
	}
	tarPath = filepath.Join(t.TempDir(), "pf-bundle.tar")
	if err := os.WriteFile(tarPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return tarPath, sign(t, key, tarPath)
}

// installed makes the scratch root look like a box already at v.
func (r *installRig) installed(v int64) {
	os.MkdirAll(r.in.Dir, 0755)
	stamp := []byte(strconv.FormatInt(v, 10) + "\n")
	os.WriteFile(filepath.Join(r.in.Dir, ".pf-ship-version"), stamp, 0644)
	os.WriteFile(r.in.VersionPath, stamp, 0644)
}

func (r *installRig) nothingWritten() {
	r.t.Helper()
	for _, p := range []string{r.in.NetEnvLocal, r.in.GatewayRole, r.in.SignersDest} {
		if _, err := os.Stat(p); err == nil {
			r.t.Errorf("%s was written by an install that refused", p)
		}
	}
	if len(r.calls) != 0 {
		r.t.Errorf("ran %v on an install that refused", r.calls)
	}
}

func TestInstallRefusesABadSignature(t *testing.T) {
	r := newInstallRig(t)
	other, _ := signingKey(t, r.root, "untrusted")
	r.in.Bundle, r.in.Sig = r.bundle(200, other)
	err := r.in.Run()
	if err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("err = %v, want a signature refusal", err)
	}
	r.nothingWritten()
}

func TestInstallRefusesADowngrade(t *testing.T) {
	r := newInstallRig(t)
	r.installed(300)
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	err := r.in.Run()
	if err == nil || !strings.Contains(err.Error(), "older than the installed floor 300") {
		t.Fatalf("err = %v, want a downgrade refusal", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("ran %v on a downgrade", r.calls)
	}
}

func TestInstallRunsProvisionBeforeShipAndShipsTheVerifiedCopy(t *testing.T) {
	r := newInstallRig(t)
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	verified, err := os.ReadFile(r.in.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	// After verification, the path of the caller is swapped for other
	// bytes, as a -bundle run by hand could be.
	provision := r.in.RunProvision
	r.in.RunProvision = func(src string, o, e io.Writer) error {
		if err := os.WriteFile(r.in.Bundle, []byte("swapped after verification"), 0644); err != nil {
			t.Fatal(err)
		}
		return provision(src, o, e)
	}
	if err := r.in.Run(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"provision", "ship"}; !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls %v, want %v: provision.sh has to run before the first apply", r.calls, want)
	}
	if !bytes.Equal(r.shipped, verified) {
		t.Fatal("pf ship install was handed bytes other than the ones that were verified")
	}
	if raw, err := os.ReadFile(r.in.NetEnvLocal); err != nil || !strings.Contains(string(raw), "INT_IF=eth1") {
		t.Fatalf("net.env.local: %q %v", raw, err)
	}
}

func TestInstallSameVersionReappliesInsteadOfSkipping(t *testing.T) {
	r := newInstallRig(t)
	r.installed(200)
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pf apply", "pf doctor --post-upgrade"}; !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls %v, want %v", r.calls, want)
	}
	if raw, err := os.ReadFile(r.in.NetEnvLocal); err != nil || !strings.Contains(string(raw), "WAN_IF=eth0") {
		t.Fatalf("the wizard's answers have to be saved before the re-apply: %q %v", raw, err)
	}

	r.calls = nil
	r.pfErr["apply"] = errors.New("exit status 1")
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "run pf install again") {
		t.Fatalf("a failed re-apply: err = %v", err)
	}
	if want := []string{"pf apply"}; !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls %v, want %v: no doctor after a failed apply", r.calls, want)
	}
}

func TestInstallSameVersionRefusesATreeOfAnotherVersion(t *testing.T) {
	r := newInstallRig(t)
	r.installed(150)
	os.WriteFile(r.in.VersionPath, []byte("200\n"), 0644)
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "tree at") {
		t.Fatalf("err = %v, want a refusal naming the mismatched tree", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("ran %v", r.calls)
	}
}

func TestInstallRefusesUplinkAsAgentBeforeWritingAnything(t *testing.T) {
	r := newInstallRig(t)
	r.in.WAN, r.in.Agent = "eth0", "eth0"
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "both eth0") {
		t.Fatalf("err = %v", err)
	}
	r.nothingWritten()
	if _, err := os.Stat(r.in.VersionPath); err == nil {
		t.Fatal("a floor was written")
	}
}

func TestInstallWizardProposesAgentAgainstThePinnedUplink(t *testing.T) {
	r := newInstallRig(t)
	r.in.WAN, r.in.Agent, r.in.Yes = "eth1", "", true
	r.in.RunLink = func() ([]byte, error) {
		return []byte(`[{"ifname":"lo","link_type":"loopback"},{"ifname":"eth0","link_type":"ether"},{"ifname":"eth1","link_type":"ether"},{"ifname":"docker0","link_type":"ether"},{"ifname":"br-1a2b","link_type":"ether"}]`), nil
	}
	r.in.RunRoute = func() ([]byte, error) { return []byte(`[{"dev":"eth0"}]`), nil }
	r.in.HasDevice = func(n string) bool { return n == "eth0" || n == "eth1" }
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err != nil {
		t.Fatal(err)
	}
	if r.in.WAN != "eth1" || r.in.Agent != "eth0" {
		t.Fatalf("wan=%q agent=%q, want the agent proposed against the pinned eth1", r.in.WAN, r.in.Agent)
	}
}

func TestProposeForSkipsVirtualInterfaces(t *testing.T) {
	links := []byte(`[
  {"ifname":"docker0","link_type":"ether"},
  {"ifname":"br-1a2b","link_type":"ether"},
  {"ifname":"virbr0","link_type":"ether"},
  {"ifname":"eth0.20","link_type":"ether"},
  {"ifname":"vnet3","link_type":"ether"},
  {"ifname":"macvtap0","link_type":"ether"},
  {"ifname":"enp1s0","link_type":"ether"},
  {"ifname":"enx00e04c","link_type":"ether"}
]`)
	hw := func(n string) bool { return n == "enp1s0" || n == "enx00e04c" }
	p, err := ProposeFor(links, []byte(`[{"dev":"enp1s0"}]`), "", hw)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"enp1s0", "enx00e04c"}; !reflect.DeepEqual(p.Candidates, want) {
		t.Fatalf("candidates %v, want %v", p.Candidates, want)
	}
	if p.WAN != "enp1s0" || p.Agent != "enx00e04c" {
		t.Fatalf("proposal %+v", p)
	}
	if _, err := ProposeFor(links, []byte(`[]`), "", func(string) bool { return false }); err == nil {
		t.Fatal("no hardware interface at all should refuse")
	}
}

// wizardRig is the rig with nothing pinned: the wizard must propose
// from two hardware ports and then ask.
func wizardRig(t *testing.T) *installRig {
	r := newInstallRig(t)
	r.in.WAN, r.in.Agent, r.in.Yes = "", "", false
	r.in.Stdin = nil
	r.in.RunLink = func() ([]byte, error) {
		return []byte(`[{"ifname":"eth0","link_type":"ether"},{"ifname":"eth1","link_type":"ether"}]`), nil
	}
	r.in.RunRoute = func() ([]byte, error) { return []byte(`[{"dev":"eth0"}]`), nil }
	r.in.HasDevice = func(string) bool { return true }
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	return r
}

func TestInstallWithoutATerminalRefusesRatherThanAccepting(t *testing.T) {
	r := wizardRig(t)
	r.in.TTY = func() (io.ReadCloser, error) { return nil, errors.New("open /dev/tty: no such device or address") }
	err := r.in.Run()
	if err == nil {
		t.Fatal("a run with no terminal and no answers went ahead")
	}
	for _, want := range []string{"no terminal", "-wan", "-agent", "-yes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	r.nothingWritten()
}

func TestInstallPromptAtEndOfInputRefuses(t *testing.T) {
	r := wizardRig(t)
	r.in.TTY = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v, want a refusal for an unanswered prompt", err)
	}
	r.nothingWritten()
}

func TestInstallPromptsOnTheTerminalNotStdin(t *testing.T) {
	if Defaults().Stdin != nil {
		t.Fatal("Defaults reads answers from stdin, which is the script itself under curl | bash")
	}
	r := wizardRig(t)
	r.in.TTY = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("eth1\neth0\n\n")), nil }
	if err := r.in.Run(); err != nil {
		t.Fatal(err)
	}
	if r.in.WAN != "eth1" || r.in.Agent != "eth0" || r.in.House != "" {
		t.Fatalf("wan=%q agent=%q house=%q, want the typed eth1, eth0 and no house", r.in.WAN, r.in.Agent, r.in.House)
	}
}

func TestInstallRefusesAPlainHTTPReleaseURLBeforeWritingAnything(t *testing.T) {
	r := newInstallRig(t)
	r.in.URLDest = filepath.Join(r.root, "etc", "release.url")
	r.in.ReleaseURL = "http://pi-fortress-block.test/releases/download"
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want an https refusal", err)
	}
	r.nothingWritten()
	if _, err := os.Stat(r.in.URLDest); err == nil {
		t.Fatal("an http release URL was kept for pf upgrade")
	}
}

func TestSysfsHardwareSkipsBridgesTunsAndEnslavedPorts(t *testing.T) {
	sys := t.TempDir()
	mk := func(ifname string, entries ...string) {
		for _, e := range entries {
			if err := os.MkdirAll(filepath.Join(sys, ifname, e), 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("eth0", "device")
	mk("enx00e04c", "device")
	mk("br0", "bridge")
	mk("docker0", "bridge")
	mk("veth1a2b")
	mk("tap0", "tun_flags")
	mk("tun9", "device", "tun_flags")
	mk("enp2s0", "device", "master")
	mk("weird", "device", "bridge")
	hw := SysfsHardware(sys)
	for name, want := range map[string]bool{
		"eth0": true, "enx00e04c": true,
		"br0": false, "docker0": false, "veth1a2b": false, "tap0": false, "tun9": false,
		"enp2s0": false, "weird": false, "missing": false, "../eth0": false, "": false,
	} {
		if got := hw(name); got != want {
			t.Errorf("%q: hardware=%v, want %v", name, got, want)
		}
	}
}

func TestInstallAsksWhereTheJournalStays(t *testing.T) {
	for _, c := range []struct{ answers, want, env string }{
		{"eth1\neth0\n\ny\n", "disk", "JOURNAL_PERSIST=1"},
		{"eth1\neth0\n\n\n", "ram", "JOURNAL_PERSIST=0"},
		// No more input after the interfaces: the default, RAM.
		{"eth1\neth0\n\n", "ram", "JOURNAL_PERSIST=0"},
	} {
		r := wizardRig(t)
		r.in.TTY = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(c.answers)), nil }
		if err := r.in.Run(); err != nil {
			t.Fatal(err)
		}
		if r.in.Journal != c.want {
			t.Errorf("answers %q: journal %q, want %q", c.answers, r.in.Journal, c.want)
		}
		b, err := os.ReadFile(r.in.NetEnvLocal)
		if err != nil || !strings.Contains(string(b), c.env+"\n") {
			t.Errorf("answers %q: net.env.local %q lacks %s (%v)", c.answers, b, c.env, err)
		}
	}
}

func TestInstallJournalFlag(t *testing.T) {
	r := newInstallRig(t)
	r.in.Journal = "sdcard"
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "-journal") {
		t.Fatalf("err = %v, want a refusal of -journal sdcard", err)
	}
	r.nothingWritten()
	// A pinned install with no -journal asks nothing and writes no key:
	// apply keeps its default.
	r = newInstallRig(t)
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(r.in.NetEnvLocal); strings.Contains(string(b), "JOURNAL_PERSIST") {
		t.Fatalf("a pinned install wrote %q", b)
	}
}
