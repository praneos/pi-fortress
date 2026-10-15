package ship

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
)

type rig struct {
	t        *testing.T
	in       *Installer
	root     string
	key      string
	alerts   []string
	applies  int
	applyErr []error
}

func keygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not on PATH; signature tests need it")
	}
	return p
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func newRig(t *testing.T, withKey bool) *rig {
	root := t.TempDir()
	r := &rig{t: t, root: root}
	in := Defaults()
	in.Incoming = filepath.Join(root, "incoming")
	in.Work = filepath.Join(root, "work")
	in.Dir = filepath.Join(root, "opt", "pi-fortress")
	in.VersionPath = filepath.Join(root, "ship.version")
	in.Signers = filepath.Join(root, "allowed_signers")
	in.Log = filepath.Join(root, "ship.jsonl")
	in.Settle, in.Poll = 50*time.Millisecond, 10*time.Millisecond
	in.Stderr = &bytes.Buffer{}
	in.Lock = func() (func(), error) { return func() {}, nil }
	in.Alert = func(msg string) { r.alerts = append(r.alerts, msg) }
	in.Apply = func() error {
		r.applies++
		if len(r.applyErr) > 0 {
			err := r.applyErr[0]
			r.applyErr = r.applyErr[1:]
			return err
		}
		return nil
	}
	r.in = in
	os.MkdirAll(in.Incoming, 0700)
	write(t, filepath.Join(in.Dir, "vm/pi/apply.sh"), "old apply\n")
	write(t, filepath.Join(in.Dir, "vm/policy/house.domains"), "operator edit\n")
	write(t, filepath.Join(in.Dir, "vm/policy/generated/ca.pem"), "pi ca\n")
	write(t, filepath.Join(in.Dir, "vm/policy/stale"), "gone after ship\n")
	if withKey {
		in.Keygen = keygen(t)
		r.key = filepath.Join(root, "release")
		run(t, in.Keygen, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", r.key)
		r.signers(r.key)
	}
	return r
}

func (r *rig) signers(key string) {
	pub := strings.Fields(read(r.t, key+".pub"))
	write(r.t, r.in.Signers, Principal+` namespaces="`+Namespace+`" `+pub[0]+" "+pub[1]+"\n")
}

// ship builds a bundle of a small tree at version, signs it with key and
// puts the pair into incoming.
func (r *rig) ship(version int64, key string) string {
	t := r.t
	src := filepath.Join(t.TempDir(), "src")
	write(t, filepath.Join(src, "vm/pi/apply.sh"), "new apply\n")
	write(t, filepath.Join(src, "vm/policy/house.domains"), "desk seed\n")
	write(t, filepath.Join(src, "vm/policy/allow.domains"), "seeded\n")
	write(t, filepath.Join(src, "vm/policy/generated/desk-ca.pem"), "desk ca\n")
	write(t, filepath.Join(src, ".git/HEAD"), "ref\n")
	out := filepath.Join(t.TempDir(), BundleName)
	var buf bytes.Buffer
	_, err := Build(&buf, src, BundleOptions{
		Version: version, SHA: "deadbee",
		ExcludeNames: []string{".git"},
		Keep:         []string{"vm/policy/generated"},
		Seed:         []string{"vm/policy/house.domains", "vm/policy/allow.domains"},
	})
	if err != nil {
		t.Fatal(err)
	}
	write(t, out, buf.String())
	if key != "" {
		run(t, r.in.Keygen, "-Y", "sign", "-f", key, "-n", Namespace, out)
	}
	write(t, filepath.Join(r.in.Incoming, BundleName), read(t, out))
	if key != "" {
		write(t, filepath.Join(r.in.Incoming, SigName), read(t, out+".sig"))
	}
	return out
}

func (r *rig) incomingEmpty() {
	r.t.Helper()
	ents, _ := os.ReadDir(r.in.Incoming)
	if len(ents) != 0 {
		r.t.Fatalf("incoming still has %d entries", len(ents))
	}
}

func (r *rig) untouched() {
	r.t.Helper()
	if got := read(r.t, filepath.Join(r.in.Dir, "vm/pi/apply.sh")); got != "old apply\n" {
		r.t.Fatalf("live tree changed: %q", got)
	}
	if raw, err := os.ReadFile(r.in.VersionPath); err == nil && string(raw) == "100\n" {
		r.t.Fatal("ship.version written on a refusal")
	}
	if _, err := os.Stat(r.in.Dir + ".new"); err == nil {
		r.t.Fatal(".new left behind")
	}
}

func TestInstallOK(t *testing.T) {
	r := newRig(t, true)
	r.ship(100, r.key)
	row, ok := r.in.Run()
	if !ok || row.Result != "ok" || row.Version != 100 || row.SHA != "deadbee" {
		t.Fatalf("row %+v ok %v; stderr %s", row, ok, r.in.Stderr)
	}
	d := r.in.Dir
	for p, want := range map[string]string{
		"vm/pi/apply.sh":                     "new apply\n",
		"vm/policy/house.domains":            "operator edit\n",
		"vm/policy/allow.domains":            "seeded\n",
		"vm/policy/generated/ca.pem":         "pi ca\n",
		"../pi-fortress.prev/vm/pi/apply.sh": "old apply\n",
	} {
		if got := read(t, filepath.Join(d, p)); got != want {
			t.Errorf("%s = %q, want %q", p, got, want)
		}
	}
	for _, gone := range []string{"vm/policy/stale", "vm/policy/generated/desk-ca.pem", ".git"} {
		if _, err := os.Lstat(filepath.Join(d, gone)); err == nil {
			t.Errorf("%s present", gone)
		}
	}
	if got := read(t, r.in.VersionPath); got != "100\n" {
		t.Fatalf("version %q", got)
	}
	if r.applies != 1 || len(r.alerts) != 0 {
		t.Fatalf("applies %d alerts %v", r.applies, r.alerts)
	}
	r.incomingEmpty()
	if last, ok := jsonl.LastShip(r.in.Log); !ok || last.Result != "ok" || last.Version != 100 {
		t.Fatalf("log %+v", last)
	}
	if _, err := os.Stat(r.in.Work); err == nil {
		t.Fatal("work dir left")
	}

	r.ship(100, r.key)
	if row, _ := r.in.Run(); row.Result != "rollback" {
		t.Fatalf("replay of the installed version: %+v", row)
	}
}

func TestInstallRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		want  string
	}{
		{"tampered bundle", func(r *rig) {
			r.ship(100, r.key)
			p := filepath.Join(r.in.Incoming, BundleName)
			raw := []byte(read(r.t, p))
			raw[len(raw)/2] ^= 1
			os.WriteFile(p, raw, 0644)
		}, "bad_sig"},
		{"other key", func(r *rig) {
			other := filepath.Join(r.root, "other")
			run(r.t, r.in.Keygen, "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", other)
			r.ship(100, other)
		}, "bad_sig"},
		{"wrong namespace", func(r *rig) {
			out := r.ship(100, "")
			run(r.t, r.in.Keygen, "-Y", "sign", "-f", r.key, "-n", "pi-fortress-dist", out)
			write(r.t, filepath.Join(r.in.Incoming, SigName), read(r.t, out+".sig"))
		}, "bad_sig"},
		{"missing signers", func(r *rig) {
			r.ship(100, r.key)
			os.Remove(r.in.Signers)
		}, "bad_sig"},
		{"writable signers", func(r *rig) {
			r.ship(100, r.key)
			os.Chmod(r.in.Signers, 0666)
		}, "bad_sig"},
		{"rollback", func(r *rig) {
			write(r.t, r.in.VersionPath, "200\n")
			r.ship(100, r.key)
		}, "rollback"},
		{"garbage version file", func(r *rig) {
			write(r.t, r.in.VersionPath, "soon\n")
			r.ship(100, r.key)
		}, "version_file"},
		{"symlinked upload", func(r *rig) {
			out := r.ship(100, r.key)
			p := filepath.Join(r.in.Incoming, BundleName)
			os.Remove(p)
			os.Symlink(out, p)
		}, "bad_upload"},
		{"symlinked keep path", func(r *rig) {
			r.ship(100, r.key)
			pol := filepath.Join(r.in.Dir, "vm/policy")
			os.Rename(pol, pol+".real")
			os.Symlink(pol+".real", pol)
			write(r.t, filepath.Join(pol+".real", "../pi/apply.sh"), "old apply\n")
		}, "swap"},
		{"no sig", func(r *rig) {
			r.ship(100, "")
		}, "incomplete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, true)
			c.setup(r)
			row, ok := r.in.Run()
			if !ok || row.Result != c.want {
				t.Fatalf("row %+v, want %s; stderr %s", row, c.want, r.in.Stderr)
			}
			if r.applies != 0 || len(r.alerts) != 1 {
				t.Fatalf("applies %d alerts %v", r.applies, r.alerts)
			}
			r.untouched()
			r.incomingEmpty()
		})
	}
}

func TestInstallNothingToDo(t *testing.T) {
	r := newRig(t, false)
	if _, ok := r.in.Run(); ok {
		t.Fatal("empty incoming processed")
	}
	if _, err := os.Stat(r.in.Log); err == nil {
		t.Fatal("logged an empty run")
	}
}

func TestInstallApplyFailureRestores(t *testing.T) {
	for _, reapply := range []error{nil, errors.New("still broken")} {
		r := newRig(t, true)
		r.applyErr = []error{errors.New("exit status 1"), reapply}
		r.ship(100, r.key)
		row, _ := r.in.Run()
		if row.Result != "apply_failed" {
			t.Fatalf("row %+v", row)
		}
		wantReason := "re-applied"
		if reapply != nil {
			wantReason = "re-apply failed too"
		}
		if !strings.Contains(row.Reason, wantReason) {
			t.Fatalf("reason %q, want %q", row.Reason, wantReason)
		}
		if r.applies != 2 || len(r.alerts) != 1 {
			t.Fatalf("applies %d alerts %v", r.applies, r.alerts)
		}
		r.untouched()
		if got := read(t, filepath.Join(r.in.Dir+".failed", "vm/pi/apply.sh")); got != "new apply\n" {
			t.Fatalf(".failed holds %q", got)
		}
		if _, err := os.Stat(r.in.Dir + ".prev"); err == nil {
			t.Fatal(".prev should have moved back to the live path")
		}
		if got := read(t, filepath.Join(r.in.Dir, "vm/policy/generated/ca.pem")); got != "pi ca\n" {
			t.Fatalf("restored tree lost generated/: %q", got)
		}
	}
}

func TestInstallFirstShipApplyFailure(t *testing.T) {
	r := newRig(t, true)
	os.RemoveAll(r.in.Dir)
	r.applyErr = []error{errors.New("exit status 1")}
	r.ship(100, r.key)
	row, _ := r.in.Run()
	if row.Result != "apply_failed" || !strings.Contains(row.Reason, "no previous tree") || r.applies != 1 {
		t.Fatalf("row %+v applies %d", row, r.applies)
	}
}

// Merge sees the Pi copy of a kept path and the bundle copy. What it
// returns goes live. A path that it declines is carried as it was.
func TestInstallMergesAKeptPathWithTheShippedCopy(t *testing.T) {
	r := newRig(t, true)
	r.in.Merge = map[string]func([]byte, []byte) ([]byte, bool, error){
		"vm/policy/house.domains": func(kept, shipped []byte) ([]byte, bool, error) {
			return append(append([]byte{}, kept...), shipped...), true, nil
		},
		"vm/policy/allow.domains": func(kept, _ []byte) ([]byte, bool, error) { return kept, false, nil },
	}
	r.ship(100, r.key)
	if row, ok := r.in.Run(); !ok || row.Result != "ok" {
		t.Fatalf("row %+v; stderr %s", row, r.in.Stderr)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/policy/house.domains")); got != "operator edit\ndesk seed\n" {
		t.Fatalf("merged house.domains = %q", got)
	}
	if got := read(t, filepath.Join(r.in.Dir, "vm/policy/allow.domains")); got != "seeded\n" {
		t.Fatalf("allow.domains = %q", got)
	}
}

// TestInstallNamespacePrincipal is the required coverage for the
// Namespace/Principal fields (docs/gateway_install.md "Two signers, on
// purpose"). A bundle signed under one identity is refused when the
// Installer expects a different one, and accepted when it matches.
// pf install/pf upgrade use this mechanism, so that the public
// pi-fortress-dist download key is not also the pi-fortress-release
// ship-push key.
func TestInstallNamespacePrincipal(t *testing.T) {
	const distNS, distPrincipal = "pi-fortress-dist", "release@pi-fortress"

	signAs := func(t *testing.T, r *rig, ns, principal string) {
		t.Helper()
		r.in.Keygen = keygen(t)
		r.key = filepath.Join(r.root, "dist")
		run(t, r.in.Keygen, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", r.key)
		pub := strings.Fields(read(t, r.key+".pub"))
		write(t, r.in.Signers, principal+` namespaces="`+ns+`" `+pub[0]+" "+pub[1]+"\n")
	}

	shipSignedAs := func(t *testing.T, r *rig, ns string) {
		t.Helper()
		src := filepath.Join(t.TempDir(), "src")
		write(t, filepath.Join(src, "vm/pi/apply.sh"), "dist apply\n")
		out := filepath.Join(t.TempDir(), BundleName)
		var buf bytes.Buffer
		if _, err := Build(&buf, src, BundleOptions{Version: 200, SHA: "distsha"}); err != nil {
			t.Fatal(err)
		}
		write(t, out, buf.String())
		run(t, r.in.Keygen, "-Y", "sign", "-f", r.key, "-n", ns, out)
		write(t, filepath.Join(r.in.Incoming, BundleName), read(t, out))
		write(t, filepath.Join(r.in.Incoming, SigName), read(t, out+".sig"))
	}

	t.Run("refused when the installer expects a different namespace", func(t *testing.T) {
		r := newRig(t, false)
		signAs(t, r, distNS, distPrincipal)
		shipSignedAs(t, r, distNS)
		r.in.Namespace, r.in.Principal = Namespace, Principal // expects the desktop-push identity, not pi-fortress-dist
		row, ok := r.in.Run()
		if !ok || row.Result != "bad_sig" {
			t.Fatalf("expected bad_sig with a namespace/principal mismatch, got %+v", row)
		}
	})

	// The case above also has a different principal. Thus ssh-keygen
	// refuses it on the principal before it compares the namespace. This
	// case keeps the principal and changes only the namespace.
	t.Run("refused when only the namespace differs", func(t *testing.T) {
		r := newRig(t, false)
		signAs(t, r, distNS, distPrincipal)
		shipSignedAs(t, r, distNS)
		r.in.Namespace, r.in.Principal = Namespace, distPrincipal
		row, ok := r.in.Run()
		if !ok || row.Result != "bad_sig" {
			t.Fatalf("expected bad_sig with only the namespace differing, got %+v", row)
		}
		if r.applies != 0 {
			t.Fatal("apply ran on a refused bundle")
		}
	})

	t.Run("refused when the signature itself was made under another namespace", func(t *testing.T) {
		r := newRig(t, false)
		signAs(t, r, distNS, distPrincipal)
		shipSignedAs(t, r, Namespace)
		r.in.Namespace, r.in.Principal = distNS, distPrincipal
		row, ok := r.in.Run()
		if !ok || row.Result != "bad_sig" {
			t.Fatalf("expected bad_sig for a signature under the ship namespace, got %+v", row)
		}
	})

	t.Run("accepted when the installer expects the matching namespace", func(t *testing.T) {
		r := newRig(t, false)
		signAs(t, r, distNS, distPrincipal)
		shipSignedAs(t, r, distNS)
		r.in.Namespace, r.in.Principal = distNS, distPrincipal
		row, ok := r.in.Run()
		if !ok || row.Result != "ok" || row.Version != 200 {
			t.Fatalf("expected ok with a matching namespace/principal, got %+v", row)
		}
		if r.applies != 1 {
			t.Fatal("apply not called")
		}
	})
}
