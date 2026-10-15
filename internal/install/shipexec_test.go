package install

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"pi-fortress/internal/ship"
)

func TestShipInstallArgs(t *testing.T) {
	got := ShipInstallArgs("/var/lib/pi-fortress/upgrade/abc123", "/etc/pi-fortress/release-signers", "/opt/pi-fortress")
	want := []string{
		"ship", "install",
		"-incoming", "/var/lib/pi-fortress/upgrade/abc123",
		"-signers", "/etc/pi-fortress/release-signers",
		"-namespace", DistNamespace,
		"-principal", DistPrincipal,
		"-dir", "/opt/pi-fortress",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ShipInstallArgs = %v, want %v", got, want)
	}
	withExtra := ShipInstallArgs("in", "sig", "dir", "-pending-file", "")
	if withExtra[len(withExtra)-2] != "-pending-file" || withExtra[len(withExtra)-1] != "" {
		t.Fatalf("extra args not appended: %v", withExtra)
	}
}

func TestNewIncomingDirIsFreshAndRootOnly(t *testing.T) {
	base := filepath.Join(t.TempDir(), "upgrade")
	a, err := NewIncomingDir(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIncomingDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two calls returned the same directory: %s", a)
	}
	for _, dir := range []string{a, b} {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !st.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
		if perm := st.Mode().Perm(); perm != 0700 {
			t.Fatalf("%s: mode %o, want 0700", dir, perm)
		}
		if filepath.Dir(dir) != base {
			t.Fatalf("%s is not under %s", dir, base)
		}
	}
}

func TestPlaceBundleNamesFilesTheInstallerExpects(t *testing.T) {
	src := t.TempDir()
	bundle := filepath.Join(src, "pf-bundle-v1-amd64.tar")
	sig := bundle + ".sig"
	if err := os.WriteFile(bundle, []byte("tar bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sig, []byte("sig bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tar, sigOut, err := PlaceBundle(bundle, sig, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(tar) != ship.BundleName || filepath.Base(sigOut) != ship.SigName {
		t.Fatalf("tar=%s sig=%s, want names %s/%s", tar, sigOut, ship.BundleName, ship.SigName)
	}
	got, err := os.ReadFile(tar)
	if err != nil || string(got) != "tar bytes" {
		t.Fatalf("tar content = %q, %v", got, err)
	}
	got, err = os.ReadFile(sigOut)
	if err != nil || string(got) != "sig bytes" {
		t.Fatalf("sig content = %q, %v", got, err)
	}
}
