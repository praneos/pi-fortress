package ship

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateVersionDefaultsAndIsMonotonic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.version")
	if v, err := ReadStateVersion(p); err != nil || v != 1 {
		t.Fatalf("missing file: %d, %v", v, err)
	}
	if err := WriteStateVersion(p, 2); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadStateVersion(p); err != nil || v != 2 {
		t.Fatalf("after write: %d, %v", v, err)
	}
	// The build of a downgrade that declares a lower StateMax must never
	// lower the recorded version. The rollback guard trusts that number
	// to know that a newer sidecar is on disk.
	if err := WriteStateVersion(p, 1); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadStateVersion(p); err != nil || v != 2 {
		t.Fatalf("after no-op write: %d, %v", v, err)
	}
}

func TestSaveReleaseKeepsThreeAndPrunes(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "b.tar")
	os.WriteFile(bundle, []byte("bundle"), 0644)
	releases := filepath.Join(root, "releases")
	for _, v := range []int64{100, 200, 300, 400} {
		if err := SaveRelease(releases, v, bundle, []byte("state")); err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
	}
	ents, err := os.ReadDir(releases)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("releases dir has %d entries, want 3: %v", len(ents), ents)
	}
	for _, want := range []string{"200", "300", "400"} {
		if _, err := os.Stat(filepath.Join(releases, want)); err != nil {
			t.Errorf("release %s missing: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(releases, "100")); err == nil {
		t.Error("release 100 should have been pruned")
	}
	for _, name := range []string{"bundle.tar", "state.tar"} {
		if _, err := os.Stat(filepath.Join(releases, "400", name)); err != nil {
			t.Errorf("400/%s missing: %v", name, err)
		}
	}
}

func TestSnapshotAndRestoreStateRoundTrip(t *testing.T) {
	root := t.TempDir()
	etc, lib := filepath.Join(root, "etc"), filepath.Join(root, "lib")
	write(t, filepath.Join(etc, "net.env"), "PI_IP=10.77.0.1\n")
	write(t, filepath.Join(etc, "broker/secrets.env"), "pf_x_CLAUDE_OAT=live\n")
	write(t, filepath.Join(lib, "state.version"), "2\n")
	write(t, filepath.Join(lib, "releases", "100", "bundle.tar"), "should not be snapshotted")
	write(t, filepath.Join(lib, "incoming", "pf-bundle.tar"), "untrusted upload, not state")

	raw, err := SnapshotState(etc, lib)
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(root, "restored")
	oetc, olib := filepath.Join(out, "etc"), filepath.Join(out, "lib")
	if err := RestoreState(oetc, olib, raw); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(oetc, "net.env")); got != "PI_IP=10.77.0.1\n" {
		t.Errorf("net.env = %q", got)
	}
	if _, err := os.Stat(filepath.Join(oetc, "broker/secrets.env")); err == nil {
		t.Error("broker/secrets.env should have been left out of the snapshot")
	}
	for _, gone := range []string{"releases/100/bundle.tar", "incoming/pf-bundle.tar", "state.version"} {
		if _, err := os.Stat(filepath.Join(olib, gone)); err == nil {
			t.Errorf("%s should have been skipped by the snapshot", gone)
		}
	}
}

func TestSnapshotLeavesOutSecretsKeysTrustRootsAndShipBookkeeping(t *testing.T) {
	root := t.TempDir()
	etc, lib := filepath.Join(root, "etc"), filepath.Join(root, "lib")
	kept := map[string]string{
		"etc/net.env":                "PI_IP=10.77.0.1\n",
		"etc/broker/secrets.expires": "slot=2026-12-01\n",
		"lib/engine/ca-cert.pem":     "public cert\n",
		"lib/www/index.html":         "page\n",
	}
	left := []string{
		"etc/broker/secrets.env", "etc/broker/secrets.env.lock", "etc/broker/.secrets.env.123", "etc/broker/secrets.disabled",
		"etc/secrets.env", "etc/mullvad.conf", "etc/allowed_signers", "etc/release-signers", "etc/lab",
		"etc/agent-env-a1.sh", "etc/agent-credentials-a1.json",
		"lib/engine/ca.pem", "lib/engine/ca-next.pem", "lib/engine/ca-old.pem", "lib/engine/ca-link.pem", "lib/mitm/mitmproxy-ca.pem", "lib/www/claims/ledger.jsonl", "lib/www/claims-redeemed/ledger.jsonl",
		"lib/alert.offset", "lib/alert.last", "lib/observe.json", "lib/observe/observe.json", "lib/observe/dns.offset", "lib/house.leases", "lib/monitor/x.json",
		"lib/ship.version", "lib/ship.pending", "lib/state.version", "lib/install-work/tree/x", "lib/upgrade/abc/pf-bundle.tar",
	}
	for p, body := range kept {
		write(t, filepath.Join(root, p), body)
	}
	for _, p := range left {
		write(t, filepath.Join(root, p), "secret-or-bookkeeping\n")
	}
	raw, err := SnapshotState(etc, lib)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[strings.TrimSuffix(hdr.Name, "/")] = true
	}
	for p := range kept {
		if !names[p] {
			t.Errorf("%s missing from the snapshot", p)
		}
	}
	for _, p := range left {
		if names[p] {
			t.Errorf("%s is in state.tar; it must never be snapshotted", p)
		}
	}
}

func TestRestoreSkipsWhatAnOlderSnapshotStillCarries(t *testing.T) {
	root := t.TempDir()
	etc, lib := filepath.Join(root, "etc"), filepath.Join(root, "lib")
	raw := stateTar(t, map[string]string{
		"etc/net.env":            "PI_IP=10.77.0.1\n",
		"etc/broker/secrets.env": "pf_x_CLAUDE_OAT=deleted-since\n",
		"lib/engine/ca.pem":      "old ca key\n",
		"lib/ship.version":       "1\n",
	})
	write(t, filepath.Join(lib, "ship.version"), "500\n")
	if err := RestoreState(etc, lib, raw); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(etc, "net.env")); got != "PI_IP=10.77.0.1\n" {
		t.Fatalf("net.env = %q", got)
	}
	for _, p := range []string{"etc/broker/secrets.env", "lib/engine/ca.pem"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s was put back from an old snapshot", p)
		}
	}
	if got := read(t, filepath.Join(lib, "ship.version")); got != "500\n" {
		t.Fatalf("restore moved the floor: %q", got)
	}
}

func TestRestoreRefusesToWriteThroughSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	write(t, filepath.Join(outside, "shadow"), "root:x\n")

	t.Run("symlinked parent", func(t *testing.T) {
		etc, lib := filepath.Join(root, "p", "etc"), filepath.Join(root, "p", "lib")
		os.MkdirAll(lib, 0755)
		if err := os.Symlink(outside, filepath.Join(lib, "dns")); err != nil {
			t.Fatal(err)
		}
		err := RestoreState(etc, lib, stateTar(t, map[string]string{"lib/dns/shadow": "owned\n"}))
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
		if got := read(t, filepath.Join(outside, "shadow")); got != "root:x\n" {
			t.Fatalf("written through the symlinked directory: %q", got)
		}
	})
	t.Run("symlinked target", func(t *testing.T) {
		etc, lib := filepath.Join(root, "t", "etc"), filepath.Join(root, "t", "lib")
		os.MkdirAll(etc, 0755)
		if err := os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(etc, "net.env")); err != nil {
			t.Fatal(err)
		}
		err := RestoreState(etc, lib, stateTar(t, map[string]string{"etc/net.env": "owned\n"}))
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
		if got := read(t, filepath.Join(outside, "shadow")); got != "root:x\n" {
			t.Fatalf("written through the symlinked file: %q", got)
		}
	})
}

// stateTar builds a state.tar by hand, as an older build (or a
// tampered file) could have written it.
func stateTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
