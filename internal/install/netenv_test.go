package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteNetEnvLocalFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net.env.local")
	if err := WriteNetEnvLocal(path, "wlan0", "eth0"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "INT_IF=eth0") || !strings.Contains(s, "WAN_IF=wlan0") {
		t.Fatalf("unexpected content:\n%s", s)
	}
}

func TestWriteNetEnvLocalOnAFreshBox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "pi-fortress", "net.env.local")
	if err := WriteNetEnvLocal(path, "eth0", "eth1"); err != nil {
		t.Fatalf("no /etc/pi-fortress yet: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), "INT_IF=eth1") {
		t.Fatalf("%v\n%s", err, raw)
	}
}

func TestWriteGatewayRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "pi-fortress", "gateway.role")
	if err := WriteGatewayRole(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no role file: %v", err)
	}
	if err := WriteGatewayRole(""); err != nil {
		t.Fatalf("empty path: %v", err)
	}
}

func TestSaveReleaseSigners(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "signers.tmp")
	line := "release@pi-fortress namespaces=\"pi-fortress-dist\" ssh-ed25519 AAAA\n"
	if err := os.WriteFile(src, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "etc", "pi-fortress", "release-signers")
	if err := SaveReleaseSigners(src, dst); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(dst); err != nil || string(raw) != line {
		t.Fatalf("%v %q", err, raw)
	}
	if err := SaveReleaseSigners(dst, dst); err != nil {
		t.Fatalf("same path: %v", err)
	}
	if err := SaveReleaseSigners(src, ""); err != nil {
		t.Fatalf("empty dst: %v", err)
	}
}

// A line with no namespaces option, or with the ship namespace, never
// gets into release-signers, and the file that is there stays.
func TestSaveReleaseSignersRefusesAnUnboundLine(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "release-signers")
	kept := "release@pi-fortress namespaces=\"pi-fortress-dist\" ssh-ed25519 AAAA\n"
	if err := os.WriteFile(dst, []byte(kept), 0644); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"release@pi-fortress ssh-ed25519 BBBB\n",
		"release@pi-fortress namespaces=\"pi-fortress-release\" ssh-ed25519 BBBB\n",
	} {
		src := filepath.Join(dir, "signers.tmp")
		if err := os.WriteFile(src, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		err := SaveReleaseSigners(src, dst)
		if err == nil || !strings.Contains(err.Error(), `namespaces="pi-fortress-dist"`) {
			t.Fatalf("%q: want a refusal that names namespaces=\"pi-fortress-dist\", got %v", line, err)
		}
		if raw, _ := os.ReadFile(dst); string(raw) != kept {
			t.Fatalf("%q: release-signers changed to %q", line, raw)
		}
	}
}

func TestSaveReleaseURLFeedsUpgrade(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "etc", "pi-fortress", "release.url")
	base := "https://github.com/praneos/pi-fortress/releases/download"
	if err := SaveReleaseURL(base+"\n", dst); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveReleaseURL("", dst); err != nil || got != base {
		t.Fatalf("upgrade reads %q, %v; want %q", got, err, base)
	}
	if err := SaveReleaseURL("", dst); err != nil {
		t.Fatalf("offline install: %v", err)
	}
	if got, _ := ResolveReleaseURL("", dst); got != base {
		t.Fatalf("offline install clobbered release.url: %q", got)
	}
}

func TestSaveReleaseURLRefusesNonHTTP(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "release.url")
	for _, bad := range []string{"file:///etc/passwd", "github.com/x", "https://a b/c", "https://"} {
		if err := SaveReleaseURL(bad, dst); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("refused URL still wrote %s: %v", dst, err)
	}
}

func TestWriteNetEnvLocalUpsertPreservesOtherLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net.env.local")
	initial := "AGENT_DNS=forward\n#INT_IF=eth9\nWAN_IF=oldwan\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteNetEnvLocal(path, "wlan1", "eth2"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "AGENT_DNS=forward") {
		t.Fatalf("lost an unrelated line:\n%s", s)
	}
	if !strings.Contains(s, "INT_IF=eth2") {
		t.Fatalf("did not set INT_IF from the commented example:\n%s", s)
	}
	if strings.Contains(s, "#INT_IF=eth9") {
		t.Fatalf("left the old commented line behind:\n%s", s)
	}
	if !strings.Contains(s, "WAN_IF=wlan1") || strings.Contains(s, "WAN_IF=oldwan") {
		t.Fatalf("did not overwrite WAN_IF:\n%s", s)
	}
}

func TestWriteNetEnvLocalEmptyIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net.env.local")
	if err := WriteNetEnvLocal(path, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected no file to be written when both interfaces are empty")
	}
}

func TestWriteHouseEnvFreshSetsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "house.env")
	if err := WriteHouseEnv(path, "eth3"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	s := string(raw)
	for _, want := range []string{"HOUSE_IF=eth3", "HOUSE_NET=10.78.0.0/24", "HOUSE_IP=10.78.0.1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestWriteHouseEnvExistingKeepsOperatorKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "house.env")
	initial := "HOUSE_IF=eth3\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\nHOUSE_ADMIN_IP=10.78.0.20\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteHouseEnv(path, "eth4"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	s := string(raw)
	if !strings.Contains(s, "HOUSE_IF=eth4") {
		t.Fatalf("did not update HOUSE_IF:\n%s", s)
	}
	if !strings.Contains(s, "HOUSE_ADMIN_IP=10.78.0.20") {
		t.Fatalf("lost the operator's HOUSE_ADMIN_IP:\n%s", s)
	}
}

func TestRemoveLabMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lab")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveLabMarker(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("lab marker still present")
	}
	// Absent is not an error.
	if err := RemoveLabMarker(path); err != nil {
		t.Fatalf("removing an already-absent marker: %v", err)
	}
}

func TestSaveReleaseURLRefusesPlainHTTP(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "release.url")
	if err := SaveReleaseURL("http://pi-fortress-block.test/releases/download", dst); err == nil {
		t.Fatal("an http release URL was kept for pf upgrade")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("refused URL still wrote %s: %v", dst, err)
	}
}
