package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

// apply.sh sources net.env and house.env, so INT_IF='eth0' is eth0 to
// apply. doctor read the same files literally. So it compared an
// interface name that still had its quotes, and reported each rung
// that names one as broken.
func TestLoadReadsQuotedValuesTheWayApplyDoes(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	houseEnv := filepath.Join(dir, "house.env")
	for path, body := range map[string]string{
		netEnv:   "PI_IP=\"10.77.0.1\"\nINT_IF='eth0'\nALLOW_DOMAIN=\"example.com\"\n",
		houseEnv: "  HOUSE_IF = \"eth1\"  \nHOUSE_IP='10.78.0.1'\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	segs, err := Load(netEnv, houseEnv, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("want agent and house, got %+v", segs)
	}
	if segs[0].IF != "eth0" || segs[0].IP != "10.77.0.1" {
		t.Fatalf("agent segment kept its quotes: %+v", segs[0])
	}
	if segs[0].probe != "example.com" {
		t.Fatalf("probe kept its quotes: %q", segs[0].probe)
	}
	if segs[1].IF != "eth1" || segs[1].IP != "10.78.0.1" {
		t.Fatalf("house segment kept its quotes: %+v", segs[1])
	}
}

// The operator overlay is sourced after net.env, so a quoted value
// there must win in the same way as an unquoted value.
func TestLoadOverlayIsUnquotedToo(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("PI_IP=10.77.0.1\nINT_IF=eth0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netEnv+".local", []byte("INT_IF=\"eth9\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	segs, err := Load(netEnv, filepath.Join(dir, "absent.env"), "")
	if err != nil {
		t.Fatal(err)
	}
	if segs[0].IF != "eth9" {
		t.Fatalf("overlay INT_IF=\"eth9\" ignored: %q", segs[0].IF)
	}
}
