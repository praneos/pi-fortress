package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// invalidIfaceNames are names that render refuses.
var invalidIfaceNames = []string{
	"eth1; true",
	"eth0$(true)",
	"eth0`true`",
	"eth0\nPARANOID=1",
	"eth0\rPARANOID=1",
	"eth0'",
	"eth0 eth1",
	"0eth",
	"averyveryverylongname0",
}

// pf install refuses, before any write, an interface name that render
// would refuse. Each name is tried as the uplink, the agent port and the
// house port.
func TestCheckIfacesRefusesInvalidNames(t *testing.T) {
	for _, bad := range invalidIfaceNames {
		if err := checkIfaces(bad, "eth1", ""); err == nil {
			t.Errorf("wan %q: accepted", bad)
		}
		if err := checkIfaces("eth0", bad, ""); err == nil {
			t.Errorf("agent %q: accepted", bad)
		}
		if err := checkIfaces("eth0", "eth1", bad); err == nil {
			t.Errorf("house %q: accepted", bad)
		}
	}
	for _, ok := range [][3]string{
		{"eth0", "eth1", ""},
		{"wlan0", "end0", "eth1.10"},
		{"enx00e04c680001", "br-lan", "usb_0"},
	} {
		if err := checkIfaces(ok[0], ok[1], ok[2]); err != nil {
			t.Errorf("%v: refused: %v", ok, err)
		}
	}
}

// A value with a line break never reaches a file that apply sources,
// because it would add a line of its own.
func TestEnvWritersRefuseLineBreaks(t *testing.T) {
	for _, bad := range []string{"eth0\nPARANOID=1", "eth0\rPARANOID=1", "eth0\r\nid"} {
		dir := t.TempDir()
		netEnv := filepath.Join(dir, "net.env.local")
		if err := WriteNetEnvLocal(netEnv, "eth0", bad); err == nil {
			t.Errorf("WriteNetEnvLocal agent %q: accepted", bad)
		}
		if err := WriteNetEnvLocal(netEnv, bad, "eth1"); err == nil {
			t.Errorf("WriteNetEnvLocal wan %q: accepted", bad)
		}
		houseEnv := filepath.Join(dir, "house.env")
		if err := WriteHouseEnv(houseEnv, bad); err == nil {
			t.Errorf("WriteHouseEnv %q: accepted", bad)
		}
		other := filepath.Join(dir, "other.env")
		if err := UpsertEnv(other, map[string]string{"K": bad}, "# h\n"); err == nil {
			t.Errorf("UpsertEnv %q: accepted", bad)
		}
		for _, p := range []string{netEnv, houseEnv, other} {
			raw, err := os.ReadFile(p)
			if err == nil && strings.Contains(string(raw), "PARANOID=1") {
				t.Errorf("%s: extra line written:\n%s", filepath.Base(p), raw)
			}
		}
	}
}
