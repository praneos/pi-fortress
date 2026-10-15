package admin

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// iotConfig is segConfig plus an IoT segment with space for a range. The
// code checks the DHCP keys of the editor against a /24, not the desk /30.
func iotConfig(t *testing.T) (*Config, string) {
	t.Helper()
	c, _ := segConfig(t)
	path := filepath.Join(c.SegmentsDir, "iot.env")
	write(t, path, "# the IoT SSID\nIF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n")
	return c, path
}

func TestSegmentDHCPKeysAreEditable(t *testing.T) {
	for _, k := range []string{"DHCP", "DHCP_START", "DHCP_END"} {
		if !slices.Contains(SegmentKeys, k) {
			t.Errorf("%s is not one of SegmentKeys", k)
		}
	}
	if SegmentToggle["DHCP"] != [2]string{"off", "on"} {
		t.Errorf("DHCP does not flip off/on with off the default: %v", SegmentToggle["DHCP"])
	}
	if !slices.Equal(SegmentDHCPRange, []string{"DHCP_START", "DHCP_END"}) {
		t.Errorf("SegmentDHCPRange = %v", SegmentDHCPRange)
	}
}

func TestSegmentEnvDefaultsDHCPToOff(t *testing.T) {
	c, _ := iotConfig(t)
	env, err := c.SegmentEnv("iot")
	if err != nil {
		t.Fatal(err)
	}
	if env["DHCP"] != "off" || env["DHCP_START"] != "" || env["DHCP_END"] != "" {
		t.Fatalf("DHCP defaults: %+v", env)
	}
}

// The range goes in as one edit, then DHCP=on. The file keeps its comment
// and its order.
func TestSetSegmentEnvTurnsOnDHCP(t *testing.T) {
	c, path := iotConfig(t)
	if warn, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP_START": "10.30.0.100", "DHCP_END": "10.30.0.199"}); err != nil || warn != "" {
		t.Fatalf("range: %v, warn %q", err, warn)
	}
	if warn, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP": "on"}); err != nil || warn != "" {
		t.Fatalf("DHCP=on: %v, warn %q", err, warn)
	}
	want := "# the IoT SSID\nIF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP_END=10.30.0.199\nDHCP_START=10.30.0.100\nDHCP=on\n"
	if got := read(t, path); got != want {
		t.Fatalf("the file:\n%s\nwant\n%s", got, want)
	}
	// One end can move alone when the range exists.
	if _, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP_END": "10.30.0.150"}); err != nil {
		t.Fatalf("DHCP_END alone with a range in place: %v", err)
	}
}

func TestSetSegmentEnvRefusesABadDHCPEditAndChangesNothing(t *testing.T) {
	c, path := iotConfig(t)
	before := read(t, path)
	for _, tc := range []struct {
		kv   map[string]string
		want string
	}{
		{map[string]string{"DHCP": "yes"}, "on or off"},
		{map[string]string{"DHCP_START": ""}, "IPv4 address"},
		{map[string]string{"DHCP_START": "10.30.0"}, "IPv4 address"},
		// The rest are pf render's, through the candidate directory.
		{map[string]string{"DHCP": "on"}, "DHCP=on needs DHCP_START and DHCP_END"},
		{map[string]string{"DHCP_START": "10.30.0.100"}, "DHCP_START and DHCP_END go together"},
		{map[string]string{"DHCP_START": "10.30.0.200", "DHCP_END": "10.30.0.100"}, "is above DHCP_END"},
		{map[string]string{"DHCP_START": "10.30.0.1", "DHCP_END": "10.30.0.50"}, "covers IP=10.30.0.1"},
		{map[string]string{"DHCP_START": "10.31.0.100", "DHCP_END": "10.31.0.199"}, "is not inside NET=10.30.0.0/24"},
	} {
		_, err := c.SetSegmentEnvKeys("iot", tc.kv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: got %v, want %q", tc.kv, err, tc.want)
		}
		if got := read(t, path); got != before {
			t.Fatalf("%v was refused and wrote the file anyway:\n%s", tc.kv, got)
		}
	}
}

// Reservations are a file beside segments.d, not a key. The candidate
// render sees them. Thus a screen refuses DHCP off under them, as apply
// refuses it.
func TestSetSegmentEnvRefusesDHCPOffUnderReservations(t *testing.T) {
	c, path := iotConfig(t)
	if _, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP_START": "10.30.0.100", "DHCP_END": "10.30.0.199"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP": "on"}); err != nil {
		t.Fatal(err)
	}
	if got, want := SegmentHostsPath(c.SegmentsDir, "iot"), filepath.Join(filepath.Dir(c.SegmentsDir), "dhcp.iot.hosts"); got != want {
		t.Fatalf("SegmentHostsPath = %s, want %s", got, want)
	}
	write(t, SegmentHostsPath(c.SegmentsDir, "iot"), "02:00:00:00:00:0a,10.30.0.50,cam\n")
	before := read(t, path)
	_, err := c.SetSegmentEnvKeys("iot", map[string]string{"DHCP": "off"})
	if err == nil || !strings.Contains(err.Error(), "but DHCP is off") {
		t.Fatalf("DHCP=off under a reservation: %v", err)
	}
	if got := read(t, path); got != before {
		t.Fatalf("the refused edit wrote the file:\n%s", got)
	}
}
