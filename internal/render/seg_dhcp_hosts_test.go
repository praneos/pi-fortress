package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// segHosts loads one segment, iot.env with body, and its reservations
// file dhcp.iot.hosts with hosts, next to segments.d as the box
// keeps them. hosts "-" writes no file at all.
func segHosts(t *testing.T, body, hosts string) (*Config, string, error) {
	t.Helper()
	dir := t.TempDir()
	sd := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(sd, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, sd, "iot.env", body)
	path := SegmentHostsPath(sd, "iot")
	if hosts != "-" {
		if err := os.WriteFile(path, []byte(hosts), 0644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: sd})
	return c, path, err
}

const iotDHCP = "IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n"

func TestSegmentHostsPathIsBesideSegmentsD(t *testing.T) {
	if got := SegmentHostsPath("/etc/pi-fortress/segments.d", "iot"); got != "/etc/pi-fortress/dhcp.iot.hosts" {
		t.Fatalf("SegmentHostsPath = %s", got)
	}
}

// The house.hosts form of the house, MAC,IP or MAC,IP,name, with comments
// and blank lines. A reserved address can be inside the dynamic range or
// outside it, as the house allows. The MAC is written as dnsmasq and the
// reservations of the house write it, lower case with colons. apply gets
// the checked entries in apply.env.
func TestSegmentHostsLoad(t *testing.T) {
	c, _, err := segHosts(t, iotDHCP, "# cameras\n\n02:00:00:00:00:0A,10.30.0.50,cam-door\n02-00-00-00-00-0b, 10.30.0.150\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []SegHost{{MAC: "02:00:00:00:00:0a", IP: "10.30.0.50", Name: "cam-door"}, {MAC: "02:00:00:00:00:0b", IP: "10.30.0.150"}}
	got := c.Segments[0].Hosts
	if len(got) != len(want) {
		t.Fatalf("hosts = %+v", got)
	}
	for i := range want {
		if got[i].MAC != want[i].MAC || got[i].IP != want[i].IP || got[i].Name != want[i].Name {
			t.Fatalf("host %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	env := c.EnvFile()
	if !strings.Contains(env, "SEG_DHCP_HOSTS=('02:00:00:00:00:0a,10.30.0.50,cam-door 02:00:00:00:00:0b,10.30.0.150')\n") {
		t.Fatalf("apply.env does not carry the checked reservations:\n%s", env)
	}
}

// No file means no reservations. A file of comments also means no
// reservations, also with DHCP off: it has nothing to give out.
func TestSegmentHostsAbsentOrEmpty(t *testing.T) {
	for _, tc := range []struct{ name, body, hosts string }{
		{"no file", iotDHCP, "-"},
		{"no file, DHCP off", "IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n", "-"},
		{"comments only, DHCP off", "IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n", "# none yet\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, err := segHosts(t, tc.body, tc.hosts)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(c.Segments[0].Hosts) != 0 {
				t.Fatalf("hosts = %+v", c.Segments[0].Hosts)
			}
			if !strings.Contains(c.EnvFile(), "SEG_DHCP_HOSTS=('')\n") {
				t.Fatalf("apply.env:\n%s", c.EnvFile())
			}
		})
	}
}

func TestSegmentHostsRefusals(t *testing.T) {
	ok := "02:00:00:00:00:0a,10.30.0.50,cam\n"
	for _, tc := range []struct{ name, body, hosts, want string }{
		{"one field", iotDHCP, "02:00:00:00:00:0a\n", "dhcp.iot.hosts:1: '02:00:00:00:00:0a' is not MAC,IP or MAC,IP,name"},
		{"four fields", iotDHCP, "02:00:00:00:00:0a,10.30.0.50,cam,extra\n", "is not MAC,IP or MAC,IP,name"},
		{"bad MAC", iotDHCP, "02:00:00:00:00:zz,10.30.0.50\n", "dhcp.iot.hosts:1: '02:00:00:00:00:zz' is not a MAC address"},
		{"short MAC", iotDHCP, "02:00:00:00:0a,10.30.0.50\n", "'02:00:00:00:0a' is not a MAC address"},
		{"EUI-64 is not a MAC", iotDHCP, "02:00:00:00:00:00:00:0a,10.30.0.50\n", "is not a MAC address"},
		{"bad IP", iotDHCP, "02:00:00:00:00:0a,10.30.0.500\n", "'10.30.0.500' is not an IPv4 address"},
		{"bad name", iotDHCP, "02:00:00:00:00:0a,10.30.0.50,cam_door\n", "'cam_door' is not a host name"},
		{"outside NET", iotDHCP, "02:00:00:00:00:0a,10.31.0.50\n", "segment iot: " + "%s:1: 10.31.0.50 is not inside NET=10.30.0.0/24"},
		{"the gateway", iotDHCP, "02:00:00:00:00:0a,10.30.0.1\n", "10.30.0.1 is IP, the address the Pi answers on"},
		{"the network address", iotDHCP, "02:00:00:00:00:0a,10.30.0.0\n", "10.30.0.0 is the network address of NET=10.30.0.0/24"},
		{"the broadcast address", iotDHCP, "02:00:00:00:00:0a,10.30.0.255\n", "10.30.0.255 is the broadcast address of NET=10.30.0.0/24"},
		{"duplicate MAC", iotDHCP, ok + "# again\n02:00:00:00:00:0A,10.30.0.51\n", "dhcp.iot.hosts:3: 02:00:00:00:00:0a is already reserved on line 1"},
		{"duplicate IP", iotDHCP, ok + "02:00:00:00:00:0b,10.30.0.50\n", "dhcp.iot.hosts:2: 10.30.0.50 is already reserved for 02:00:00:00:00:0a on line 1"},
		{"DHCP off", "IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n", ok, "segment iot: %s reserves 1 address, but DHCP is off"},
		{"DHCP off explicitly", "IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=off\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n", ok + "02:00:00:00:00:0b,10.30.0.51\n", "reserves 2 addresses, but DHCP is off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, path, err := segHosts(t, tc.body, tc.hosts)
			want := tc.want
			if strings.Contains(want, "%s") {
				want = strings.ReplaceAll(want, "%s", path)
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
			if !strings.HasSuffix(err.Error(), "Nothing was changed.") {
				t.Errorf("the refusal does not say nothing was changed: %v", err)
			}
		})
	}
}

// A reservations file that apply cannot read is not an empty file. A
// render without it would remove all fixed leases on the segment.
func TestSegmentHostsUnreadable(t *testing.T) {
	dir := t.TempDir()
	sd := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(sd, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, sd, "iot.env", iotDHCP)
	if err := os.Mkdir(SegmentHostsPath(sd, "iot"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: sd})
	if err == nil || !strings.Contains(err.Error(), "dhcp.iot.hosts cannot be read") || !strings.HasSuffix(err.Error(), "Nothing was changed.") {
		t.Fatalf("a reservations path that is a directory was read as no reservations: %v", err)
	}
}
