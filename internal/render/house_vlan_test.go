package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// houseVLAN loads a house and a segments.d made of name:body pairs.
func houseVLAN(t *testing.T, house, intIF string, stderr *bytes.Buffer, segs ...string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	hp := "/nonexistent/house.env"
	if house != "" {
		hp = write(t, dir, "house.env", house)
	}
	sd := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(sd, 0755); err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		name, body, _ := strings.Cut(s, ":")
		write(t, sd, name, body)
	}
	o := Options{Net: lab, HouseEnv: hp, SegmentsDir: sd, IntIF: intIF}
	if stderr != nil {
		o.Stderr = stderr
	}
	return Load(o)
}

const iotBase = "iot.env:IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n"

// A segment on the house cable is only as isolated as the consumer AP
// that tags it. Thus nothing on that cable can hold more than house
// trust: no SSH to the Pi, no SSH into the agents, and never the agent
// network itself. Each refusal has its happy-path twin.
func TestHouseCableRefusesMoreThanHouseTrust(t *testing.T) {
	for _, tc := range []struct {
		name, house, intIF, seg, want string
	}{
		{name: "admin on a vlan of the house", house: "HOUSE_IF=eth2\n", seg: iotBase + "ADMIN=yes\n",
			want: "segment iot: IF=eth2.30 is a VLAN on HOUSE_IF=eth2, and ADMIN=yes would let it SSH to the Pi"},
		{name: "ssh_to on a vlan of the house", house: "HOUSE_IF=eth2\n", seg: iotBase + "SSH_TO=10.77.0.10\n",
			want: "segment iot: IF=eth2.30 is a VLAN on HOUSE_IF=eth2, and SSH_TO=10.77.0.10 would let it SSH into the agent network"},
		{name: "agent network on a vlan of the house", house: "HOUSE_IF=eth2\n", intIF: "eth2.20",
			want: "INT_IF=eth2.20 is a VLAN on HOUSE_IF=eth2"},
		// The house itself can be a VLAN child. The cable is then its
		// parent, and a sibling or the untagged parent also uses it.
		{name: "admin on a sibling of a vlan house", house: "HOUSE_IF=eth2.10\nHOUSE_NET=10.78.0.0/24\n", seg: iotBase + "ADMIN=yes\n",
			want: "segment iot: IF=eth2.30 shares a cable with HOUSE_IF=eth2.10, and ADMIN=yes"},
		{name: "admin untagged under a vlan house", house: "HOUSE_IF=eth2.10\n", seg: "iot.env:IF=eth2\nNET=10.30.0.0/24\nIP=10.30.0.1\nADMIN=yes\n",
			want: "segment iot: IF=eth2 shares a cable with HOUSE_IF=eth2.10, and ADMIN=yes"},
		{name: "agent network untagged under a vlan house", house: "HOUSE_IF=eth2.10\n", intIF: "eth2",
			want: "INT_IF=eth2 shares a cable with HOUSE_IF=eth2.10"},
		{name: "agent network a sibling of a vlan house", house: "HOUSE_IF=eth2.10\n", intIF: "eth2.20",
			want: "INT_IF=eth2.20 shares a cable with HOUSE_IF=eth2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var segs []string
			if tc.seg != "" {
				segs = append(segs, tc.seg)
			}
			_, err := houseVLAN(t, tc.house, tc.intIF, nil, segs...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if !strings.HasSuffix(err.Error(), "Nothing was changed.") {
				t.Errorf("the refusal does not say nothing was changed: %v", err)
			}
		})
	}
}

func TestHouseCableAllowsAHouseTrustSegment(t *testing.T) {
	for _, tc := range []struct{ name, house, intIF, seg string }{
		{name: "plain iot vlan", house: "HOUSE_IF=eth2\n", seg: iotBase},
		{name: "explicit admin no", house: "HOUSE_IF=eth2\n", seg: iotBase + "ADMIN=no\nSSH_TO=\n"},
		// SSH_FROM names who can SSH in. It gives the segment nothing.
		{name: "ssh_from into the iot vlan", house: "HOUSE_IF=eth2\n", seg: iotBase + "SSH_FROM=10.78.0.20\n"},
		{name: "agents on another cable", house: "HOUSE_IF=eth2\n", intIF: "eth0.20", seg: iotBase},
		{name: "sibling of a vlan house", house: "HOUSE_IF=eth2.10\n", seg: iotBase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := houseVLAN(t, tc.house, tc.intIF, nil, tc.seg); err != nil {
				t.Fatalf("a house-trust segment on the house cable was refused: %v", err)
			}
		})
	}
}

// A VLAN whose parent is not the house cable keeps ADMIN and SSH_TO as
// before. This includes a parent whose name only starts with the name of HOUSE_IF.
func TestVLANOffTheHouseCableKeepsAdminAndSSH(t *testing.T) {
	desk := "desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\n"
	for _, tc := range []struct{ name, house, intIF, seg, ifname string }{
		{name: "desk vlan beside a house port", house: "HOUSE_IF=eth2\n", intIF: "eth0.20", seg: desk, ifname: "eth0.79"},
		{name: "no house at all", seg: "iot.env:IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nADMIN=yes\nSSH_TO=10.77.0.10\n", ifname: "eth2.30"},
		{name: "a parent that only shares a prefix", house: "HOUSE_IF=eth2\n", seg: "iot.env:IF=eth20.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nADMIN=yes\nSSH_TO=10.77.0.10\n", ifname: "eth20.30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			c, err := houseVLAN(t, tc.house, tc.intIF, &stderr, tc.seg)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			nft := c.Ruleset(labElements)
			for _, want := range []string{
				`iifname "` + tc.ifname + `" tcp dport 22 ct state new accept`,
				`iifname "` + tc.ifname + `" oifname "` + c.IntIF + `" ip daddr `,
			} {
				if !strings.Contains(nft, want) {
					t.Errorf("missing %q", want)
				}
			}
			if strings.Contains(stderr.String(), "house cable") {
				t.Errorf("warned about a segment off the house cable: %s", stderr.String())
			}
		})
	}
}

// The warning goes to stderr, and the render still succeeds. A VLAN for
// each SSID is allowed, and the operator learns what it depends on.
func TestHouseCableWarns(t *testing.T) {
	var stderr bytes.Buffer
	guest := "guest.env:IF=eth2.40\nNET=10.40.0.0/24\nIP=10.40.0.1\n"
	c, err := houseVLAN(t, "HOUSE_IF=eth2\n", "", &stderr, iotBase, guest)
	if err != nil {
		t.Fatalf("a house-trust VLAN segment was refused: %v", err)
	}
	if c.Ruleset(labElements) == "" {
		t.Fatal("no ruleset")
	}
	got := stderr.String()
	for _, want := range []string{
		"pi-fortress: WARNING",
		"guest (IF=eth2.40), iot (IF=eth2.30)",
		"HOUSE_IF=eth2",
		"only as isolated as the AP or switch",
		"its own VLAN tag",
		"tagged frames",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning lacks %q:\n%s", want, got)
		}
	}
	if n := strings.Count(strings.TrimRight(got, "\n"), "\n") + 1; n > 2 {
		t.Errorf("warning is %d lines, want at most 2:\n%s", n, got)
	}

	stderr.Reset()
	if _, err := houseVLAN(t, "HOUSE_IF=eth2\n", "", &stderr, "desk.env:IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n"); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Errorf("warned with nothing on the house cable: %s", stderr.String())
	}
	if _, err := houseVLAN(t, "HOUSE_IF=eth2\n", "", nil, iotBase); err != nil {
		t.Fatalf("no stderr: %v", err)
	}
}

// What a VLAN on the house cable already gets: a fence from the house,
// the agents and all other segments in the two directions. The Pi answers
// it only on DNS and ping. The holes of the house use the exact house
// interface as the key. Thus a frame tagged into the VLAN cannot use them.
func TestHouseVLANSegmentIsIsolated(t *testing.T) {
	desk := "desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10\n"
	c, err := houseVLAN(t, "HOUSE_IF=eth2\nHOUSE_ADMIN_IP=10.78.0.20\n", "eth0.20", nil, iotBase, desk)
	if err != nil {
		t.Fatal(err)
	}
	nft := c.Ruleset(labElements)
	fwd := chain(t, nft, "forward")
	for _, pair := range [][2]string{
		{"eth2.30", "eth2"}, {"eth2", "eth2.30"},
		{"eth2.30", "eth0.20"}, {"eth0.20", "eth2.30"},
		{"eth2.30", "eth0.79"}, {"eth0.79", "eth2.30"},
	} {
		if want := `iifname "` + pair[0] + `" oifname "` + pair[1] + `" counter drop`; !strings.Contains(fwd, want) {
			t.Errorf("forward lacks %q", want)
		}
	}
	for _, want := range []string{
		`iifname "eth2.30" ip daddr @reserved_v4 counter drop`,
		`iifname "eth2.30" ip saddr != 10.30.0.0/24 counter drop`,
		`iifname "eth2" ip saddr 10.78.0.20 tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept`,
		`iifname "eth2" oifname "eth0.20" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q", want)
		}
	}
	in := chain(t, nft, "input")
	var iot []string
	for _, l := range strings.Split(in, "\n") {
		if strings.Contains(l, `iifname "eth2.30"`) {
			iot = append(iot, strings.TrimSpace(l))
		}
	}
	for _, l := range iot {
		ok := strings.Contains(l, "dport 53") || strings.Contains(l, "echo-request") ||
			strings.Contains(l, `ip daddr 10.30.0.1 udp dport 123 accept`) ||
			strings.HasSuffix(l, "counter drop") || strings.Contains(l, "log prefix") ||
			strings.Contains(l, "jump seg_iot_")
		if !ok || (strings.Contains(l, "accept") && strings.Contains(l, "dport 22")) {
			t.Errorf("input opens more than DNS, NTP and ping to the house VLAN: %s", l)
		}
	}
	if len(iot) == 0 || iot[len(iot)-1] != `iifname "eth2.30" counter drop` {
		t.Errorf("the house VLAN's input does not end in its drop: %q", iot)
	}
	if strings.Contains(nft, `"eth2*"`) {
		t.Error("an interface wildcard would let the VLAN match the house's rules")
	}
}
