package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wanVLAN loads a box whose uplink is wan, with an optional house.env
// and segments made of name:body pairs.
func wanVLAN(t *testing.T, wan, intIF, house string, segs ...string) (*Config, error) {
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
	return Load(Options{Net: lab, HouseEnv: hp, SegmentsDir: sd, IntIF: intIF, WanIF: wan})
}

func segOn(ifname string) string {
	return "iot.env:IF=" + ifname + "\nNET=10.30.0.0/24\nIP=10.30.0.1\n"
}

// An uplink that is itself a VLAN (an ISP VLAN such as eth0.35) puts its
// full cable on the side of the uplink. A sibling VLAN or the untagged
// parent carries frames from all other devices on that wire.
func TestWANCableRefusesSiblingsAndParent(t *testing.T) {
	for _, tc := range []struct {
		name, intIF, house, seg, want string
	}{
		{name: "segment on a sibling vlan", intIF: "eth1", seg: segOn("eth0.30"),
			want: "segment iot: IF=eth0.30 shares a cable with WAN_IF=eth0.35"},
		{name: "segment untagged on the parent", intIF: "eth1", seg: segOn("eth0"),
			want: "segment iot: IF=eth0 shares a cable with WAN_IF=eth0.35"},
		{name: "agents on a sibling vlan", intIF: "eth0.20",
			want: "INT_IF=eth0.20 shares a cable with WAN_IF=eth0.35"},
		{name: "agents untagged on the parent", intIF: "eth0",
			want: "INT_IF=eth0 shares a cable with WAN_IF=eth0.35"},
		{name: "house on a sibling vlan", intIF: "eth1", house: "HOUSE_IF=eth0.40\n",
			want: "HOUSE_IF=eth0.40 shares a cable with WAN_IF=eth0.35"},
		{name: "house untagged on the parent", intIF: "eth1", house: "HOUSE_IF=eth0\n",
			want: "HOUSE_IF=eth0 shares a cable with WAN_IF=eth0.35"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var segs []string
			if tc.seg != "" {
				segs = append(segs, tc.seg)
			}
			_, err := wanVLAN(t, "eth0.35", tc.intIF, tc.house, segs...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "the uplink") || !strings.HasSuffix(err.Error(), "Nothing was changed.") {
				t.Errorf("the refusal does not say why or that nothing was changed: %v", err)
			}
		})
	}
}

func TestWANCableAllowsOtherCables(t *testing.T) {
	for _, tc := range []struct{ name, wan, intIF, house, seg string }{
		{name: "vlan uplink, everything on another cable", wan: "eth0.35", intIF: "eth1.20", house: "HOUSE_IF=eth2\n", seg: segOn("eth1.30")},
		{name: "vlan uplink, a parent that only shares a prefix", wan: "eth0.35", intIF: "eth1", seg: segOn("eth00.30")},
		{name: "vlan uplink, untagged look-alike", wan: "eth0.35", intIF: "eth00", seg: segOn("eth01")},
		{name: "plain uplink, segment beside it", wan: "eth0", intIF: "eth1", seg: segOn("eth00.30")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := wanVLAN(t, tc.wan, tc.intIF, tc.house, tc.seg); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// A WAN that is not a VLAN keeps the one refusal it always had, word for
// word, and nothing new.
func TestPlainWANKeepsTheOldRefusal(t *testing.T) {
	_, err := wanVLAN(t, "eth0", "eth1", "", segOn("eth0.30"))
	want := "segment iot: IF=eth0.30: eth0 is WAN_IF, the uplink, and a VLAN on it would carry tagged frames from the uplink's wire straight into the segment. Put the segment on a cable of its own. Nothing was changed."
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if _, err := wanVLAN(t, "eth0", "eth1.20", "", segOn("eth1.30")); err != nil {
		t.Fatalf("VLANs of another cable beside a plain uplink were refused: %v", err)
	}
}
