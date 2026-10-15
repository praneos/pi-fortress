package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// segDHCP loads segments.d made of name:body pairs next to an optional
// house.env.
func segDHCP(t *testing.T, house string, stderr *bytes.Buffer, segs ...string) (*Config, error) {
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
	o := Options{Net: lab, HouseEnv: hp, SegmentsDir: sd}
	if stderr != nil {
		o.Stderr = stderr
	}
	return Load(o)
}

const iotNet = "iot.env:IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.1\n"

func TestSegmentDHCPLoads(t *testing.T) {
	c, err := segDHCP(t, "", nil, iotNet+"DHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n",
		"desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	if err != nil {
		t.Fatal(err)
	}
	var desk, iot Segment
	for _, s := range c.Segments {
		switch s.Name {
		case "desk":
			desk = s
		case "iot":
			iot = s
		}
	}
	if iot.DHCP != "on" || iot.DHCPStart != "10.30.0.100" || iot.DHCPEnd != "10.30.0.199" {
		t.Fatalf("iot: %+v", iot)
	}
	if desk.DHCP != "" {
		t.Fatalf("DHCP is on for a segment that never asked: %+v", desk)
	}
	env := c.EnvFile()
	for _, want := range []string{
		"SEG_DHCP=('off' 'on')\n",
		"SEG_DHCP_START=('' '10.30.0.100')\n",
		"SEG_DHCP_END=('' '10.30.0.199')\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("apply.env lacks %q:\n%s", want, env)
		}
	}
}

// The smallest net that a lease fits in: a /30 has one address left in
// addition to the address of the Pi. An explicit DHCP=off renders exactly
// what no line renders.
func TestSegmentDHCPEdges(t *testing.T) {
	for _, tc := range []struct{ name, seg string }{
		{name: "one lease in a /30", seg: "desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nDHCP=on\nDHCP_START=10.79.0.2\nDHCP_END=10.79.0.2\n"},
		{name: "range right below the gateway", seg: "iot.env:IF=eth2.30\nNET=10.30.0.0/24\nIP=10.30.0.254\nDHCP=on\nDHCP_START=10.30.0.1\nDHCP_END=10.30.0.253\n"},
		{name: "off with no range", seg: iotNet + "DHCP=off\n"},
		{name: "off keeps a valid range for later", seg: iotNet + "DHCP=off\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := segDHCP(t, "", nil, tc.seg); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	off, err := segDHCP(t, "", nil, iotNet+"DHCP=off\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n")
	if err != nil {
		t.Fatal(err)
	}
	none, err := segDHCP(t, "", nil, iotNet)
	if err != nil {
		t.Fatal(err)
	}
	if off.Ruleset(labElements) != none.Ruleset(labElements) {
		t.Error("DHCP=off changed the ruleset")
	}
	if off.Segments[0].DHCP != "" {
		t.Errorf("DHCP=off is not normalised to off: %q", off.Segments[0].DHCP)
	}
}

func TestSegmentDHCPRefusals(t *testing.T) {
	rng := func(a, b string) string { return iotNet + "DHCP=on\nDHCP_START=" + a + "\nDHCP_END=" + b + "\n" }
	for _, tc := range []struct{ name, house, seg, other, want string }{
		{name: "not on or off", seg: iotNet + "DHCP=yes\n", want: "DHCP='yes' is not on or off"},
		{name: "start not an address", seg: rng("10.30.0", "10.30.0.199"), want: "DHCP_START='10.30.0' is not an IPv4 address"},
		{name: "end not an address", seg: rng("10.30.0.100", "10.30.0.300"), want: "DHCP_END='10.30.0.300' is not an IPv4 address"},
		{name: "on without a range", seg: iotNet + "DHCP=on\n", want: "segment iot: DHCP=on needs DHCP_START and DHCP_END"},
		{name: "on with half a range", seg: iotNet + "DHCP=on\nDHCP_START=10.30.0.100\n", want: "segment iot: DHCP=on needs DHCP_START and DHCP_END"},
		{name: "half a range while off", seg: iotNet + "DHCP_END=10.30.0.199\n", want: "segment iot: DHCP_START and DHCP_END go together"},
		{name: "start outside the net", seg: rng("10.31.0.100", "10.30.0.199"), want: "segment iot: DHCP_START=10.31.0.100 is not inside NET=10.30.0.0/24"},
		{name: "end outside the net", seg: rng("10.30.0.100", "10.30.1.10"), want: "segment iot: DHCP_END=10.30.1.10 is not inside NET=10.30.0.0/24"},
		{name: "start above end", seg: rng("10.30.0.200", "10.30.0.100"), want: "segment iot: DHCP_START=10.30.0.200 is above DHCP_END=10.30.0.100"},
		{name: "covers the gateway", seg: rng("10.30.0.1", "10.30.0.50"), want: "covers IP=10.30.0.1"},
		{name: "covers the network address", seg: rng("10.30.0.0", "10.30.0.0"), want: "covers 10.30.0.0, the network address of NET=10.30.0.0/24"},
		{name: "covers the broadcast address", seg: rng("10.30.0.200", "10.30.0.255"), want: "covers 10.30.0.255, the broadcast address of NET=10.30.0.0/24"},
		{name: "a /30 has no room beside the gateway and the edges", seg: "desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.2\nDHCP=on\nDHCP_START=10.79.0.1\nDHCP_END=10.79.0.3\n", want: "segment desk: the DHCP range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs := []string{tc.seg}
			if tc.other != "" {
				segs = append(segs, tc.other)
			}
			_, err := segDHCP(t, tc.house, nil, segs...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if !strings.HasSuffix(err.Error(), "Nothing was changed.") {
				t.Errorf("the refusal does not say nothing was changed: %v", err)
			}
		})
	}
}

// A range is inside its own NET, and NETs cannot overlap each other or
// HOUSE_NET. Thus two ranges can never share an address. The overlap is
// refused before the code examines a range.
func TestSegmentDHCPRangesNeverOverlap(t *testing.T) {
	a := iotNet + "DHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n"
	b := "cam.env:IF=eth2.40\nNET=10.30.0.128/25\nIP=10.30.0.129\nDHCP=on\nDHCP_START=10.30.0.150\nDHCP_END=10.30.0.160\n"
	if _, err := segDHCP(t, "", nil, a, b); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("two segments' ranges sharing addresses were accepted: %v", err)
	}
	house := "HOUSE_IF=eth1\nHOUSE_NET=10.30.0.0/24\nHOUSE_IP=10.30.0.1\nHOUSE_DHCP_START=10.30.0.100\nHOUSE_DHCP_END=10.30.0.199\n"
	if _, err := segDHCP(t, house, nil, "iot.env:IF=eth2.30\nNET=10.30.0.0/25\nIP=10.30.0.2\nDHCP=on\nDHCP_START=10.30.0.110\nDHCP_END=10.30.0.120\n"); err == nil || !strings.Contains(err.Error(), "overlaps HOUSE_NET") {
		t.Fatalf("a range inside the house's was accepted: %v", err)
	}
}

// DHCP is allowed on the house cable, where it is the main purpose: it
// grants nothing past house trust. The warning says that the AP must not
// also serve DHCP on that SSID.
func TestSegmentDHCPOnTheHouseCable(t *testing.T) {
	var stderr bytes.Buffer
	_, err := segDHCP(t, "HOUSE_IF=eth2\n", &stderr, iotNet+"DHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n")
	if err != nil {
		t.Fatalf("DHCP on a house-cable VLAN was refused: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "rides the house cable") || !strings.Contains(got, "must not run its own DHCP") {
		t.Errorf("the warning does not tell the operator to keep the AP's DHCP off:\n%s", got)
	}
	if n := strings.Count(strings.TrimRight(got, "\n"), "\n") + 1; n > 2 {
		t.Errorf("warning is %d lines, want at most 2:\n%s", n, got)
	}
	stderr.Reset()
	if _, err := segDHCP(t, "HOUSE_IF=eth2\n", &stderr, iotNet); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "DHCP") {
		t.Errorf("the warning mentions DHCP for a segment without it:\n%s", stderr.String())
	}
}

// With DHCP on, the interface of the segment gets the three DHCP rules of
// the house and nothing more. Its own spoof chain returns the 0.0.0.0
// source of a client without a lease to raw prerouting. The gate lets a
// broadcast to port 67 pass. Input accepts port 67. All other segments,
// and the same segment with DHCP off, do not change.
func TestSegmentDHCPFirewall(t *testing.T) {
	desk := "desk.env:IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n"
	on, err := segDHCP(t, "", nil, iotNet+"DHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n", desk)
	if err != nil {
		t.Fatal(err)
	}
	off, err := segDHCP(t, "", nil, iotNet, desk)
	if err != nil {
		t.Fatal(err)
	}
	nft := on.Ruleset(labElements)

	raw := chain(t, nft, "filter_prerouting")
	order(t, raw, "filter_prerouting",
		`iifname "eth2.30" ip saddr != 10.30.0.0/24 jump seg_iot_spoof`,
		`iifname "eth2.30" meta nfproto ipv6 counter drop`)
	order(t, raw, "filter_prerouting", `iifname "eth0.79" ip saddr != 10.79.0.0/30 counter drop`)
	if strings.Contains(raw, `iifname "eth2.30" ip saddr != 10.30.0.0/24 counter drop`) {
		t.Error("the DHCP segment still drops 0.0.0.0 before its exception")
	}
	sc := chain(t, nft, "seg_iot_spoof")
	order(t, sc, "seg_iot_spoof",
		`ip saddr 0.0.0.0 udp sport 68 udp dport 67 ip daddr { 10.30.0.1, 255.255.255.255 } counter return`,
		`log prefix "pi-fortress iot-spoof: " level info`,
		"counter drop")
	if strings.Contains(sc, "accept") {
		t.Errorf("the DHCP exception must return to raw prerouting, not accept past it:\n%s", sc)
	}

	gate := chain(t, nft, "resolver_gate")
	order(t, gate, "resolver_gate",
		`iifname "eth2.30" ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept`,
		`iifname "eth2.30" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.30.0.1 ip daddr != @resolved_iot_v4 limit rate`)

	in := chain(t, nft, "input")
	order(t, in, "input",
		`iifname "eth2.30" udp dport 53 accept`,
		`iifname "eth2.30" udp sport 68 udp dport 67 accept`,
		`iifname "eth2.30" counter drop`)

	for _, l := range strings.Split(nft, "\n") {
		if strings.Contains(l, "dport 67") && !strings.Contains(l, `"eth2.30"`) && !strings.Contains(l, "ip saddr 0.0.0.0") {
			t.Errorf("port 67 opened off the DHCP segment: %s", strings.TrimSpace(l))
		}
		if strings.Contains(l, `"eth0.79"`) && (strings.Contains(l, "dport 67") || strings.Contains(l, "spoof")) && strings.Contains(l, "jump") {
			t.Errorf("the desk, without DHCP, got the exception: %s", strings.TrimSpace(l))
		}
	}
	// 0.0.0.0 is input to the Pi only. forward still pins each source to
	// NET, and nothing there names port 67 or the empty source.
	fwd := chain(t, nft, "forward")
	if strings.Contains(fwd, "0.0.0.0") || strings.Contains(fwd, "dport 67") {
		t.Errorf("forward opens DHCP or the empty source:\n%s", fwd)
	}

	offNFT := off.Ruleset(labElements)
	for _, bad := range []string{"dport 67", "seg_iot_spoof", "255.255.255.255"} {
		if strings.Contains(offNFT, bad) {
			t.Errorf("DHCP off still renders %q", bad)
		}
	}
	if !strings.Contains(offNFT, `iifname "eth2.30" ip saddr != 10.30.0.0/24 counter drop`) {
		t.Error("DHCP off lost the plain source check")
	}
}

// BLOCK_DIRECT_IP=off has no gate to carve, so the gate accept is not
// rendered. The spoof exception and the input accept are still rendered.
func TestSegmentDHCPWithoutTheGate(t *testing.T) {
	c, err := segDHCP(t, "", nil, iotNet+"BLOCK_DIRECT_IP=off\nDHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n")
	if err != nil {
		t.Fatal(err)
	}
	nft := c.Ruleset(labElements)
	if strings.Contains(chain(t, nft, "resolver_gate"), "eth2.30") {
		t.Error("a segment without a gate got a gate rule")
	}
	for _, want := range []string{"jump seg_iot_spoof", `iifname "eth2.30" udp sport 68 udp dport 67 accept`} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q", want)
		}
	}
}
