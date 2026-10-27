package render

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var reEgressFP = regexp.MustCompile(`(?m)^HOUSE_EGRESS_FP='([0-9a-f]*)'\nSEG_EGRESS_FP=\(((?:'[0-9a-f]{16}' ?)*)\)\n$`)

// egressFPs loads a house and the desk and guest segments, and gives the
// fingerprints that apply.env carries: the house, then one per segment.
func egressFPs(t *testing.T, house, desk string, e Elements) (string, []string) {
	t.Helper()
	segs := segGoldenDir(t)
	if desk != "" {
		write(t, segs, "desk.env", deskEnvLines+desk)
	}
	o := Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs}
	if house != "" {
		o.HouseEnv = write(t, filepath.Dir(segs), "house.env", "HOUSE_IF=eth1\n"+house)
	}
	env := load(t, o).EgressEnv(e)
	m := reEgressFP.FindStringSubmatch(env)
	if m == nil {
		t.Fatalf("apply.env egress lines:\n%s", env)
	}
	return m[1], strings.Fields(strings.ReplaceAll(m[2], "'", ""))
}

func TestEgressFPNoHouse(t *testing.T) {
	house, segs := egressFPs(t, "", "", labElements)
	if house != "" || len(segs) != 2 {
		t.Fatalf("house %q, segments %q", house, segs)
	}
}

// A line that writes only the default is not a change of the policy.
func TestEgressFPDefaultsAreNoChange(t *testing.T) {
	h0, s0 := egressFPs(t, "WG_IF=wg0\n", "", labElements)
	h1, s1 := egressFPs(t, "WG_IF=wg0\nHOUSE_EGRESS=strict\nHOUSE_ALLOW_WIFI_CALLING=off\nHOUSE_ALLOW_CALL_UDP=off\nHOUSE_ALLOW_WHATSAPP=on\n"+
		"HOUSE_BLOCK_DIRECT_IP=on\nHOUSE_BLOCK_HTTP=off\nHOUSE_BLOCK_VPN=on\nHOUSE_PRIVATE_DNS=off\n",
		"EGRESS=strict\nBLOCK_DIRECT_IP=on\nINSPECT=off\nNTP=redirect\n", labElements)
	if h0 == "" || h0 != h1 || strings.Join(s0, " ") != strings.Join(s1, " ") {
		t.Fatalf("explicit defaults changed a fingerprint: %s %v / %s %v", h0, s0, h1, s1)
	}
}

// Each egress input of the house changes the house fingerprint and no
// other. A key that is not egress policy changes nothing.
func TestEgressFPHouse(t *testing.T) {
	h0, s0 := egressFPs(t, "WG_IF=wg0\n", "", labElements)
	for _, line := range []string{"HOUSE_EGRESS=audit\n", "HOUSE_EGRESS=open\n", "HOUSE_ALLOW_WIFI_CALLING=on\n",
		"HOUSE_ALLOW_CALL_UDP=on\n", "HOUSE_ALLOW_WHATSAPP=off\n", "HOUSE_ALLOW_PORTS='tcp:27015'\n", "HOUSE_ALLOW_PORTS='udp:3000-3010'\n",
		"HOUSE_BLOCK_DIRECT_IP=off\n", "HOUSE_BLOCK_HTTP=on\n", "HOUSE_BLOCK_VPN=off\n", "HOUSE_PRIVATE_DNS=on\n"} {
		h, s := egressFPs(t, "WG_IF=wg0\n"+line, "", labElements)
		if h == h0 {
			t.Errorf("%s did not change the house fingerprint", strings.TrimSpace(line))
		}
		if strings.Join(s, " ") != strings.Join(s0, " ") {
			t.Errorf("%s changed a segment fingerprint", strings.TrimSpace(line))
		}
	}
	if h, _ := egressFPs(t, "WG_IF=wg0\nHOUSE_ADMIN_IP=10.78.0.20\n", "", labElements); h != h0 {
		t.Error("HOUSE_ADMIN_IP changed the house fingerprint")
	}
}

// EGRESS, ALLOW_PORTS, BLOCK_DIRECT_IP, INSPECT and NTP change only the
// fingerprint of their segment.
// ssh_allow.ips opens SSH from each plain segment, so it changes all of them.
func TestEgressFPSegment(t *testing.T) {
	h0, s0 := egressFPs(t, "WG_IF=wg0\n", "", labElements)
	for _, line := range []string{"EGRESS=audit\n", "EGRESS=open\n", "ALLOW_PORTS='tcp:27015'\n", "ALLOW_PORTS='udp:3000-3010'\n", "BLOCK_DIRECT_IP=off\n", "INSPECT=on\n", "NTP=pass\n"} {
		h, s := egressFPs(t, "WG_IF=wg0\n", line, labElements)
		if h != h0 || s[0] == s0[0] || s[1] != s0[1] {
			t.Errorf("%s: house %v, desk %v, guest %v changed; want only the desk", strings.TrimSpace(line), h != h0, s[0] != s0[0], s[1] != s0[1])
		}
	}
	if _, s := egressFPs(t, "WG_IF=wg0\n", "DNS_TYPES='SRV'\n", labElements); s[0] != s0[0] {
		t.Error("DNS_TYPES changed the desk fingerprint")
	}
	e := labElements
	e.SSHAllow = "elements = { 192.0.2.1 }"
	h, s := egressFPs(t, "WG_IF=wg0\n", "", e)
	if h != h0 || s[0] == s0[0] || s[1] == s0[1] {
		t.Errorf("ssh_allow: house %v, desk %v, guest %v changed; want both segments", h != h0, s[0] != s0[0], s[1] != s0[1])
	}
}

// ntp_pass.ips is part of the policy of an NTP=pass segment only. A change
// of it cuts the flows of that segment. Each other segment keeps its
// fingerprint.
func TestEgressFPNTPPassList(t *testing.T) {
	other := labElements
	other.NTPPass = "elements = { 216.239.35.4 }"
	_, def0 := egressFPs(t, "", "", labElements)
	_, def1 := egressFPs(t, "", "", other)
	if strings.Join(def0, " ") != strings.Join(def1, " ") {
		t.Error("ntp_pass.ips changed a fingerprint without an NTP=pass segment")
	}
	_, p0 := egressFPs(t, "", "NTP=pass\n", labElements)
	_, p1 := egressFPs(t, "", "NTP=pass\n", other)
	if p0[0] == p1[0] || p0[1] != p1[1] {
		t.Errorf("ntp_pass.ips: desk changed %v, guest changed %v; want only the desk", p0[0] != p1[0], p0[1] != p1[1])
	}
}
