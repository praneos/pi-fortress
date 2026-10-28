package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The NTP that reaches the gateway has a meter for each source, as DNS has.
// The house and each plain segment have it, before the conntrack accept of
// input: a UDP flow that is established would skip a meter that is behind
// that accept. The agent has no NTP, so it gets no meter.
func TestNTPInputHasSourceMeter(t *testing.T) {
	nft := ntpPassRendered(t, "strict", "NTP=pass\n", ntpPassElements)
	in := chain(t, nft, "input")
	for _, m := range []struct{ iface, name, ip string }{
		{"eth2", "house", "10.78.0.1"},
		{"eth3", "desk", "10.79.0.1"},
		{"eth4", "guest", "10.80.0.1"},
	} {
		meter := `iifname "` + m.iface + `" udp dport 123 meter ` + m.name + `_ntpflood { ip saddr limit rate over 20/second burst 40 packets } counter drop`
		if n := strings.Count(in, "\n    "+meter+"\n"); n != 1 {
			t.Errorf("%s: %d NTP meters in input, want 1:\n%s", m.iface, n, in)
			continue
		}
		order(t, in, "input", meter, "ct state established,related accept",
			`iifname "`+m.iface+`" ip daddr `+m.ip+` udp dport 123 accept`)
	}
	for _, l := range strings.Split(in, "\n") {
		if strings.Contains(l, `iifname "eth0"`) && strings.Contains(l, "123") {
			t.Errorf("the agent has an NTP rule in input: %s", strings.TrimSpace(l))
		}
	}
}

// The meter follows the accept: no house interface, no house meter. A
// segment name with a dash gives a valid meter identifier.
func TestNTPInputMeterFollowsTheNet(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "lab-desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	nft := load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"}).Ruleset(labElements)
	in := chain(t, nft, "input")
	mustHave(t, "input", in,
		`iifname "eth3" udp dport 123 meter lab_desk_ntpflood { ip saddr limit rate over 20/second burst 40 packets } counter drop`)
	if strings.Contains(in, "house_ntpflood") {
		t.Errorf("a ruleset without a house has a house NTP meter:\n%s", in)
	}
}
