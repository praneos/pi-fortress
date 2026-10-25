package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func segDir(t *testing.T, files map[string]string) string {
	t.Helper()
	segs := filepath.Join(t.TempDir(), "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		write(t, segs, name, body)
	}
	return segs
}

// A segment with the name of the house shared resolved_house_v4, the DNS
// meters of the house and dns-house.jsonl. Thus a name that the desk
// resolved opened the gate of the house. The agent, the Pi and the broker own names the same way.
func TestReservedSegmentNamesAreRefused(t *testing.T) {
	for _, name := range []string{"house", "agent", "pi", "broker"} {
		segs := segDir(t, map[string]string{name + ".env": deskBase})
		_, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("segment %q: %v", name, err)
		}
	}
	segs := segDir(t, map[string]string{"housemate.env": deskBase})
	load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
}

// a-b and a_b are two files and one set of nft identifiers.
func TestSegmentNamesThatCollideInNftAreRefused(t *testing.T) {
	segs := segDir(t, map[string]string{
		"lab-desk.env": deskBase,
		"lab_desk.env": "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n",
	})
	_, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
	if err == nil || !strings.Contains(err.Error(), "lab-desk") || !strings.Contains(err.Error(), "lab_desk") {
		t.Fatalf("lab-desk and lab_desk: %v", err)
	}
	segs = segDir(t, map[string]string{
		"lab-desk.env":  deskBase,
		"lab-guest.env": "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n",
	})
	load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
}

// nft reads a leading zero as octal: tcp:0443 opened port 291.
func TestParsePortsIsStrictAndCanonical(t *testing.T) {
	tcp, udp, err := ParsePorts("tcp:443 udp:27000-27010 tcp:5000-5002")
	if err != nil || tcp != "443, 5000-5002" || udp != "27000-27010" {
		t.Fatalf("ParsePorts: %q %q %v", tcp, udp, err)
	}
	for _, bad := range []string{"tcp:0443", "tcp:+443", "udp:27000-027010", "tcp:0", "tcp:65536", "tcp:-5", "tcp: 443", "tcp:443-", "tcp:500-400", "tcp:0x1bb"} {
		if tcp, udp, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) accepted: %q %q", bad, tcp, udp)
		}
	}
	segs := segDir(t, map[string]string{"desk.env": deskBase + "ALLOW_PORTS=tcp:0443\n"})
	if _, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"}); err == nil {
		t.Error("ALLOW_PORTS=tcp:0443 accepted")
	}
	house := write(t, t.TempDir(), "house.env", "HOUSE_IF=eth1\nHOUSE_ALLOW_PORTS=\"udp:027015\"\n")
	if _, err := Load(Options{Net: lab, SegmentsDir: "/nonexistent", HouseEnv: house}); err == nil {
		t.Error("HOUSE_ALLOW_PORTS=udp:027015 accepted")
	}
}

// Under EGRESS=open or audit, nothing behind the gate stops a protocol that
// is not TCP, UDP or ping. Thus the gate covers them. GRE, ESP or SCTP to
// an address that the desk never resolved is dropped and logged as directip.
func TestOpenEgressGatesEveryProtocol(t *testing.T) {
	miss := `ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4`
	for _, egress := range []string{"open", "audit", "strict"} {
		nft := deskRuleset(t, deskBase+"EGRESS="+egress+"\n", labElements)
		gate := chain(t, nft, "resolver_gate")
		order(t, gate, "resolver_gate",
			`iifname "eth3" meta l4proto { tcp, udp } th dport != 53 `+miss+` counter drop`,
			`iifname "eth3" icmp type echo-request `+miss+` counter drop`,
			`iifname "eth3" meta l4proto != { tcp, udp, icmp } `+miss+` limit rate 10/second burst 20 packets log prefix "pi-fortress desk-directip: " level info`,
			`iifname "eth3" meta l4proto != { tcp, udp, icmp } `+miss+` counter drop`,
			`iifname "eth3" icmp type != echo-request `+miss+` limit rate 10/second burst 20 packets log prefix "pi-fortress desk-directip: " level info`,
			`iifname "eth3" icmp type != echo-request `+miss+` counter drop`)
	}
	off := deskRuleset(t, deskBase+"EGRESS=open\nBLOCK_DIRECT_IP=off\n", labElements)
	if strings.Contains(chain(t, off, "resolver_gate"), `iifname "eth3"`) {
		t.Fatal("BLOCK_DIRECT_IP=off still gates the desk")
	}
}

// A VLAN child of the uplink gives all other devices on the wire of the
// uplink a tagged way into the segment.
func TestVLANOfTheUplinkIsRefused(t *testing.T) {
	segs := segDir(t, map[string]string{"desk.env": "IF=wlan0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n"})
	_, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
	if err == nil || !strings.Contains(err.Error(), "WAN_IF") {
		t.Errorf("segment on wlan0.79: %v", err)
	}
	_, err = Load(Options{Net: lab, SegmentsDir: "/nonexistent", HouseEnv: "/nonexistent/house.env", IntIF: "wlan0.20"})
	if err == nil || !strings.Contains(err.Error(), "WAN_IF") {
		t.Errorf("INT_IF=wlan0.20: %v", err)
	}
	house := write(t, t.TempDir(), "house.env", "HOUSE_IF=eth9.30\n")
	_, err = Load(Options{Net: lab, SegmentsDir: "/nonexistent", HouseEnv: house, WanIF: "eth9"})
	if err == nil || !strings.Contains(err.Error(), "WAN_IF") {
		t.Errorf("HOUSE_IF=eth9.30 on WAN_IF=eth9: %v", err)
	}
	segs = segDir(t, map[string]string{"desk.env": "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n"})
	load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env", IntIF: "eth0.20"})
}

// SSH_FROM arrives only on the house or on a different plain segment. Each
// of these has a source check. It never arrives on the tunnel, which has none.
func TestSSHFromIsAnInterfaceAllowList(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth2\nWG_IF=wg0\n")
	segs := segDir(t, map[string]string{
		"desk.env":  deskBase + "SSH_FROM=10.78.0.20\n",
		"guest.env": "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n",
	})
	fwd := chain(t, load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house}).Ruleset(labElements), "forward")
	rule := `iifname { "eth2", "eth4" } oifname "eth3" ip saddr 10.78.0.20 tcp dport 22 ct state new counter accept`
	if !strings.Contains(fwd, rule) {
		t.Fatalf("missing %s:\n%s", rule, fwd)
	}
	for _, ln := range strings.Split(fwd, "\n") {
		if strings.Contains(ln, "10.78.0.20 tcp dport 22") && (strings.Contains(ln, "!=") || strings.Contains(ln, "wg0") || strings.Contains(ln, "wlan0") || strings.Contains(ln, `"eth0"`)) {
			t.Errorf("SSH_FROM reachable from the tunnel, the uplink or the agents: %s", ln)
		}
	}
	// There is no place for it to come from: Load refuses it
	// (TestSSHFromMustBeInsideTheHouseOrASegment).
	segs = segDir(t, map[string]string{"desk.env": deskBase + "SSH_FROM=10.78.0.20\n"})
	if _, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"}); err == nil {
		t.Fatal("SSH_FROM accepted with no house and no other segment")
	}
}

// The accept of the SNI queue ends forward. Thus the WireGuard kill switch
// must come before it, for each state, with the SNI bits masked out of the
// bypass compare. Without a tunnel, there is no kill switch to move.
func TestHouseKillSwitchPrecedesTheSNIQueue(t *testing.T) {
	dir := t.TempDir()
	wg := load(t, Options{Net: lab, HouseEnv: write(t, dir, "wg.env", "HOUSE_IF=eth1\nWG_IF=wg0\n"), SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	fwd := chain(t, wg, "forward")
	order(t, fwd, "forward",
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 counter drop`,
		`counter queue num 1`,
		`ct state established,related accept`,
		`iifname "eth1" oifname "wlan0" meta mark 0x1 counter accept`,
		`iifname "eth1" oifname "wg0" accept`)
	for _, ln := range strings.Split(fwd, "\n") {
		if strings.Contains(ln, "0xff0fffff != 0x1") && (strings.Contains(ln, "ct state") || strings.Contains(ln, "wg0")) {
			t.Errorf("kill switch is scoped to a state or touches the tunnel: %s", ln)
		}
	}
	plain := load(t, Options{Net: lab, HouseEnv: write(t, dir, "plain.env", "HOUSE_IF=eth1\n"), SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	if strings.Contains(plain, "house-killswitch") {
		t.Fatalf("kill switch without WG_IF:\n%s", chain(t, plain, "forward"))
	}
}
