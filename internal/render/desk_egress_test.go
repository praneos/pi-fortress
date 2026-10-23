package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deskRuleset(t *testing.T, deskEnv string, el Elements) string {
	t.Helper()
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", deskEnv)
	house := write(t, dir, "house.env", "HOUSE_IF=eth2\nHOUSE_ADMIN_IP=10.78.0.20\n")
	return load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house}).Ruleset(el)
}

const deskBase = "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\n"

func mustHave(t *testing.T, where, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("%s missing:\n%s", where, w)
		}
	}
}

// The ruleset treats a desk as possibly compromised: the DNS pin of the house,
// a gate on all ports, no local addresses and the strict port policy of the house.
func TestPlainSegmentIsStrictByDefault(t *testing.T) {
	nft := deskRuleset(t, deskBase, labElements)
	mustHave(t, "filter_prerouting", chain(t, nft, "filter_prerouting"),
		`iifname "eth3" meta l4proto { tcp, udp } th dport 53 accept`,
		`iifname "eth3" ip daddr @dns_bypass_v4 counter drop`,
		`iifname "eth3" udp dport 443 counter drop`,
		`iifname "eth3" tcp dport 853 counter drop`,
		`iifname "eth3" udp dport 853 counter drop`)
	mustHave(t, "resolver_gate", chain(t, nft, "resolver_gate"),
		`iifname "eth3" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 counter drop`,
		`iifname "eth3" icmp type echo-request ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 counter drop`)
	fwd := chain(t, nft, "forward")
	mustHave(t, "forward", fwd,
		`iifname "eth3" ip daddr @reserved_v4 counter drop`,
		`iifname "eth3" jump seg_desk_egress`)
	// The local drop and the port policy come before the uplink accept.
	// If not, they are rendered but never reached.
	local := strings.Index(fwd, `iifname "eth3" ip daddr @reserved_v4 counter drop`)
	jump := strings.Index(fwd, `iifname "eth3" jump seg_desk_egress`)
	up := strings.Index(fwd, `iifname "eth3" oifname "wlan0" accept`)
	if !(local >= 0 && local < jump && jump < up) {
		t.Fatalf("order: local %d, egress jump %d, uplink accept %d\n%s", local, jump, up, fwd)
	}
	eg := chain(t, nft, "seg_desk_egress")
	mustHave(t, "seg_desk_egress", eg,
		"tcp dport 80 return",
		"tcp dport { "+strings.Join(houseTLSPorts, ", ")+" } return",
		"tcp dport { "+houseSTARTTLSPorts+" } return",
		"udp dport 123 return",
		`log prefix "pi-fortress desk-port: "`,
		"counter drop")
}

func TestPlainSegmentEgressModesAndPorts(t *testing.T) {
	open := deskRuleset(t, deskBase+"EGRESS=open\n", labElements)
	if strings.Contains(open, "seg_desk_egress") {
		t.Fatal("EGRESS=open still renders a port policy")
	}
	audit := deskRuleset(t, deskBase+"EGRESS=audit\n", labElements)
	eg := chain(t, audit, "seg_desk_egress")
	if !strings.Contains(eg, `"pi-fortress desk-audit: "`) || strings.Contains(eg, "counter drop") {
		t.Fatalf("EGRESS=audit must log and pass:\n%s", eg)
	}
	ports := deskRuleset(t, deskBase+"ALLOW_PORTS=\"tcp:5000-5002 udp:3478\"\n", labElements)
	mustHave(t, "seg_desk_egress", chain(t, ports, "seg_desk_egress"),
		"tcp dport { 5000-5002 } return", "udp dport { 3478 } return")
}

// SSH_FROM opens SSH from one address into the desk, before all isolation
// drops. It never opens it from the uplink, and gives the desk nothing back.
func TestPlainSegmentSSHFromIsOneWay(t *testing.T) {
	nft := deskRuleset(t, deskBase+"SSH_FROM=10.78.0.20\n", labElements)
	fwd := chain(t, nft, "forward")
	rule := `iifname "eth2" oifname "eth3" ip saddr 10.78.0.20 tcp dport 22 ct state new counter accept`
	at := strings.Index(fwd, rule)
	if at < 0 {
		t.Fatalf("no SSH_FROM accept:\n%s", fwd)
	}
	for _, drop := range []string{`iifname "eth2" oifname "eth3" counter drop`, `iifname "eth3" oifname "eth2" counter drop`, `iifname "eth3" ip daddr @reserved_v4 counter drop`} {
		if d := strings.Index(fwd, drop); d < 0 || d < at {
			t.Errorf("%q must exist and come after the SSH_FROM accept", drop)
		}
	}
	if strings.Contains(fwd, `iifname "eth3" oifname "eth2" ip daddr 10.78.0.20`) || strings.Contains(fwd, `ip daddr 10.78.0.20 tcp`) {
		t.Fatalf("the desk got a way back to its SSH_FROM address:\n%s", fwd)
	}
	if !strings.Contains(nft, "ct state established,related accept") {
		t.Fatal("replies ride conntrack; the forward chain lost its established accept")
	}
}

func TestPlainSegmentGateExemptsSSHToAndHonoursBlockDirectIPOff(t *testing.T) {
	to := deskRuleset(t, deskBase+"SSH_TO=10.77.0.10-10.77.0.12\n", labElements)
	mustHave(t, "resolver_gate", chain(t, to, "resolver_gate"),
		`ip daddr != @resolved_desk_v4 ip daddr != 10.77.0.10-10.77.0.12 counter drop`)
	off := deskRuleset(t, deskBase+"BLOCK_DIRECT_IP=off\n", labElements)
	if strings.Contains(chain(t, off, "resolver_gate"), `iifname "eth3"`) {
		t.Fatal("BLOCK_DIRECT_IP=off still gates the desk")
	}
}

// git over SSH from a desk goes only where it can go from the agent: ssh_allow.ips.
func TestPlainSegmentSSHOutOnlyToSSHAllow(t *testing.T) {
	el := labElements
	el.SSHAllow = "elements = { 140.82.112.0/20 }"
	fwd := chain(t, deskRuleset(t, deskBase, el), "forward")
	accept := `iifname "eth3" tcp dport 22 ip daddr @ssh_allow_v4 ct state new counter accept`
	a, local, jump := strings.Index(fwd, accept), strings.Index(fwd, `iifname "eth3" ip daddr @reserved_v4 counter drop`), strings.Index(fwd, `iifname "eth3" jump seg_desk_egress`)
	if !(local >= 0 && local < a && a < jump) {
		t.Fatalf("ssh_allow accept must sit after the local drop and before the port policy (%d %d %d):\n%s", local, a, jump, fwd)
	}
	if strings.Contains(chain(t, deskRuleset(t, deskBase, labElements), "forward"), "ssh_allow_v4") {
		t.Fatal("no ssh_allow.ips, yet the desk references the set")
	}
}

func TestPlainSegmentNewKeysAreChecked(t *testing.T) {
	// SSH_FROM inside AGENT_NET would give the agents SSH into the desk.
	// Inside the NET of the desk itself, it is no hole at all.
	for _, bad := range []string{"EGRESS=closed", "SSH_FROM=10.78.0", "SSH_FROM=mac.lan", "ALLOW_PORTS=tcp:0", "ALLOW_PORTS=sctp:5", "SSH_FROM=10.77.0.10", "SSH_FROM=10.79.0.2"} {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		os.Mkdir(segs, 0755)
		write(t, segs, "desk.env", deskBase+bad+"\n")
		if _, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// All that is not the desk renders exactly as before the desk hardening.
// This change must not move the rules of the agent and the house. The
// baseline is the output of main without the lines of the desk. The body
// of the new egress chain is the only desk text without the name.
func TestPlainSegmentHardeningLeavesAgentAndHouseAlone(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "plain_segment_others.nft"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	skip := false
	for _, l := range strings.Split(deskRuleset(t, deskBase, labElements), "\n") {
		switch {
		case strings.HasPrefix(l, "  chain seg_desk_egress {"):
			// The chain's own leading blank line goes with it.
			if n := len(kept); n > 0 && kept[n-1] == "" {
				kept = kept[:n-1]
			}
			skip = true
			continue
		case skip && l == "  }":
			skip = false
			continue
		case skip, strings.Contains(l, "eth3"), strings.Contains(l, "desk"):
			continue
		}
		kept = append(kept, l)
	}
	got := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
	if got != string(want) {
		t.Fatalf("non-desk rules changed; diff against testdata/plain_segment_others.nft:\n%s", got)
	}
}
