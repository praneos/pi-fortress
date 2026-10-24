package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// connBox is a house and one plain segment, so every class renders.
func connBox(t *testing.T, limits map[string]string) Options {
	t.Helper()
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\n")
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", "IF=eth3\nNET=10.80.0.0/30\nIP=10.80.0.1\nADMIN=yes\n")
	net := lab
	net.ConnLimits = limits
	return Options{Net: net, HouseEnv: house, SegmentsDir: segs}
}

func TestConnLimitsDefaults(t *testing.T) {
	nft := load(t, connBox(t, nil)).Ruleset(labElements)
	in := chain(t, nft, "input")
	// The count of the agent is after the conntrack accept, so an established
	// flow never reaches it. It is before the port accepts that it limits.
	order(t, in, "input",
		`ct state established,related accept`,
		`iifname "eth0" meta l4proto tcp ct state new meter agent_newconn { ip saddr limit rate over 50/second burst 200 packets } jump agent_connlimit`,
		`iifname "eth0" meta l4proto tcp ct state new add @agent_conn_v4 { ip saddr ct count over 128 } jump agent_connlimit`,
		`iifname "eth0" meta l4proto tcp ct state new ct count over 4096 jump agent_connlimit`,
		// The total new-flow rate of the segment limits its TIME_WAIT entries:
		// one meter for all addresses that a root agent aliases.
		`iifname "eth0" meta l4proto tcp ct state new limit rate over 300/second burst 600 packets jump agent_connlimit`,
		`iifname "eth0" tcp dport 80 accept`,
		`iifname "eth0" tcp dport 8080 accept`)
	fwd := chain(t, nft, "forward")
	// Forwarded budgets go first, before the SNI queue. The accept verdict of
	// that queue would leave the chain before a later count saw the flow.
	order(t, fwd, "forward",
		`iifname "eth1" ct state new meter house_newconn { ip saddr limit rate over 100/second burst 500 packets } jump house_connlimit`,
		`iifname "eth1" ct state new add @house_conn_v4 { ip saddr ct count over 1024 } jump house_connlimit`,
		`iifname "eth1" ct state new ct count over 32768 jump house_connlimit`,
		// The total new TCP rate of the house limits its TIME_WAIT entries:
		// one meter for all addresses on the segment.
		`iifname "eth1" ct state new meta l4proto tcp limit rate over 1000/second burst 5000 packets jump house_connlimit`,
		`iifname "eth3" ct state new meter seg_desk_newconn { ip saddr limit rate over 50/second burst 200 packets } jump seg_desk_connlimit`,
		`iifname "eth3" ct state new add @seg_desk_conn_v4 { ip saddr ct count over 128 } jump seg_desk_connlimit`,
		`iifname "eth3" ct state new ct count over 4096 jump seg_desk_connlimit`,
		// The total new TCP rate of each plain segment, SEG_NEW_TOTAL, is
		// last among its budgets, as for the house.
		`iifname "eth3" ct state new meta l4proto tcp limit rate over 300/second burst 600 packets jump seg_desk_connlimit`,
		`queue num`,
		`ct state established,related accept`)
	for _, set := range []string{"agent_conn_v4", "house_conn_v4", "seg_desk_conn_v4"} {
		if !strings.Contains(nft, "\n  set "+set+" {\n    type ipv4_addr\n    size 65535\n    flags dynamic\n  }") {
			t.Errorf("set %s not declared", set)
		}
	}
	for name, seg := range map[string]string{"agent_connlimit": "agent", "house_connlimit": "house", "seg_desk_connlimit": "desk"} {
		body := chain(t, nft, name)
		order(t, body, name, `log prefix "pi-fortress `+seg+`-connlimit: "`, `meta l4proto tcp counter reject with tcp reset`, `counter drop`)
	}
	// Per-source echo and SSH meters, each ahead of the accept it guards.
	order(t, in, "input", `iifname "eth0" icmp type echo-request meter agent_ping`, `iifname "eth0" icmp type echo-request accept`)
	order(t, in, "input", `iifname "eth1" icmp type echo-request meter house_ping`, `iifname "eth1" icmp type echo-request accept`)
	order(t, in, "input", `iifname "eth3" tcp dport 22 ct state new meter seg_desk_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop`, `iifname "eth3" tcp dport 22 ct state new accept`)
	order(t, in, "input", `iifname "eth3" icmp type echo-request meter seg_desk_ping`, `iifname "eth3" icmp type echo-request accept`)
	order(t, in, "input", `iifname "wlan0" tcp dport 22 ct state new meter wan_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop`, `iifname "wlan0" tcp dport 22 ct state new accept`)
	order(t, in, "input", `iifname "wlan0" icmp type echo-request meter wan_ping`, `iifname "wlan0" icmp type echo-request accept`)
	if strings.Contains(in, `tcp dport 22 ct state new limit rate`) && !strings.Contains(in, `ip saddr 10.78.0.5 tcp dport 22`) {
		t.Error("a shared SSH budget is still rendered")
	}
}

func TestConnLimitsOverridesAndZero(t *testing.T) {
	nft := load(t, connBox(t, map[string]string{
		"AGENT_CONN_PER_IP": "192", "AGENT_NEW_PER_IP": "20/80", "AGENT_CONN_TOTAL": "0",
		"HOUSE_CONN_PER_IP": "0", "HOUSE_NEW_PER_IP": "0", "HOUSE_CONN_TOTAL": "0", "HOUSE_NEW_TOTAL": "0",
		"SEG_NEW_PER_IP": "0",
	})).Ruleset(labElements)
	for _, want := range []string{
		`add @agent_conn_v4 { ip saddr ct count over 192 } jump agent_connlimit`,
		`meter agent_newconn { ip saddr limit rate over 20/second burst 80 packets } jump agent_connlimit`,
		`iifname "eth3" ct state new add @seg_desk_conn_v4 { ip saddr ct count over 128 }`,
		`iifname "eth3" ct state new ct count over 4096`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("override not rendered: %s", want)
		}
	}
	for _, gone := range []string{
		`iifname "eth0" meta l4proto tcp ct state new ct count over`,
		`house_newconn`, `house_conn_v4`, `house_connlimit`, `ct count over 32768`,
		`limit rate over 1000/second`,
		`seg_desk_newconn`,
	} {
		if strings.Contains(nft, gone) {
			t.Errorf("0 still renders %s", gone)
		}
	}
}

// HOUSE_NEW_TOTAL alone overrides the segment-wide new-flow rate of the
// house. 0 removes only that rule: the per-device limits stay.
func TestHouseNewTotal(t *testing.T) {
	nft := load(t, connBox(t, map[string]string{"HOUSE_NEW_TOTAL": "2000/8000"})).Ruleset(labElements)
	want := `iifname "eth1" ct state new meta l4proto tcp limit rate over 2000/second burst 8000 packets jump house_connlimit`
	if strings.Count(nft, want) != 1 {
		t.Errorf("want exactly one %s", want)
	}
	if strings.Contains(nft, `iifname "eth3" ct state new meta l4proto tcp limit rate over 2000/second`) {
		t.Error("a plain segment got the house's total")
	}
	nft = load(t, connBox(t, map[string]string{"HOUSE_NEW_TOTAL": "0"})).Ruleset(labElements)
	if strings.Contains(nft, `iifname "eth1" ct state new meta l4proto tcp limit rate`) {
		t.Error("HOUSE_NEW_TOTAL=0 still renders the house total")
	}
	if !strings.Contains(nft, `iifname "eth1" ct state new ct count over 32768 jump house_connlimit`) {
		t.Error("HOUSE_NEW_TOTAL=0 took the house's other limits with it")
	}
	// A per-device rate above the segment's can never be reached.
	if _, err := Load(connBox(t, map[string]string{"HOUSE_NEW_PER_IP": "500/1000", "HOUSE_NEW_TOTAL": "200/400"})); err == nil || !strings.Contains(err.Error(), "HOUSE_NEW_TOTAL") {
		t.Errorf("per-device rate over the total: %v", err)
	}
}

// SEG_NEW_TOTAL is the segment-wide new TCP rate of each plain segment: one
// rule for each segment, each on its own interface and connlimit chain. The
// own NEW_TOTAL of a segment overrides it. 0 (in net.env or the file)
// removes only that rule.
func TestSegNewTotal(t *testing.T) {
	o := connBox(t, map[string]string{"SEG_NEW_TOTAL": "300/1500"})
	write(t, o.SegmentsDir, "guest.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\nNEW_TOTAL=150/600\n")
	write(t, o.SegmentsDir, "lab-b.env", "IF=eth5\nNET=10.82.0.0/24\nIP=10.82.0.1\nNEW_TOTAL=0\n")
	nft := load(t, o).Ruleset(labElements)
	fwd := chain(t, nft, "forward")
	for _, want := range []string{
		`iifname "eth3" ct state new meta l4proto tcp limit rate over 300/second burst 1500 packets jump seg_desk_connlimit`,
		`iifname "eth4" ct state new meta l4proto tcp limit rate over 150/second burst 600 packets jump seg_guest_connlimit`,
	} {
		if strings.Count(fwd, want) != 1 {
			t.Errorf("want exactly one %s", want)
		}
	}
	order(t, fwd, "forward",
		`iifname "eth4" ct state new ct count over 4096 jump seg_guest_connlimit`,
		`iifname "eth4" ct state new meta l4proto tcp limit rate over 150/second`)
	if strings.Contains(nft, `iifname "eth5" ct state new meta l4proto tcp limit rate`) {
		t.Error("NEW_TOTAL=0 in the segment's file still renders its total")
	}
	if !strings.Contains(nft, `iifname "eth5" ct state new ct count over 4096 jump seg_lab_b_connlimit`) {
		t.Error("NEW_TOTAL=0 took the segment's other limits with it")
	}
	nft = load(t, connBox(t, map[string]string{"SEG_NEW_TOTAL": "0"})).Ruleset(labElements)
	if strings.Contains(nft, `iifname "eth3" ct state new meta l4proto tcp limit rate`) {
		t.Error("SEG_NEW_TOTAL=0 still renders the desk total")
	}
	if !strings.Contains(nft, `iifname "eth1" ct state new meta l4proto tcp limit rate over 1000/second`) {
		t.Error("SEG_NEW_TOTAL=0 took the house's total with it")
	}
	// A per-device rate above the segment's can never be reached.
	if _, err := Load(connBox(t, map[string]string{"SEG_NEW_PER_IP": "500/1000", "SEG_NEW_TOTAL": "200/400"})); err == nil || !strings.Contains(err.Error(), "SEG_NEW_TOTAL") {
		t.Errorf("per-device rate over the total: %v", err)
	}
}

func TestConnLimitsRefused(t *testing.T) {
	for key, val := range map[string]string{
		"AGENT_CONN_PER_IP": "8",       // under the floor
		"HOUSE_CONN_PER_IP": "0128",    // leading zero
		"SEG_CONN_TOTAL":    "999999",  // past the conntrack table
		"AGENT_NEW_PER_IP":  "50",      // no burst
		"HOUSE_NEW_PER_IP":  "100/50",  // burst under rate
		"SEG_NEW_PER_IP":    "-5/10",   // sign
		"AGENT_CONN_TOTAL":  "4096 ",   // space
		"HOUSE_CONN_TOTAL":  "lots",    // not a number
		"SEG_CONN_PER_IP":   "1024/10", // wrong shape
		"HOUSE_NEW_TOTAL":   "50/100",  // under the segment floor
		"SEG_NEW_TOTAL":     "99/200",  // under the segment floor
	} {
		if err := CheckConnLimit(key, val); err == nil {
			t.Errorf("CheckConnLimit(%s, %q) accepted", key, val)
		}
		if _, err := Load(connBox(t, map[string]string{key: val})); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("Load with %s=%q: %v", key, val, err)
		}
	}
	if CheckConnLimit("HOUSE_NEW_TOTAL", "1000") == nil {
		t.Error("HOUSE_NEW_TOTAL without a burst accepted")
	}
	if CheckConnLimit("SEG_NEW_TOTAL", "200") == nil {
		t.Error("SEG_NEW_TOTAL without a burst accepted")
	}
	for key, val := range map[string]string{"AGENT_CONN_PER_IP": "0", "AGENT_NEW_PER_IP": "50/200", "SEG_CONN_TOTAL": "", "HOUSE_CONN_TOTAL": "131072", "HOUSE_NEW_TOTAL": "1000/5000", "SEG_NEW_TOTAL": "200/1000"} {
		if err := CheckConnLimit(key, val); err != nil {
			t.Errorf("CheckConnLimit(%s, %q): %v", key, val, err)
		}
	}
	// A device cap above its segment's total can never be reached.
	if _, err := Load(connBox(t, map[string]string{"AGENT_CONN_PER_IP": "5000"})); err == nil || !strings.Contains(err.Error(), "AGENT_CONN_TOTAL") {
		t.Errorf("per-IP over the total: %v", err)
	}
	if len(ConnLimitKeys) != 11 || ConnLimitKeys[6] != "HOUSE_NEW_TOTAL" || ConnLimitKeys[10] != "SEG_NEW_TOTAL" {
		t.Errorf("ConnLimitKeys: %v", ConnLimitKeys)
	}
}

// TestSegmentConnLimits: the own CONN_PER_IP, NEW_PER_IP and CONN_TOTAL of
// a plain segment override the SEG_ values of net.env, one key at a time.
// A segment that names none keeps the SEG_ budget. A bad value, or a
// per-device cap above the total, gets a refusal that names the file of the segment.
func TestSegmentConnLimits(t *testing.T) {
	o := connBox(t, map[string]string{"SEG_CONN_TOTAL": "4096"})
	write(t, o.SegmentsDir, "guest.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\nCONN_PER_IP=64\nNEW_PER_IP=0\n")
	write(t, o.SegmentsDir, "lab-b.env", "IF=eth5\nNET=10.82.0.0/24\nIP=10.82.0.1\nCONN_TOTAL=0\nNEW_PER_IP=20/40\nCONN_PER_IP=\n")
	nft := load(t, o).Ruleset(labElements)
	for _, want := range []string{
		// desk: nothing of its own, net.env's SEG_ values.
		`iifname "eth3" ct state new meter seg_desk_newconn { ip saddr limit rate over 50/second burst 200 packets }`,
		`iifname "eth3" ct state new add @seg_desk_conn_v4 { ip saddr ct count over 128 }`,
		`iifname "eth3" ct state new ct count over 4096 jump seg_desk_connlimit`,
		// guest: its own per-device cap, meter off, SEG_CONN_TOTAL kept.
		`iifname "eth4" ct state new add @seg_guest_conn_v4 { ip saddr ct count over 64 } jump seg_guest_connlimit`,
		`iifname "eth4" ct state new ct count over 4096 jump seg_guest_connlimit`,
		// lab-b: its own meter, no segment total, the default per device
		// (its empty CONN_PER_IP is the SEG_ value, not off).
		`iifname "eth5" ct state new meter seg_lab_b_newconn { ip saddr limit rate over 20/second burst 40 packets }`,
		`iifname "eth5" ct state new add @seg_lab_b_conn_v4 { ip saddr ct count over 128 }`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("not rendered: %s", want)
		}
	}
	for _, gone := range []string{`seg_guest_newconn`, `iifname "eth5" ct state new ct count over`} {
		if strings.Contains(nft, gone) {
			t.Errorf("rendered though the segment turned it off: %s", gone)
		}
	}

	for body, want := range map[string]string{
		"CONN_PER_IP=8\n":                         "CONN_PER_IP='8'",
		"NEW_PER_IP=50\n":                         "NEW_PER_IP='50'",
		"CONN_TOTAL=0128\n":                       "CONN_TOTAL='0128'",
		"CONN_PER_IP=5000\n":                      "CONN_PER_IP=5000 is more than CONN_TOTAL=4096",
		"CONN_TOTAL=100\n":                        "CONN_PER_IP=128 is more than CONN_TOTAL=100",
		"SEG_CONN_PER_IP=100\n":                   "unknown key 'SEG_CONN_PER_IP'",
		"NEW_TOTAL=50/100\n":                      "NEW_TOTAL='50/100'",
		"NEW_TOTAL=200\n":                         "NEW_TOTAL='200'",
		"NEW_PER_IP=400/800\n":                    "NEW_PER_IP=400/800 is more than NEW_TOTAL=300/600",
		"NEW_TOTAL=150/600\nNEW_PER_IP=160/600\n": "NEW_PER_IP=160/600 is more than NEW_TOTAL=150/600",
	} {
		o := connBox(t, map[string]string{"SEG_CONN_TOTAL": "4096"})
		write(t, o.SegmentsDir, "guest.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\n"+body)
		_, err := Load(o)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "guest.env") {
			t.Errorf("%q: %v", body, err)
		}
	}
}
