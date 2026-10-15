package render

import (
	"strconv"
	"strings"
	"testing"
)

// TestPlainSegmentDefaultsAreTheAgents: a plain segment with no own budget
// and no SEG_ key in net.env gets the numbers of the agent segment. This
// includes the per-device and segment-wide new-flow rates. They are still
// counted in forward on all protocols. An agent that escaped to a desk
// host must not find a bigger budget there than in the VM that it left.
func TestPlainSegmentDefaultsAreTheAgents(t *testing.T) {
	a, s := connDefaults[connAgent], connDefaults[connSeg]
	if s.PerIP != a.PerIP || s.Rate != a.Rate || s.Burst != a.Burst || s.Total != a.Total {
		t.Errorf("plain defaults %+v, agent %+v", s, a)
	}
	if got := strconv.Itoa(s.NewTotal) + "/second burst " + strconv.Itoa(s.NewBurst) + " packets"; got != agentNewTotal {
		t.Errorf("plain NEW_TOTAL renders %q, agent's is %q", got, agentNewTotal)
	}

	nft := load(t, connBox(t, nil)).Ruleset(labElements)
	fwd := chain(t, nft, "forward")
	order(t, fwd, "forward",
		`iifname "eth3" ct state new meter seg_desk_newconn { ip saddr limit rate over 50/second burst 200 packets } jump seg_desk_connlimit`,
		`iifname "eth3" ct state new add @seg_desk_conn_v4 { ip saddr ct count over 128 } jump seg_desk_connlimit`,
		`iifname "eth3" ct state new ct count over 4096 jump seg_desk_connlimit`,
		`iifname "eth3" ct state new meta l4proto tcp limit rate over 300/second burst 600 packets jump seg_desk_connlimit`,
		`ct state established,related accept`)
	if strings.Contains(fwd, `iifname "eth3" meta l4proto tcp ct state new meter seg_desk_newconn`) {
		t.Error("plain segment's per-device meter narrowed to TCP; it counts every protocol")
	}
}

// TestSegKeysAcceptTheAgentsNumbers: the floors still let an operator
// write the numbers of the agent into the SEG_ keys and the file of a
// segment. A per-device rate above the new 300/600 segment total is refused.
func TestSegKeysAcceptTheAgentsNumbers(t *testing.T) {
	for key, val := range map[string]string{"SEG_CONN_PER_IP": "128", "SEG_NEW_PER_IP": "50/200", "SEG_CONN_TOTAL": "4096", "SEG_NEW_TOTAL": "300/600"} {
		if err := CheckConnLimit(key, val); err != nil {
			t.Errorf("CheckConnLimit(%s, %q): %v", key, val, err)
		}
	}
	o := connBox(t, nil)
	write(t, o.SegmentsDir, "guest.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\nNEW_PER_IP=301/600\n")
	if _, err := Load(o); err == nil || !strings.Contains(err.Error(), "NEW_PER_IP=301/600 is more than NEW_TOTAL=300/600") {
		t.Errorf("per-device rate over the default segment total: %v", err)
	}
	o = connBox(t, nil)
	write(t, o.SegmentsDir, "guest.env", "IF=eth4\nNET=10.81.0.0/24\nIP=10.81.0.1\nCONN_TOTAL=100\n")
	if _, err := Load(o); err == nil || !strings.Contains(err.Error(), "CONN_PER_IP=128 is more than CONN_TOTAL=100") {
		t.Errorf("default per-device cap over a lowered total: %v", err)
	}
}
