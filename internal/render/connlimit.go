package render

import (
	"fmt"
	"strconv"
	"strings"
)

// Connection budgets per device and per segment.
//
// Before these budgets, only the conntrack table of the kernel stood between
// one device and the full box, and that table is shared. The forwarded
// flows of each segment, each agent flow to the engine, and the flows of
// the Pi itself -- the origin connections of the broker, the DoT upstream,
// and SSH into the Pi -- all take their entry from the same
// nf_conntrack_max. One house device (or a root agent) that opened flows
// until the table was full took new flows away from all of them at the
// same time, SSH to the gateway included. Thus each segment gets three
// numbers:
//
//   - CONN_PER_IP: the live flows that one source address can hold, a ct
//     count in a dynamic set keyed on ip saddr.
//   - NEW_PER_IP: the new flows per second that one source can open,
//     "RATE/BURST", a limit meter keyed on ip saddr. This stops the
//     conntrack table from filling with short-lived entries (TIME_WAIT is
//     30 s on the Pi, vm/pi/apply.sh, and does not count as live, so
//     CONN_PER_IP alone does not limit it).
//   - CONN_TOTAL: the live flows that the full segment can hold, a ct count
//     on the rule itself. It is the backstop for a device that spreads itself
//     over many addresses (a root agent can alias across AGENT_NET, and
//     nothing binds an address to a MAC on the house). It also keeps the
//     sum of the segments well under nf_conntrack_max: 4096 + 32768 +
//     4096 per plain segment leaves most of 131072 for the Pi itself.
//
// "0" disables one number, and the rule is not rendered. An absent key is
// the default. The keys are from net.env, and net.env.local can override
// them as it can the other keys. pf admin validates them with
// CheckConnLimit before it writes one. A plain segment can have its own
// CONN_PER_IP, NEW_PER_IP, CONN_TOTAL and NEW_TOTAL in its segments.d file.
// For each missing key, it uses the SEG_ key (segConnBudget).
// CheckConnLimit("SEG_"+key, v) validates those.
//
// The defaults come from what real clients hold, with headroom. npm opens
// 16-50 sockets, docker pull 3-10, a headless browser 6 per host. Thus 128
// is a lot for an agent. A phone peaks at 100-300 flows, and a laptop with
// many tabs at 300-800. Thus 1024 for a house device. Torrent-style clients
// need thousands and will break here. Strict house egress already stops
// most of what they do.
//
// A plain segment uses the numbers of the agent, not of the house. The desk
// seat is the host that the agent VMs run on. Thus an agent that escapes
// its VM owns the desk, and it arrives on the plain segment with the same
// intent that it had on the agent segment. The budget should not grow on
// the way out. The cost is for a desktop browser with hundreds of tabs,
// which can pass 128 live flows. Its file sets CONN_PER_IP (or net.env
// SEG_CONN_PER_IP) higher, as a house device would need 1024.
type connBudget struct {
	PerIP, Rate, Burst, Total int
	// NewTotal and NewBurst are the new TCP flows per second of the segment.
	// They limit its TIME_WAIT entries (houseNewTotalKey, segNewTotalKey).
	// The house and plain segments have a key for it. For the agent, it is the
	// constant agentNewTotal.
	NewTotal, NewBurst int
}

// Segment classes, each with its own three keys: the agent segment, the
// house, and every plain segment in segments.d (the desk seat is one).
const (
	connAgent = "AGENT"
	connHouse = "HOUSE"
	connSeg   = "SEG"
)

var connDefaults = map[string]connBudget{
	connAgent: {PerIP: 128, Rate: 50, Burst: 200, Total: 4096},
	connHouse: {PerIP: 1024, Rate: 100, Burst: 500, Total: 32768, NewTotal: 1000, NewBurst: 5000},
	connSeg:   {PerIP: 128, Rate: 50, Burst: 200, Total: 4096, NewTotal: 300, NewBurst: 600},
}

// ConnLimitKeys are the net.env keys, in the sequence that net.env lists
// them: three for each class. HOUSE_NEW_TOTAL of the house and
// SEG_NEW_TOTAL of the plain segments come after their three. apply.sh
// exports each to pf render, and pf admin accepts each.
var ConnLimitKeys = func() []string {
	var out []string
	for _, class := range []string{connAgent, connHouse, connSeg} {
		out = append(out, class+"_CONN_PER_IP", class+"_NEW_PER_IP", class+"_CONN_TOTAL")
		switch class {
		case connHouse:
			out = append(out, houseNewTotalKey)
		case connSeg:
			out = append(out, segNewTotalKey)
		}
	}
	return out
}()

// agentNewTotal is the new TCP flows per second of the full agent segment.
// It limits the TIME_WAIT entries of the segment. A flow that the engine
// admits and closes, or accepts and refuses at its own cap, leaves a
// conntrack entry in TIME_WAIT for 30 s (vm/pi/apply.sh lowers the 120 of
// the kernel). CONN_TOTAL does not count it (nf_conncount skips closed
// flows). For each source, NEW_PER_IP limits one address to 50 × 30 +
// 200 = 1700 entries. But a root agent can alias across AGENT_NET. Sufficient
// addresses under the meter would fill the 131072 table that all segments
// and the Pi share. The kernel frees assured TIME_WAIT entries from its gc
// worker only past 95 % full, not when a new flow needs one. A short
// `ct timeout` for 8080 was the targeted fix. The Pi kernel has no
// CONFIG_NF_CONNTRACK_TIMEOUT (dnsNoTrack). Thus the segment gets a total:
// 300 × 30 + 600 = 9600 entries at worst, 7 % of the table (it was 36600
// at 120 s). Three agents at their full per-source 50/s are 150, half of
// it. Thus it applies only to a flood spread over six or more addresses.
// It is a constant, not a net.env key. No one has needed a different
// number, and a key is four places to keep the same (ConnLimitKeys,
// net.env, pf admin, the docs).
const agentNewTotal = "300/second burst 600 packets"

// houseNewTotalKey is the new TCP flow rate for the full house segment, the
// house side of the TIME_WAIT limit. Nothing binds an address to a MAC on
// the house. Thus many devices, or one device that aliases addresses
// across the house /24, can each stay under HOUSE_NEW_PER_IP (100/s) and
// together put TIME_WAIT entries in the table that SSH and the DoT of the
// Pi share. The default, 1000/s burst 5000, is sized for a household. A
// browser opens tens of connections on a page load, and HOUSE_NEW_PER_IP
// already limits one device to 100/s. Thus ten devices at their full
// per-device rate at the same time fit. The burst is the full per-device
// burst of ten devices. At the 30 s TIME_WAIT of the Pi, that is
// 1000 × 30 + 5000 = 35000 entries at worst, 27 % of 131072. At the 120 s of the
// kernel, it would have been 125000, the full table. This is why apply.sh
// also lowers the timeout. With the 9600 of the agent, the TIME_WAIT worst
// case of the two segments is 34 %. TCP only: UDP and ICMP entries stay
// live until they time out, and CONN_TOTAL counts those.
const houseNewTotalKey = "HOUSE_NEW_TOTAL"

// segNewTotalKey is the new TCP flow rate for each full plain segment, the
// plain-segment side of the TIME_WAIT limit. The own file of a segment can
// set NEW_TOTAL in its place (segConnBudget). SEG_NEW_PER_IP limits one
// address to 50/s. But a device that aliases addresses in its subnet can
// stay under that on each address, and put TIME_WAIT entries in the table
// that the house, the agent and SSH to the Pi share. The default is the
// agentNewTotal of the agent, 300/s burst 600, for the same reason that the
// other plain defaults are those of the agent (connDefaults): six devices
// at their full per-device 50/s at the same time. At the 30 s TIME_WAIT of
// the Pi, that is 300 × 30 + 600 = 9600 entries at worst per segment,
// 7.3 % of 131072, under the 10 % that one segment can take. Render makes
// one rule for each segments.d file and sets no cap on their number. The
// desk is one, and three are 28800 (22 %). With the 35000 of the house and
// the 9600 of the agent, that is 73400, 56 %, under the 60 % that the
// segments together can take. A fourth segment is 83000 (63 %) and should
// set a lower NEW_TOTAL in its file. TCP only, as for the house.
const segNewTotalKey = "SEG_NEW_TOTAL"

// Floors and ceilings. Below a floor, the limit is no longer a limit on
// abuse. It becomes an outage that looks like a broken network. One
// browser tab opens a dozen flows at the same time. Thus a per-device cap
// under 16 fails page loads, and a segment total under 64 fails a second
// device. The ceilings are the conntrack table (nf_conntrack_max, 131072,
// in vm/pi/apply.sh). A budget larger than the table is not a budget.
const (
	minConnPerIP = 16
	minConnTotal = 64
	maxConn      = 131072
	minNewRate   = 5
	maxNewRate   = 100000
	// minNewTotal: a segment total under the default per-device rate of one
	// device would fail page loads on a second device.
	minNewTotal = 100
)

// atoiStrict accepts a positive decimal with no sign, no leading zero and
// no spaces. Thus it refuses "0128" or "+5", and does not read them as a
// value that the operator possibly did not mean.
func atoiStrict(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || strconv.Itoa(n) != s {
		return 0, false
	}
	return n, true
}

// ConnLimitDefault is the value that render uses for one of ConnLimitKeys
// when net.env does not set it, in the form of the key ("128", "50/200").
// It is empty for a key that is not one of them. Thus a screen can show the
// number that applies, not only the word "default".
func ConnLimitDefault(key string) string {
	class, suffix, _ := strings.Cut(key, "_")
	d, ok := connDefaults[class]
	if !ok {
		return ""
	}
	switch suffix {
	case "CONN_PER_IP":
		return strconv.Itoa(d.PerIP)
	case "NEW_PER_IP":
		return strconv.Itoa(d.Rate) + "/" + strconv.Itoa(d.Burst)
	case "CONN_TOTAL":
		return strconv.Itoa(d.Total)
	case "NEW_TOTAL":
		if d.NewTotal > 0 {
			return strconv.Itoa(d.NewTotal) + "/" + strconv.Itoa(d.NewBurst)
		}
	}
	return ""
}

// CheckConnLimit validates the value of one key the same way as Load reads
// it. For each key, empty is the default and "0" is off.
func CheckConnLimit(key, v string) error {
	_, _, err := parseConnValue(key, v, 0, 0)
	return err
}

// parseConnValue returns the number of the key, and for NEW_PER_IP also the
// burst as the second value. For "", it returns dflt and dburst.
func parseConnValue(key, v string, dflt, dburst int) (int, int, error) {
	if v == "" {
		return dflt, dburst, nil
	}
	if v == "0" {
		return 0, 0, nil
	}
	switch {
	case strings.HasSuffix(key, "_NEW_PER_IP"):
		if rate, burst, ok := parseRateBurst(v, minNewRate); ok {
			return rate, burst, nil
		}
		return 0, 0, fmt.Errorf("want 0 or RATE/BURST new connections a second, RATE %d-%d and BURST at least RATE (e.g. 50/200)", minNewRate, maxNewRate)
	case strings.HasSuffix(key, "_NEW_TOTAL"):
		if rate, burst, ok := parseRateBurst(v, minNewTotal); ok {
			return rate, burst, nil
		}
		return 0, 0, fmt.Errorf("want 0 or RATE/BURST new connections a second for the whole segment, RATE %d-%d and BURST at least RATE (e.g. 1000/5000)", minNewTotal, maxNewRate)
	case strings.HasSuffix(key, "_CONN_PER_IP"):
		return parseConnCount(v, minConnPerIP)
	case strings.HasSuffix(key, "_CONN_TOTAL"):
		return parseConnCount(v, minConnTotal)
	}
	return 0, 0, fmt.Errorf("not a connection limit key")
}

// parseRateBurst reads "RATE/BURST" with RATE from minRate to maxNewRate and
// BURST from RATE to 10*maxNewRate.
func parseRateBurst(v string, minRate int) (int, int, bool) {
	r, b, ok := strings.Cut(v, "/")
	rate, okR := atoiStrict(r)
	burst, okB := atoiStrict(b)
	if !ok || !okR || !okB || rate < minRate || rate > maxNewRate || burst < rate || burst > 10*maxNewRate {
		return 0, 0, false
	}
	return rate, burst, true
}

func parseConnCount(v string, minCount int) (int, int, error) {
	n, ok := atoiStrict(v)
	if !ok || n < minCount || n > maxConn {
		return 0, 0, fmt.Errorf("want 0 or %d-%d connections", minCount, maxConn)
	}
	return n, 0, nil
}

// loadConnLimits reads Net.ConnLimits into the three budgets. It refuses a
// bad value, with the key and the file that it came from. It also refuses a
// per-device cap larger than the total of its segment. That combination
// never limits what it says, and it is almost always a missing digit.
func (c *Config) loadConnLimits() error {
	c.connBudgets = map[string]connBudget{}
	for _, class := range []string{connAgent, connHouse, connSeg} {
		d := connDefaults[class]
		var b connBudget
		var err error
		get := func(suffix string, dflt, dburst int) (int, int) {
			if err != nil {
				return 0, 0
			}
			key := class + suffix
			n, m, e := parseConnValue(key, c.ConnLimits[key], dflt, dburst)
			if e != nil {
				err = fmt.Errorf("%s='%s': %v (%s)", key, c.ConnLimits[key], e, c.EnvSrc)
			}
			return n, m
		}
		b.PerIP, _ = get("_CONN_PER_IP", d.PerIP, 0)
		b.Rate, b.Burst = get("_NEW_PER_IP", d.Rate, d.Burst)
		b.Total, _ = get("_CONN_TOTAL", d.Total, 0)
		if class != connAgent {
			b.NewTotal, b.NewBurst = get("_NEW_TOTAL", d.NewTotal, d.NewBurst)
		}
		if err != nil {
			return err
		}
		if b.PerIP > 0 && b.Total > 0 && b.PerIP > b.Total {
			return fmt.Errorf("%s_CONN_PER_IP=%d is more than %s_CONN_TOTAL=%d, so the per-device cap could never be reached (%s)", class, b.PerIP, class, b.Total, c.EnvSrc)
		}
		if b.Rate > 0 && b.NewTotal > 0 && b.Rate > b.NewTotal {
			return fmt.Errorf("%s_NEW_PER_IP=%d/%d is more than %s_NEW_TOTAL=%d/%d, so the per-device rate could never be reached (%s)", class, b.Rate, b.Burst, class, b.NewTotal, b.NewBurst, c.EnvSrc)
		}
		c.connBudgets[class] = b
	}
	return nil
}

// segConnBudget is the budget of a plain segment. It uses each of
// CONN_PER_IP, NEW_PER_IP, CONN_TOTAL and NEW_TOTAL that its segments.d
// file names. For each key that the file does not name, it uses the SEG_
// value of net.env (which has its own default). It works one key at a
// time, so a guest segment can make its per-device cap smaller and keep the
// shared segment total. The validation is the same as for the SEG_ keys,
// with the same refusals of a per-device cap or rate above the segment
// total. The error names the file of the segment, where the operator must look.
func (c *Config) segConnBudget(s *Segment, file string) error {
	b := c.connBudgets[connSeg]
	for _, suffix := range []string{"CONN_PER_IP", "NEW_PER_IP", "CONN_TOTAL", "NEW_TOTAL"} {
		v, ok := s.ConnLimits[suffix]
		if !ok {
			continue
		}
		n, m, err := parseConnValue(connSeg+"_"+suffix, v, 0, 0)
		if err != nil {
			return fmt.Errorf("%s: %s='%s': %v", file, suffix, v, err)
		}
		switch suffix {
		case "CONN_PER_IP":
			b.PerIP = n
		case "NEW_PER_IP":
			b.Rate, b.Burst = n, m
		case "CONN_TOTAL":
			b.Total = n
		case "NEW_TOTAL":
			b.NewTotal, b.NewBurst = n, m
		}
	}
	if b.PerIP > 0 && b.Total > 0 && b.PerIP > b.Total {
		return fmt.Errorf("%s: CONN_PER_IP=%d is more than CONN_TOTAL=%d (with net.env's SEG_ value for a key the file leaves out), so the per-device cap could never be reached", file, b.PerIP, b.Total)
	}
	if b.Rate > 0 && b.NewTotal > 0 && b.Rate > b.NewTotal {
		return fmt.Errorf("%s: NEW_PER_IP=%d/%d is more than NEW_TOTAL=%d/%d (with net.env's SEG_ value for a key the file leaves out), so the per-device rate could never be reached", file, b.Rate, b.Burst, b.NewTotal, b.NewBurst)
	}
	s.conn = b
	return nil
}

// connLimit renders the budget of one segment: the dynamic set that holds
// the per-device count, the chain that an over-limit flow jumps to, and the
// three rules. match is the iifname of the segment plus the part that
// narrows it to the counted flows (the agent: TCP only, see Ruleset). name
// is the nft identifier stem, and seg is the name in the log prefix.
//
// Order: the new-flow meter is first, because it is the cheap one, and a
// flood that it drops never reaches the ct count lists. Then the count of
// the device. Then the count of the segment, so a flow already refused for
// its device does not also use the budget of the segment. Each rule
// matches only ct state new. Each caller puts them where no earlier rule
// accepts a new flow. Thus an established flow -- the SSH session of the
// operator included -- is never evaluated here. A flow already admitted is
// never cut when a limit is lowered.
//
// All three fail open. When the dynamic set is full, the add fails, the
// rule does not match, and the flow continues to the rules below. That is
// correct for a limit whose function is fairness, not policy. A
// source-spoofing flood that fills the set can at worst disable the
// per-device limits, and the segment total still applies.
func connLimit(name, seg, match string, b connBudget) (set, rules, chain string) {
	if b == (connBudget{}) {
		return "", "", ""
	}
	jump := " jump " + name + "_connlimit"
	if b.Rate > 0 {
		rules += match + " meter " + name + "_newconn { ip saddr limit rate over " + strconv.Itoa(b.Rate) + "/second burst " + strconv.Itoa(b.Burst) + " packets }" + jump
	}
	if b.PerIP > 0 {
		// size limits the set, not the segment. Past it, the rule fails
		// open (above). 65535 is the meter default of nft.
		set = "\n\n  set " + name + "_conn_v4 {\n    type ipv4_addr\n    size 65535\n    flags dynamic\n  }"
		rules += match + " add @" + name + "_conn_v4 { ip saddr ct count over " + strconv.Itoa(b.PerIP) + " }" + jump
	}
	if b.Total > 0 {
		rules += match + " ct count over " + strconv.Itoa(b.Total) + jump
	}
	if b.NewTotal > 0 {
		// This goes last, so a flow already refused for its device or for the live
		// total does not also use the rate of the segment (houseNewTotalKey,
		// segNewTotalKey).
		rules += match + " meta l4proto tcp limit rate over " + strconv.Itoa(b.NewTotal) + "/second burst " + strconv.Itoa(b.NewBurst) + " packets" + jump
	}
	// One log line for each over-limit flow, at most ten each second, under
	// the prefix of the segment. Thus pf observe files it as "<seg>-connlimit".
	// For TCP, a reset and not a silent drop: the client fails at once with
	// "connection refused". It does not send a SYN again for a minute. A limit
	// that means "not now" should look like this.
	chain = "\n\n  chain " + name + "_connlimit {" +
		"\n   " + logRate + "\"pi-fortress " + seg + "-connlimit: \" level info" +
		"\n    meta l4proto tcp counter reject with tcp reset" +
		"\n    counter drop\n  }"
	return set, rules, chain
}

// connLimits fills the fragments for the agent, the house and each plain
// segment.
func (f *fragments) connLimits() {
	add := func(name, seg, match string, b connBudget, rules *string) {
		set, r, chain := connLimit(name, seg, match, b)
		f.ConnSets += set
		*rules += r
		f.ConnChains += chain
	}
	// The flows of the agent to the Pi are local, not forwarded. nat
	// prerouting redirects 443 to the engine on 8080, and 80 is pf www. Thus
	// the count is in input, after the conntrack accept and before the port
	// accepts. TCP only: the DNS of the agent is UDP to pf dns, one flow for
	// each query, and the 200/s DNS meter already limits it. Without this, a
	// resolver-heavy build with a few hundred lookups would use its connection
	// budget on lookups that finished seconds ago.
	agentMatch := "\n    iifname \"" + f.IntIF + "\" meta l4proto tcp ct state new"
	add("agent", "agent", agentMatch, f.connBudgets[connAgent], &f.AgentConnLimit)
	if f.connBudgets[connAgent] != (connBudget{}) {
		f.AgentConnLimit += agentMatch + " limit rate over " + agentNewTotal + " jump agent_connlimit"
	}
	// House and plain segments are forwarded. Their rules go first in
	// forward, before the house SNI queue and before the conntrack accept. The
	// packets of a pending 443 flow go in the queue to pf dns. The accept
	// verdict that a queue returns leaves the chain. Thus a count after the
	// queue would never see those flows.
	if f.HouseIF != "" {
		add("house", "house", "\n    iifname \""+f.HouseIF+"\" ct state new", f.connBudgets[connHouse], &f.ConnLimitFwd)
	}
	for _, s := range f.Segments {
		// seg_ prevents a segment called "house" or "agent" from naming the
		// same set as the real one.
		add("seg_"+nftName(s.Name), s.Name, "\n    iifname \""+s.IF+"\" ct state new", s.conn, &f.ConnLimitFwd)
	}
}
