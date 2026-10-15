//go:build vagrant

package itest

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dropTests check that the DoH and direct-IP drops of the agent segment
// are logged. The policy group only sees them fail.
func dropTests(t *testing.T) {
	e := netenv(t)
	allow := e["ALLOW_DOMAIN"]

	t.Run("DoH to a resolver address logged", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "agent", "curl -sS --noproxy '*' -o /dev/null --max-time 5 https://1.1.1.1/dns-query")
		kernLog(t, since, "pi-fortress agent-doh: ", "DST=1.1.1.1 ")
	})
	// The resolver pin, end to end: the only DNS of the agent is the Pi,
	// over UDP or TCP. 8.8.8.8 is a well-known safe host (AGENTS.md).
	// Nothing reaches it over UDP or TCP. Nothing tested this until the
	// ch.at report asked if dig @server gets out. The lock of the agent
	// refuses both before they leave the VM. Thus the probe lifts the
	// lock, and the Pi must log the drop. 8.8.8.8 is in the DoH address
	// set, and the drop of that set comes before the port 53 drop.
	t.Run("DNS straight out is dropped", func(t *testing.T) {
		liftAgentLock(t)
		since := piClock(t)
		mustFailOn(t, "agent", "dig +time=3 +tries=1 @8.8.8.8 example.com")
		mustFailOn(t, "agent", "dig +tcp +time=3 +tries=1 @8.8.8.8 example.com")
		kernLog(t, since, "pi-fortress agent-doh: ", "DST=8.8.8.8 ", "PROTO=UDP ", "DPT=53 ")
		kernLog(t, since, "pi-fortress agent-doh: ", "DST=8.8.8.8 ", "PROTO=TCP ", "DPT=53 ")
	})
	// A key in a query name is refused before it is forwarded. Thus the
	// authoritative server of the zone never sees it. The key has the
	// all-A canary shape, and the zone is the block canary.
	t.Run("a key in a query name is refused", func(t *testing.T) {
		name := "sk-ant-oat01-" + strings.Repeat("A", 40) + ".pi-fortress-block.test"
		out := agent(t, "dig +time=3 +tries=1 @"+e["PI_IP"]+" "+name+" TXT | grep -o 'status: [A-Z]*' || true")
		if strings.TrimSpace(out) != "status: REFUSED" {
			t.Fatalf("dig %s: %q, want status: REFUSED", name[:20], out)
		}
		if n := grepCount(t, "/var/log/pi-fortress/dns.jsonl", "AAAAAAAAAAAAAAAAAAAA"); n != 0 {
			t.Fatalf("the key reached dns.jsonl %d times", n)
		}
	})
	// Address-only: an LLM over DNS answers with TXT. Thus the resolver of
	// the agent itself gives an empty answer to all types except A.
	// example.com has TXT records upstream, so an answer here would come
	// from the forwarder.
	t.Run("a TXT query is answered empty", func(t *testing.T) {
		out := agent(t, "dig +time=3 +tries=1 @"+e["PI_IP"]+" example.com TXT")
		if !strings.Contains(out, "status: NOERROR") || !strings.Contains(out, "ANSWER: 0,") {
			t.Fatalf("dig example.com TXT, want NOERROR and no answers:\n%s", out)
		}
	})
	// And an A answer comes back as addresses only. www.microsoft.com is
	// a well-known safe host whose answer is a CNAME chain upstream.
	t.Run("an A answer carries no CNAME", func(t *testing.T) {
		out := agent(t, "dig +time=3 +tries=1 @"+e["PI_IP"]+" www.microsoft.com A +noall +answer")
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if strings.TrimSpace(out) == "" {
			t.Fatal("dig www.microsoft.com A: no answer")
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) != 5 || f[0] != "www.microsoft.com." || f[3] != "A" {
				t.Fatalf("dig www.microsoft.com A: %q is not an A record under the asked name:\n%s", l, out)
			}
		}
	})
	t.Run("direct IP dropped and logged", func(t *testing.T) {
		ip := unresolved(t, "resolved_v4", allow)
		since := piClock(t)
		mustFailOn(t, "agent", "curl -sS --noproxy '*' -o /dev/null --max-time 5 --resolve "+allow+":443:"+ip+" https://"+allow+"/")
		kernLog(t, since, "pi-fortress agent-directip: ", "DST="+ip+" ")
	})
	t.Run("a source outside the agent net is dropped and logged", func(t *testing.T) {
		spoofDropped(t, e["PI_IP"], e["AGENT_NET"])
	})
}

// spoofCounter reads the source-check drop counter of the agent segment:
// the one rule in raw prerouting that says ip saddr != AGENT_NET.
var spoofCounter = regexp.MustCompile(`ip saddr != (\S+) counter packets (\d+) bytes \d+ drop`)

func spoofPackets(t *testing.T, agentNet string) int {
	t.Helper()
	for _, m := range spoofCounter.FindAllStringSubmatch(pi(t, "sudo nft list chain inet fortress filter_prerouting"), -1) {
		if m[1] == agentNet {
			n, _ := strconv.Atoi(m[2])
			return n
		}
	}
	t.Fatalf("no source check for %s in filter_prerouting", agentNet)
	return 0
}

// spoofDropped acts as a root agent that puts an address outside its
// segment on its NIC and pings the Pi from it. The source check of the Pi
// (render antiSpoof) must count and log each ping. The address is the
// TEST-NET canary. The MAC of the Pi is pinned first, so the ARP for it
// never goes out under the canary name. All changes are undone on EXIT.
func spoofDropped(t *testing.T, piIP, agentNet string) {
	const src = "192.0.2.1"
	before := spoofPackets(t, agentNet)
	since := piClock(t)
	script := strings.Join([]string{
		"set -u",
		"ping -c 1 -W 2 " + piIP + " >/dev/null",
		"dev=$(ip -4 route get " + piIP + " | awk '{for(i=1;i<NF;i++) if($i==\"dev\"){print $(i+1); exit}}')",
		"mac=$(ip neigh show " + piIP + " dev $dev | awk '{print $3; exit}')",
		"trap 'ip addr del " + src + "/32 dev $dev 2>/dev/null; ip neigh del " + piIP + " dev $dev 2>/dev/null' EXIT",
		"ip neigh replace " + piIP + " lladdr $mac dev $dev nud permanent",
		"ip addr add " + src + "/32 dev $dev",
		"ping -c 3 -i 0.3 -W 1 -I " + src + " " + piIP + " >/dev/null; echo rc=$?",
	}, "; ")
	out, err := ssh(t, 60*time.Second, "agent", "sudo bash -c "+shellQuote(script))
	if !strings.Contains(out, "rc=") {
		t.Fatalf("the agent's spoofed ping did not run: %v\n%s", err, out)
	}
	if strings.Contains(out, "rc=0") {
		t.Errorf("the Pi answered a ping from %s on the agent segment", src)
	}
	kernLog(t, since, "pi-fortress agent-spoof: ", "SRC="+src+" ")
	// At least one, not all three. The agent-to-Pi link sometimes loses
	// ICMP (setup.sh accepts any reply of three for the same reason). A
	// ping lost on the wire never reaches the counter. The requirement:
	// no ping got an answer (above), and the check saw and logged them.
	if after := spoofPackets(t, agentNet); after-before < 1 {
		t.Errorf("the source check counted none of 3 spoofed pings (%d -> %d)", before, after)
	}
	if left := agent(t, "ip -4 -o addr show | grep -F ' "+src+"/' || true"); strings.TrimSpace(left) != "" {
		t.Errorf("the agent kept the canary address:\n%s", left)
	}
}
