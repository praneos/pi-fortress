//go:build vagrant

package itest

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// deskTests run on the desk seat: a plain segment. Thus NAT to the uplink,
// isolation from all other segments, the resolver and block lists of the
// Pi, strict egress, and no inspection. Three labs come here: the local
// VirtualBox lab, the desk VM of the cloud lab, and a real desktop. The
// assertions are the same in all three, except the two that name a
// device, because only the local lab is untagged.
func deskTests(t *testing.T) {
	needHost(t, "desk")
	e := netenv(t)
	agentIP, blockIP := e["AGENT_IP"], e["BLOCK_IP"]
	gw, self := e["DESK_IP"], e["DESK_SEAT_IP"]
	// A VirtualBox internal network carries no 802.1Q tags. Thus the local
	// lab puts the desk segment on its own adapter, not on a child of the
	// agent trunk. All above the link layer is the same segment. The
	// differences are the interface names, and that this host has no
	// trunk and no agent VLAN to lock out.
	tagged := target() != "vagrant"

	t.Run("setup.sh status", func(t *testing.T) {
		cmd := "sudo /vagrant/vm/desk/lab.sh status"
		if tagged {
			cmd = "sudo sh -c '. /etc/pf-lab.env; PARENT=$LAB_IF /vagrant/vm/desk/setup.sh status'"
		}
		out := mustSSH(t, "desk", cmd)
		for _, want := range []string{" " + self + "/30", "table inet pf_desk_lock"} {
			if !contains(out, want) {
				t.Fatalf("no %q in:\n%s", want, out)
			}
		}
		if out := mustSSH(t, "desk", "systemctl is-active pf-desk-lock.service"); strings.TrimSpace(out) != "active" {
			t.Fatal(out)
		}
	})
	t.Run("default route and internet through the Pi", func(t *testing.T) {
		if out := mustSSH(t, "desk", "ip route show default"); !contains(out, "via "+gw) {
			t.Fatal(out)
		}
		out, _ := ssh(t, 20*time.Second, "desk", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://"+e["ALLOW_DOMAIN"])
		if !curlOK(strings.TrimSpace(out)) {
			t.Fatal(out)
		}
	})
	t.Run("ssh to the Pi and the agents", func(t *testing.T) {
		mustSSH(t, "desk", "nc -z -w3 "+gw+" 22")
		mustSSH(t, "desk", "nc -z -w3 "+agentIP+" 22")
	})
	// SSH_TO is one port, not a route: all other traffic that the seat
	// sends to the agent segment meets the isolation drop. Port 80, not a
	// probe from the agent side. That probe cannot reach the forward chain
	// at all: the blanket ssh ban of the agent segment drops its packets
	// in prerouting. Thus an agent-to-desk assertion would pass, and the
	// isolation rule would never apply. The reverse rule is asserted as a
	// rule below, because nothing that an agent may send can test it.
	// Nothing listens on port 80 of the agent. Thus a refused nc alone
	// would pass with no isolation at all: the desk-to-agent drop of the
	// Pi must count the SYN.
	t.Run("the hole to the agents is only ssh", func(t *testing.T) {
		addrs := pi(t, "ip -br -4 addr")
		deskIf, agentIf := devWith(addrs, gw), devWith(addrs, e["PI_IP"])
		if deskIf == "" || agentIf == "" {
			t.Fatalf("no device for %s or %s in:\n%s", gw, e["PI_IP"], addrs)
		}
		piDropsGrow(t, "forward", `iifname "`+deskIf+`" oifname "`+agentIf+`"`, func() {
			mustFailOn(t, "desk", "nc -z -w3 "+agentIP+" 80")
		})
	})
	t.Run("the Pi isolates the two segments", func(t *testing.T) {
		// Ask the Pi, do not assume. Then the assertion is the same if the
		// segment is a plain port or a VLAN child.
		addrs := pi(t, "ip -br -4 addr")
		deskIf, agentIf := devWith(addrs, gw), devWith(addrs, e["PI_IP"])
		if deskIf == "" || agentIf == "" {
			t.Fatalf("no device for %s or %s in:\n%s", gw, e["PI_IP"], addrs)
		}
		out := pi(t, "sudo nft list ruleset")
		for _, want := range []string{
			`iifname "` + agentIf + `" oifname "` + deskIf + `" counter`,
			`iifname "` + deskIf + `" oifname "` + agentIf + `" counter`,
		} {
			if !lineWith(out, want, "drop") {
				t.Fatalf("no %q drop in the ruleset", want)
			}
		}
	})
	t.Run("blocked address dropped and logged", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "desk", "curl -sS --noproxy '*' -o /dev/null --max-time 5 http://"+blockIP)
		kernLog(t, since, "pi-fortress desk-blacklist: ", "DST="+blockIP+" ")
	})
	// The segment resolves through this box now. Port 53 answers. The
	// answer comes from the resolver of the Pi, not from a resolver that
	// the seat would select. A listed name is sinkholed as it is for the
	// agents.
	t.Run("the Pi resolves for the segment", func(t *testing.T) {
		mustSSH(t, "desk", "nc -z -w3 "+gw+" 53")
		if out := mustSSH(t, "desk", "cat /etc/resolv.conf"); !contains(out, "nameserver "+gw) {
			t.Fatalf("the seat does not ask the Pi:\n%s", out)
		}
		out := mustSSH(t, "desk", "dig +short +time=3 @"+gw+" "+e["BLOCK_DOMAIN"])
		if !contains(out, "0.0.0.0") {
			t.Fatalf("a listed name was not sinkholed:\n%s", out)
		}
		// The Pi-side half of the same lookup.
		// All above is the view of the seat. A seat cannot tell the
		// resolver of the Pi from a different service that answers on that
		// address. Without this row, a second daemon could serve the
		// segment, or the log of the agent segment could include it, and
		// the three checks above would still pass. The own file of the
		// segment, tagged with the segment, shows the truth.
		// dns-desk.jsonl, not observe.json: observe saves its state every
		// 15 minutes, but the resolver appends the row when it answers.
		// Thus observe.json would be stale for a new lookup.
		const deskLog = "/var/log/pi-fortress/dns-desk.jsonl"
		eventually(t, 20*time.Second, func() string {
			rows, _ := ssh(t, 15*time.Second, "pi", "sudo tail -n 20 "+deskLog)
			if lineWith(rows, `"seg":"desk"`, e["BLOCK_DOMAIN"]) {
				return ""
			}
			return fmt.Sprintf("no %s row with \"seg\":\"desk\" for %s:\n%s", deskLog, e["BLOCK_DOMAIN"], rows)
		})
	})
	// And a lookup sent to a different server is refused. If not, the
	// 80/443 gate below would have a set that nothing fills. The seat
	// would then resolve all names and reach none of them.
	t.Run("no resolver but the Pi's", func(t *testing.T) {
		mustFailOn(t, "desk", "dig +short +time=2 +tries=1 @"+e["DNS_UPSTREAM"]+" "+e["ALLOW_DOMAIN"])
	})
	// The resolver gate: an address this segment resolved opens, and one
	// it never asked for does not.
	t.Run("only resolved addresses answer on 443", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "desk", "curl -4 -sS --noproxy '*' -o /dev/null --max-time 5 https://"+e["ECHO_CORE_IP"])
		kernLog(t, since, "pi-fortress desk-directip: ", "DST="+e["ECHO_CORE_IP"]+" ", "DPT=443 ")
	})
	// PARANOID=on on the desk (docs/paranoid_mode.md, plain segments).
	// Nothing in the suite arms it, for the reason that the paranoid arm
	// of the agent gives in dns_segments_test.go. Arm the box manually
	// (PARANOID=on in /etc/pi-fortress/segments.d/desk.env, sudo pf
	// apply). Then the resolver of the desk answers only allow.desk.domains.
	// With the shipped seed, api.anthropic.com answers. example.com, a
	// safe name that nobody seeds, gets the blocked answer.
	deskParanoid := strings.TrimSpace(pi(t, "grep -hE '^PARANOID=' /etc/pi-fortress/segments.d/desk.env 2>/dev/null | tail -1 | cut -d= -f2- || true"))
	t.Run("a paranoid desk resolves only its allowlist", func(t *testing.T) {
		if deskParanoid != "on" {
			t.Skip("the desk segment is not PARANOID=on")
		}
		const allow = "/etc/pi-fortress/allow.desk.domains"
		conf := pi(t, "sudo cat /etc/pi-fortress/dns.json")
		if !lineWith(conf, `"name": "desk"`, `"paranoid": true, "allow": "`+allow+`"`) || lineWith(conf, `"name": "desk"`, "core_hosts") {
			t.Fatalf("dns.json does not arm the desk on its own allowlist:\n%s", conf)
		}
		list := pi(t, "sudo cat "+allow)
		if listedLine(list, "anthropic.com") {
			out := mustSSH(t, "desk", "dig +short +time=3 @"+gw+" api.anthropic.com")
			if ip := firstIPv4(out); ip == "" || ip == "0.0.0.0" {
				t.Fatalf("api.anthropic.com is on the desk's list and did not resolve: %q", out)
			}
		}
		if listedLine(list, "example.com") {
			t.Skip("example.com is on the desk's list; nothing left to refuse safely")
		}
		out := mustSSH(t, "desk", "dig +short +time=3 @"+gw+" example.com")
		if !contains(out, "0.0.0.0") {
			t.Fatalf("example.com is not on the desk's list and answered %q", out)
		}
		const deskLog = "/var/log/pi-fortress/dns-desk.jsonl"
		eventually(t, 20*time.Second, func() string {
			rows, _ := ssh(t, 15*time.Second, "pi", "sudo tail -n 20 "+deskLog)
			if lineWith(rows, `"name":"example.com"`, `"act":"blocked"`) {
				return ""
			}
			return "no blocked row for example.com in " + deskLog + ":\n" + rows
		})
	})
	t.Run("ping the Pi", func(t *testing.T) {
		mustSSH(t, "desk", "ping -c2 -W2 "+gw)
	})
	t.Run("no ssh to house devices", func(t *testing.T) {
		needHost(t, "house")
		mustFailOn(t, "desk", "nc -z -w3 10.78.0.20 22")
	})
	// The half of the desk lock that each tier can prove. Otherwise, a
	// container on the default docker bridge would NAT out through the
	// desk route without the fence. When nothing forwards, it has no network.
	t.Run("this host forwards nothing", func(t *testing.T) {
		out := mustSSH(t, "desk", "sudo nft list chain inet pf_desk_lock forward")
		if !contains(out, "policy drop") {
			t.Fatalf("the forward chain does not drop by default:\n%s", out)
		}
	})
	t.Run("Pi addresses", func(t *testing.T) {
		out := pi(t, "ip -br -4 addr")
		// Untagged: one adapter per segment, and no house.
		want := [][2]string{{"", " " + e["PI_IP"] + "/24"}, {"", " " + gw + "/30"}}
		if tagged {
			want = [][2]string{{".20@", " " + e["PI_IP"] + "/24"}, {".79@", " " + gw + "/30"}, {"", " 10.78.0.1/24"}}
		}
		for _, w := range want {
			if !lineWith(out, w[0], w[1]) {
				t.Fatalf("no %s line with%s in:\n%s", w[0], w[1], out)
			}
		}
	})
	t.Run("lock survives a reboot", func(t *testing.T) {
		needReboot(t)
		reboot(t, "desk")
		mustSSH(t, "desk", "sudo nft list table inet pf_desk_lock")
	})
}

// listedLine is an allowlist line that is exactly name, not a comment
// that happens to mention it.
func listedLine(list, name string) bool {
	for line := range strings.SplitSeq(list, "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}

// devWith is the interface that has addr in `ip -br addr` output, as nft
// names it: a VLAN child prints as eth0.79@eth0 there and as eth0.79 in
// a rule.
func devWith(out, addr string) string {
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(line, " "+addr+"/") {
			continue
		}
		return strings.SplitN(f[0], "@", 2)[0]
	}
	return ""
}
