package render

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ntpRendered is the house (eth2, 10.78.0.1) and the desk (eth3,
// 10.79.0.1) next to the agent (eth0), with the egress mode of each.
func ntpRendered(t *testing.T, houseEgress, deskEgress string) string {
	t.Helper()
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", deskBase+"EGRESS="+deskEgress+"\n")
	house := write(t, dir, "house.env", "HOUSE_IF=eth2\nHOUSE_ADMIN_IP=10.78.0.20\nHOUSE_EGRESS="+houseEgress+"\n")
	return load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house}).Ruleset(labElements)
}

// The house and each plain segment send all NTP to the gateway, in each
// egress mode. NTP never reaches forward, so no egress chain names a time
// port. NTS key exchange (TCP 4460) has no accept: strict drops it, as all
// other ports that it does not name.
func TestNTPGoesToTheGateway(t *testing.T) {
	for _, mode := range []string{"strict", "audit", "open"} {
		t.Run(mode, func(t *testing.T) {
			nft := ntpRendered(t, mode, mode)
			mustHave(t, "prerouting", chain(t, nft, "prerouting"),
				`iifname "eth2" udp dport 123 ip daddr != 10.78.0.1 counter dnat ip to 10.78.0.1`,
				`iifname "eth3" udp dport 123 ip daddr != 10.79.0.1 counter dnat ip to 10.79.0.1`)
			// Raw has no NTP accept: the blacklist drops a query to a listed
			// address before nat can redirect it. Forward drops NTP from the
			// house and the desk in each mode, behind the redirect.
			raw := chain(t, nft, "filter_prerouting")
			fwd := chain(t, nft, "forward")
			for _, i := range []string{"eth2", "eth3"} {
				order(t, raw, "filter_prerouting",
					`iifname "`+i+`" meta nfproto ipv6 counter drop`,
					`iifname "`+i+`" ip daddr @blacklist_v4`)
				order(t, fwd, "forward",
					`iifname "`+i+`" meta nfproto ipv6 counter drop`,
					`iifname "`+i+`" udp dport 123 counter drop`,
					`iifname "`+i+`" udp dport 53 reject`)
			}
			// The gate of the desk runs before nat. The resolver gave no NTP
			// address, so the accept comes before the gate drops.
			order(t, chain(t, nft, "resolver_gate"), "resolver_gate",
				`iifname "eth3" udp dport 123 accept`,
				`iifname "eth3" meta l4proto { tcp, udp } th dport != 53 ct state new`)
			// Each line that names a time port is one of these, as many times as
			// here: the desk accept is in its gate.
			want := map[string]int{
				`iifname "eth2" udp dport 123 ip daddr != 10.78.0.1 counter dnat ip to 10.78.0.1`: 1,
				`iifname "eth3" udp dport 123 ip daddr != 10.79.0.1 counter dnat ip to 10.79.0.1`: 1,
				`iifname "eth3" udp dport 123 accept`:                                             1,
				`iifname "eth2" udp dport 123 counter drop`:                                       1,
				`iifname "eth3" udp dport 123 counter drop`:                                       1,
				`iifname "eth2" ip daddr 10.78.0.1 udp dport 123 accept`:                          1,
				`iifname "eth3" ip daddr 10.79.0.1 udp dport 123 accept`:                          1,
			}
			port := regexp.MustCompile(`\b(123|4123|4460)\b`)
			for _, l := range strings.Split(nft, "\n") {
				l = strings.TrimSpace(l)
				if port.MatchString(l) && want[l] == 0 {
					t.Errorf("a time port outside the redirect: %s", l)
				}
			}
			for l, w := range want {
				if n := strings.Count(nft, "\n    "+l+"\n"); n != w {
					t.Errorf("%d of %q, want %d", n, l, w)
				}
			}
		})
	}
}

// Input opens UDP 123 only on the address of the house and of the desk,
// above the drop of that interface. The uplink and the agent get nothing.
func TestNTPInputIsTheHouseAndSegmentsOnly(t *testing.T) {
	in := chain(t, ntpRendered(t, "strict", "strict"), "input")
	order(t, in, "input", `iifname "eth2" ip daddr 10.78.0.1 udp dport 123 accept`, `iifname "eth2" counter drop`)
	order(t, in, "input", `iifname "eth3" ip daddr 10.79.0.1 udp dport 123 accept`, `iifname "eth3" counter drop`)
	for _, l := range strings.Split(in, "\n") {
		if strings.Contains(l, "123") && !strings.Contains(l, `iifname "eth2"`) && !strings.Contains(l, `iifname "eth3"`) {
			t.Errorf("input opens NTP on a different interface: %s", strings.TrimSpace(l))
		}
	}
}

// The agent network gets no NTP: no redirect, and no accept for UDP 123
// or TCP 4460 in input or forward. Its input and forward end in a drop.
// Its clock comes from the HTTP Date header of the gateway.
func TestAgentHasNoNTP(t *testing.T) {
	nft := ntpRendered(t, "open", "open")
	for _, name := range []string{"filter_prerouting", "resolver_gate", "prerouting", "input", "forward"} {
		for _, l := range strings.Split(chain(t, nft, name), "\n") {
			if strings.Contains(l, `iifname "eth0"`) && (strings.Contains(l, "123") || strings.Contains(l, "4460")) {
				t.Errorf("%s has a time rule for the agent: %s", name, strings.TrimSpace(l))
			}
		}
	}
	// The accepts of the agent. Each one names a port that is not a time
	// port, or ping.
	allowed := regexp.MustCompile(`(tcp dport (80|8080|53|22)|udp dport 53|icmp type echo-request) `)
	for _, name := range []string{"input", "forward"} {
		body := chain(t, nft, name)
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), `iifname "eth0"`) && strings.HasSuffix(l, "accept") && !allowed.MatchString(l) {
				t.Errorf("%s: an agent accept that is not a known port: %s", name, strings.TrimSpace(l))
			}
		}
	}
	order(t, chain(t, nft, "input"), "input", `iifname "eth0" udp dport 53 accept`, `iifname "eth0" counter drop`)
	order(t, chain(t, nft, "forward"), "forward", `iifname "eth0" tcp dport 22 counter drop`, `iifname "eth0" counter drop`)
}

// ntpPassElements is labElements with an ntp_pass.ips of two servers.
var ntpPassElements = func() Elements {
	e := labElements
	e.NTPPass = "elements = { 162.159.200.1, 216.239.35.4 }"
	return e
}()

// ntpPassRendered is ntpRendered with a second segment, guest (eth4,
// 10.80.0.1), in the same egress mode. desk adds lines to the desk file.
// The guest keeps the default, so the same render shows both.
func ntpPassRendered(t *testing.T, egress, desk string, e Elements) string {
	t.Helper()
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", deskBase+"EGRESS="+egress+"\n"+desk)
	write(t, segs, "guest.env", "IF=eth4\nNET=10.80.0.0/24\nIP=10.80.0.1\nEGRESS="+egress+"\n")
	house := write(t, dir, "house.env", "HOUSE_IF=eth2\nHOUSE_ADMIN_IP=10.78.0.20\nHOUSE_EGRESS="+egress+"\n")
	return load(t, Options{Net: lab, SegmentsDir: segs, HouseEnv: house}).Ruleset(e)
}

// NTP=redirect is the default: the line renders the same ruleset as no
// line. Without an NTP=pass segment, ntp_pass.ips renders nothing.
func TestNTPRedirectIsTheDefault(t *testing.T) {
	for _, mode := range []string{"strict", "audit", "open"} {
		nft := ntpPassRendered(t, mode, "", labElements)
		if ntpPassRendered(t, mode, "NTP=redirect\n", labElements) != nft {
			t.Errorf("%s: NTP=redirect changed the ruleset", mode)
		}
		if ntpPassRendered(t, mode, "", ntpPassElements) != nft {
			t.Errorf("%s: ntp_pass.ips changed a ruleset that has no NTP=pass segment", mode)
		}
		if strings.Contains(nft, "ntp_pass") || strings.Contains(nft, "4460") || strings.Contains(nft, "4123") {
			t.Errorf("%s: a ruleset without NTP=pass names the pass servers or ports", mode)
		}
	}
}

// NTP=pass on the desk: NTP to @ntp_pass_v4 is not redirected and not
// dropped. NTP to each other address still goes to the gateway. The gate
// lets only the time ports to the set through. The blacklist still runs
// first. The guest and the house in the same render, and the agent, do not
// change.
func TestNTPPassSegment(t *testing.T) {
	for _, mode := range []string{"strict", "audit", "open"} {
		t.Run(mode, func(t *testing.T) {
			nft := ntpPassRendered(t, mode, "NTP=pass\n", ntpPassElements)
			set := "\n  set ntp_pass_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { 162.159.200.1, 216.239.35.4 }\n  }\n"
			if n := strings.Count(nft, set); n != 1 {
				t.Errorf("%d ntp_pass_v4 sets with the elements, want 1", n)
			}
			mustHave(t, "prerouting", chain(t, nft, "prerouting"),
				`iifname "eth3" udp dport 123 ip daddr != 10.79.0.1 ip daddr != @ntp_pass_v4 counter dnat ip to 10.79.0.1`,
				`iifname "eth2" udp dport 123 ip daddr != 10.78.0.1 counter dnat ip to 10.78.0.1`,
				`iifname "eth4" udp dport 123 ip daddr != 10.80.0.1 counter dnat ip to 10.80.0.1`)
			gate := chain(t, nft, "resolver_gate")
			order(t, gate, "resolver_gate",
				`iifname "eth3" udp dport 123 accept`,
				`iifname "eth3" udp dport { 123, 4123 } ip daddr @ntp_pass_v4 accept`,
				`iifname "eth3" tcp dport 4460 ip daddr @ntp_pass_v4 accept`,
				`iifname "eth3" meta l4proto { tcp, udp } th dport != 53 ct state new`)
			fwd := chain(t, nft, "forward")
			order(t, fwd, "forward",
				`iifname "eth3" meta nfproto ipv6 counter drop`,
				`iifname "eth3" udp dport 123 ip daddr != @ntp_pass_v4 counter drop`,
				`iifname "eth3" udp dport 53 reject`)
			for _, i := range []string{"eth2", "eth4"} {
				mustHave(t, "forward", fwd, `iifname "`+i+`" udp dport 123 counter drop`)
			}
			order(t, chain(t, nft, "filter_prerouting"), "filter_prerouting",
				`iifname "eth3" meta nfproto ipv6 counter drop`,
				`iifname "eth3" ip daddr @blacklist_v4 counter drop`,
				`iifname "eth3" meta l4proto { tcp, udp } th dport 53 accept`)
			order(t, chain(t, nft, "input"), "input",
				`iifname "eth3" ip daddr 10.79.0.1 udp dport 123 accept`, `iifname "eth3" counter drop`)
			// Each rule that names the set is a rule of the desk: in its
			// gate, nat, forward or egress chain. A pass port is never open
			// to an address outside the set.
			eg := ""
			if mode != "open" {
				eg = chain(t, nft, "seg_desk_egress")
			}
			for _, l := range strings.Split(nft, "\n") {
				l = strings.TrimSpace(l)
				if strings.Contains(l, "@ntp_pass_v4") && !strings.HasPrefix(l, `iifname "eth3" `) && !strings.Contains(eg, "\n    "+l+"\n") {
					t.Errorf("a rule outside the desk names ntp_pass_v4: %s", l)
				}
				if regexp.MustCompile(`\b(4123|4460)\b`).MatchString(l) && !strings.Contains(l, "ip daddr @ntp_pass_v4") {
					t.Errorf("a pass port without the set: %s", l)
				}
			}
			for _, name := range []string{"filter_prerouting", "resolver_gate", "prerouting", "input", "forward"} {
				for _, l := range strings.Split(chain(t, nft, name), "\n") {
					if strings.Contains(l, `iifname "eth0"`) && (strings.Contains(l, "123") || strings.Contains(l, "4460") || strings.Contains(l, "ntp_pass")) {
						t.Errorf("%s has a time rule for the agent: %s", name, strings.TrimSpace(l))
					}
				}
			}
		})
	}
}

// Under strict, the egress chain of an NTP=pass desk returns the time
// ports to @ntp_pass_v4 only, after the mail ports and before ping and the
// log. Under audit they return before the audit log, so the log never
// names them. The guest and the house chains have no time port.
func TestNTPPassEgress(t *testing.T) {
	times := []string{"udp dport { 123, 4123 } ip daddr @ntp_pass_v4 return", "tcp dport 4460 ip daddr @ntp_pass_v4 return"}
	for _, mode := range []string{"strict", "audit"} {
		t.Run(mode, func(t *testing.T) {
			nft := ntpPassRendered(t, mode, "NTP=pass\nALLOW_PORTS=\"tcp:5000\"\n", ntpPassElements)
			eg := chain(t, nft, "seg_desk_egress")
			want := append([]string{"tcp dport { " + houseSTARTTLSPorts + " } return"}, times...)
			want = append(want, "icmp type echo-request", "tcp dport { 5000 } return", `log prefix "pi-fortress desk-`+map[string]string{"strict": "port", "audit": "audit"}[mode]+`: "`)
			order(t, eg, "seg_desk_egress", want...)
			for _, w := range times {
				if n := strings.Count(eg, w); n != 1 {
					t.Errorf("%d of %q, want 1", n, w)
				}
			}
			port := regexp.MustCompile(`\b(123|4123|4460)\b`)
			for _, c := range []string{"seg_guest_egress", "house_egress"} {
				if body := chain(t, nft, c); port.MatchString(body) {
					t.Errorf("%s has a time port:\n%s", c, body)
				}
			}
		})
	}
	if nft := ntpPassRendered(t, "open", "NTP=pass\n", ntpPassElements); strings.Contains(nft, "seg_desk_egress") {
		t.Error("EGRESS=open with NTP=pass renders a port policy")
	}
}

// An empty ntp_pass.ips still declares the set, so the rules that name it
// load. Nothing then matches it: all NTP of the segment goes to the gateway.
func TestNTPPassEmptyList(t *testing.T) {
	nft := ntpPassRendered(t, "strict", "NTP=pass\n", labElements)
	if !strings.Contains(nft, "\n  set ntp_pass_v4 {\n    type ipv4_addr\n    flags interval\n  }\n") {
		t.Fatal("NTP=pass with an empty ntp_pass.ips has no empty set")
	}
	mustHave(t, "prerouting", chain(t, nft, "prerouting"),
		`iifname "eth3" udp dport 123 ip daddr != 10.79.0.1 ip daddr != @ntp_pass_v4 counter dnat ip to 10.79.0.1`)
}

// BLOCK_DIRECT_IP=off has no gate, so NTP=pass adds nothing there. The
// redirect, the forward drop and the egress returns still use the set.
func TestNTPPassWithoutTheGate(t *testing.T) {
	nft := ntpPassRendered(t, "strict", "NTP=pass\nBLOCK_DIRECT_IP=off\n", ntpPassElements)
	if gate := chain(t, nft, "resolver_gate"); strings.Contains(gate, `iifname "eth3"`) {
		t.Errorf("BLOCK_DIRECT_IP=off still has a gate rule for the desk:\n%s", gate)
	}
	mustHave(t, "forward", chain(t, nft, "forward"), `iifname "eth3" udp dport 123 ip daddr != @ntp_pass_v4 counter drop`)
	mustHave(t, "seg_desk_egress", chain(t, nft, "seg_desk_egress"), "tcp dport 4460 ip daddr @ntp_pass_v4 return")
}

// A value other than redirect or pass refuses the render with the file and
// the line.
func TestNTPBadValueRefuses(t *testing.T) {
	for _, v := range []string{"", "on", "off", "nts", "Pass", "redirect pass"} {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		if err := os.Mkdir(segs, 0755); err != nil {
			t.Fatal(err)
		}
		file := write(t, segs, "desk.env", deskBase+"NTP="+v+"\n")
		_, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent"})
		if err == nil || !strings.Contains(err.Error(), file+":5: NTP is not redirect or pass") {
			t.Errorf("NTP=%q: %v", v, err)
		}
	}
}
