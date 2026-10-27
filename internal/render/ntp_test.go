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
