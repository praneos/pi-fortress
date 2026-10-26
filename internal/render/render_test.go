package render

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

var lab = Net{AgentNet: "10.77.0.0/24", PiIP: "10.77.0.1", AgentIP: "10.77.0.10", DNSUpstream: "9.9.9.9"}

// labFwd is lab pinned to AGENT_DNS=forward, for the tests of the
// forward-mode agent gate (@resolved_v4) and of the raw TCP 22 drop that it
// keeps whole. lab itself renders the default, fakeip.
var labFwd = func() Net { n := lab; n.AgentDNS = AgentDNSForward; return n }()

var labElements = Elements{Blacklist: "elements = { 203.0.113.9 }", DoH: "elements = { 198.51.100.7 }", DirectIP: "elements = { 203.0.113.64/26 }"}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, o Options) *Config {
	t.Helper()
	c, err := Load(o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestNoHouseMatchesGolden(t *testing.T) {
	golden, err := os.ReadFile("../../vm/pi/testdata/nft.no-house.golden")
	if err != nil {
		t.Fatal(err)
	}
	c := load(t, Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
	if got := c.Ruleset(labElements); got != string(golden) {
		t.Fatalf("no-house render drifted from the golden:\n%s", got)
	}
	if c.DoTAuthName != "" || c.DoTIPs != "" {
		t.Fatal("DoT is configured without the keys being set")
	}
	if c.IntIF != "eth0" || c.WanIF != "wlan0" {
		t.Fatalf("defaults: %s %s", c.IntIF, c.WanIF)
	}
}

// UDP DNS to the Pi is untracked on each segment. The query is below the
// spoof checks and above the port 53 accept of the house that ends raw
// prerouting. The answer is in raw output. The accept of the answer is
// above the pf-dns drop that pins the DoT stub.
func TestDNSNoTrack(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9"
	nft := load(t, Options{Net: net, HouseEnv: house, SegmentsDir: segs, IntIF: "eth0.20"}).Ruleset(labElements)
	var pre, out, reply []string
	for _, i := range []string{"eth0.20", "eth1", "eth0.79"} {
		pre = append(pre, `iifname "`+i+`" udp dport 53 fib daddr type local notrack`)
		out = append(out, `oifname "`+i+`" meta skuid "pf-dns" udp sport 53 notrack`)
		reply = append(reply, `oifname "`+i+`" meta skuid "pf-dns" udp sport 53 ct state untracked accept`)
	}
	j := func(l []string) string { return strings.Join(l, "\n    ") }
	order := []string{
		`iifname "eth0.79" ip saddr != 10.79.0.0/30 counter drop`,
		j(pre),
		`iifname "eth1" meta l4proto { tcp, udp } th dport 53 accept`,
		"chain raw_output {\n    type filter hook output priority raw; policy accept;\n    " + j(out) + "\n  }",
		"    ct state established,related accept\n    " + j(reply) + "\n    oifname \"lo\" accept",
		`meta skuid "pf-dns" counter drop`,
	}
	at := 0
	for _, w := range order {
		i := strings.Index(nft[at:], w)
		if i < 0 {
			t.Fatalf("missing or out of order: %s", w)
		}
		at += i + len(w)
	}
	for _, w := range slices.Concat(pre, out, reply) {
		if strings.Count(nft, w) != 1 {
			t.Errorf("want exactly one %q", w)
		}
	}
	for _, line := range strings.Split(nft, "\n") {
		if strings.Contains(line, "untracked") || strings.Contains(line, "notrack") {
			if strings.Contains(line, `"wlan0"`) || strings.Contains(line, `"wg0"`) {
				t.Errorf("the uplink or the tunnel is in the untracked DNS set: %s", line)
			}
		}
	}
}

func TestHouseSegmentsAndDoT(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.20\nWG_IF=wg0\n")
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\n")
	write(t, segs, "guest.env", "IF=eth2\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9 149.112.112.112"
	c := load(t, Options{Net: net, HouseEnv: house, SegmentsDir: segs, IntIF: "eth0.20"})
	nft := c.Ruleset(labElements)
	for _, want := range []string{
		`iifname "eth1" meta l4proto { tcp, udp } th dport 53 accept` + "\n" +
			`    iifname "eth1" ip daddr @dns_bypass_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress house-doh: " level info` + "\n" + `    iifname "eth1" ip daddr @dns_bypass_v4 counter drop`,
		`iifname "eth1" udp dport 853 limit rate 10/second burst 20 packets log prefix "pi-fortress house-doh: " level info` + "\n" + `    iifname "eth1" udp dport 853 counter drop`,
		`iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress house-directip: " level info` + "\n" +
			`    iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop`,
		`iifname "eth1" ip daddr @vpn_bypass_v4 meta mark set 0x1`,
		`iifname "eth1" oifname "wlan0" meta mark 0x1 counter accept`,
		`iifname "eth1" oifname "eth0.20" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept`,
		`iifname "eth0.79" oifname "eth0.20" ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept`,
		`iifname "eth0.79" oifname "eth2" counter drop`,
		`iifname "eth2" oifname "eth0.79" counter drop`,
		`ip saddr 10.78.0.0/24 oifname "wg0" counter masquerade`,
		`ip saddr 10.80.0.0/24 oifname "wlan0" counter masquerade`,
		`meta skuid "pf-broker" counter drop` + "\n" + `    meta skuid "pf-dns" ip daddr { 9.9.9.9, 149.112.112.112 } tcp dport 853 accept`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n%s", want)
		}
	}
	// Trunk drop first, then the tunnel kill-switch for flows admitted
	// before the tunnel, then the conntrack accept.
	order(t, chain(t, nft, "forward"), "forward",
		`iifname "eth0" counter drop`,
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 counter drop`,
		"ct state established,related accept",
	)
	if strings.Count(nft, `iifname "eth0" counter drop`) != 2 {
		t.Error("trunk drop must open input and forward, nowhere else")
	}
	if c.DNSForward != DoTAddr || c.HouseDNSForward != "10.64.0.1@wg0" {
		t.Errorf("forwards: %s %s", c.DNSForward, c.HouseDNSForward)
	}
	if got := strings.Join(c.VLANParents, ","); got != "eth0" {
		t.Errorf("VLAN parents: %s", got)
	}
	// The two keys stay after the parse. The stub unit is built from them, and
	// they cannot come from a second place.
	if c.DoTAuthName != "dns.quad9.net" || len(strings.Fields(c.DoTIPs)) != 2 {
		t.Errorf("DoT keys: name=%q ips=%q", c.DoTAuthName, c.DoTIPs)
	}
	env := c.EnvFile()
	for _, want := range []string{
		"INT_IF='eth0.20'\n", "HOUSE_DNS_EXPLICIT='0'\n", "WG_BYPASS_MARK='0x1'\n",
		"DOT_IPS='9.9.9.9 149.112.112.112'\n", "SEG_NAME=('desk' 'guest')\n", "SEG_SSH_TO=('10.77.0.10-10.77.0.12' '')\n",
		"VLAN_PARENTS='eth0 '\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("apply.env lacks %q:\n%s", want, env)
		}
	}
}

// TestHouseWebToggles: HOUSE_BLOCK_DIRECT_IP and HOUSE_BLOCK_HTTP. Unset
// renders what the house always had. Each value changes only its own rules.
func TestHouseWebToggles(t *testing.T) {
	dir := t.TempDir()
	render := func(extra string) string {
		house := write(t, dir, "house.env", "HOUSE_IF=eth1\n"+extra)
		return load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	}
	const gate = `iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4`
	const gate443 = `iifname "eth1" tcp dport { 443, 465, 993, 5223, 5228, 8443 } ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @reserved_v4 ct mark set ct mark and 0xff0fffff or 0x00100000`
	const httpLog = `iifname "eth1" tcp dport 80 limit rate 10/second burst 20 packets log prefix "pi-fortress house-http: " level info`
	const httpReject = `iifname "eth1" tcp dport 80 counter reject with tcp reset`

	base := render("")
	if on := render("HOUSE_BLOCK_DIRECT_IP=on\nHOUSE_BLOCK_HTTP=off\n"); on != base {
		t.Error("the default values render differently from unset")
	}
	// On a miss, 80 is logged and dropped. Each new TLS flow is marked
	// for the SNI check (strict egress, the default).
	if strings.Count(base, gate) != 2 || strings.Count(base, gate443) != 1 || strings.Contains(base, "house-http") {
		t.Errorf("default house gate changed:\n%s", chain(t, base, "resolver_gate"))
	}

	off := render("HOUSE_BLOCK_DIRECT_IP=off\n")
	if strings.Contains(off, "house-directip") || strings.Contains(off, "ct state new ip daddr != 10.78.0.1") || strings.Contains(off, "queue num") {
		t.Errorf("HOUSE_BLOCK_DIRECT_IP=off left the gate:\n%s", chain(t, off, "resolver_gate"))
	}
	if !strings.Contains(off, "set resolved_house_v4 {") {
		t.Error("the resolved set dnsmasq writes to must stay with the gate off")
	}

	http := render("HOUSE_BLOCK_HTTP=on\n")
	if strings.Count(http, gate443) != 1 || strings.Contains(http, gate) {
		t.Errorf("with HTTP blocked the gate keeps only 443:\n%s", chain(t, http, "resolver_gate"))
	}
	fwd := chain(t, http, "forward")
	order(t, fwd, "forward", `iifname "eth1" tcp dport 53 reject with tcp reset`, httpLog, httpReject, `iifname "eth1" oifname "wlan0" accept`)

	both := render("HOUSE_BLOCK_DIRECT_IP=off\nHOUSE_BLOCK_HTTP=on\n")
	if strings.Contains(both, "house-directip") || !strings.Contains(both, httpReject) {
		t.Error("the two toggles are not independent")
	}

	wg := render("HOUSE_BLOCK_HTTP=on\nWG_IF=wg0\n")
	order(t, chain(t, wg, "forward"), "forward", httpReject, `iifname "eth1" oifname "wlan0" meta mark 0x1 counter accept`, `iifname "eth1" oifname "wg0" accept`)

	for _, v := range []string{"HOUSE_BLOCK_DIRECT_IP=no\n", "HOUSE_BLOCK_HTTP=1\n"} {
		house := write(t, dir, "house.env", "HOUSE_IF=eth1\n"+v)
		if _, err := Load(Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "is not on or off") {
			t.Errorf("%q: got %v", v, err)
		}
	}
}

// TestHouseSSHToWidensTheAgentDestinationButKeepsTheAdminPin: the one
// house->agent ssh hole was hardcoded to AgentIP, the first agent. Thus,
// when AGENT_COUNT gave three VMs, the admin machine could not reach
// agent2 or agent3. HOUSE_SSH_TO widens the destination. The ip saddr pin
// on HouseAdminIP does not change. When HOUSE_SSH_TO is unset, the render
// must be byte-for-byte what an existing house.env always has.
func TestHouseSSHToWidensTheAgentDestinationButKeepsTheAdminPin(t *testing.T) {
	dir := t.TempDir()
	render := func(extra string) string {
		house := write(t, dir, "house.env", "HOUSE_IF=eth1\n"+extra)
		return load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	}
	const oldHole = `iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept`

	unset := render("HOUSE_ADMIN_IP=10.78.0.20\n")
	if !strings.Contains(unset, oldHole) {
		t.Fatalf("HOUSE_SSH_TO unset changed today's single-AgentIP hole:\n%s", chain(t, unset, "forward"))
	}

	wide := render("HOUSE_ADMIN_IP=10.78.0.20\nHOUSE_SSH_TO=10.77.0.10-10.77.0.12\n")
	if strings.Contains(wide, oldHole) {
		t.Error("HOUSE_SSH_TO set still rendered the old single-AgentIP hole")
	}
	if !strings.Contains(wide, `iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept`) {
		t.Errorf("HOUSE_SSH_TO did not widen the destination:\n%s", chain(t, wide, "forward"))
	}

	// The "&&" guard: HOUSE_SSH_TO alone, without HOUSE_ADMIN_IP, must not
	// open a hole. This key only widens the destination of the existing pin.
	// It never opens one alone.
	noAdmin := render("HOUSE_SSH_TO=10.77.0.10-10.77.0.12\n")
	if strings.Contains(noAdmin, "ip daddr 10.77.0.10-10.77.0.12 tcp dport 22") {
		t.Error("HOUSE_SSH_TO without HOUSE_ADMIN_IP rendered a hole")
	}
}

func TestSSHAllowAcceptsSitAboveTheTCP22Drops(t *testing.T) {
	e := labElements
	e.SSHAllow = "elements = { 203.0.113.64/26 }"
	c := load(t, Options{Net: labFwd, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
	nft := c.Ruleset(e)
	if !strings.Contains(nft, "set ssh_allow_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { 203.0.113.64/26 }\n  }") {
		t.Fatalf("set ssh_allow_v4 missing or malformed:\n%s", nft)
	}
	raw := chain(t, nft, "filter_prerouting")
	order(t, raw, "filter_prerouting",
		`iifname "eth0" ip daddr @blacklist_v4 counter drop`,
		`iifname "eth0" ip daddr @dns_bypass_v4 counter drop`,
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 accept`,
		`iifname "eth0" tcp dport 22 counter drop`)
	fwd := chain(t, nft, "forward")
	order(t, fwd, "forward",
		"ct state established,related accept",
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 ct state new limit rate 30/minute burst 60 packets log prefix "pi-fortress ssh-allow: " level info counter accept`,
		`iifname "eth0" tcp dport 22 counter drop`)
	if a, b := index(fwd, `@ssh_allow_v4`), index(fwd, `tcp dport 22 counter drop`); b-a != 1 {
		t.Errorf("forward accept is not immediately before the 22 drop: %d %d", a, b)
	}
	for _, l := range strings.Split(chain(t, nft, "input"), "\n") {
		if strings.Contains(l, `iifname "eth0"`) && strings.Contains(l, "dport 22") {
			t.Errorf("the agent may not SSH the Pi itself: %s", l)
		}
	}
	if strings.Contains(c.Ruleset(labElements), "ssh_allow_v4") {
		t.Error("an empty list still emitted the set or an accept")
	}
}

// The DNS flood meters must come before the conntrack accept. A client
// that keeps one UDP socket is one flow. After the first reply, each later
// query on it is established and would never reach a meter.
func TestDNSFloodMetersPrecedeConntrackAccept(t *testing.T) {
	house := write(t, t.TempDir(), "house.env", "HOUSE_IF=eth1\n")
	c := load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"})
	order(t, chain(t, c.Ruleset(labElements), "input"), "input",
		`iifname "eth0" tcp dport 53 meter agent_dnsflood_tcp`,
		`iifname "eth0" udp dport 53 meter agent_dnsflood_udp`,
		`iifname "eth1" tcp dport 53 meter house_dnsflood_tcp`,
		`iifname "eth1" udp dport 53 meter house_dnsflood_udp`,
		"ct state established,related accept",
		`iifname "eth0" udp dport 53 accept`,
		`iifname "eth1" udp dport 53 accept`)
}

func TestSSHAllowLeavesTheHouseAndDeskHolesAlone(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.20\n")
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\n")
	c := load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: segs})
	e := labElements
	e.SSHAllow = "elements = { 203.0.113.64/26 }"
	nft := c.Ruleset(e)
	for _, want := range []string{
		`iifname "eth1" ip saddr 10.78.0.20 tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept`,
		`iifname "eth1" oifname "eth0" ip saddr 10.78.0.20 ip daddr 10.77.0.10 tcp dport 22 ct state new accept`,
		`iifname "eth0.79" oifname "eth0" ip daddr 10.77.0.10-10.77.0.12 tcp dport 22 ct state new accept`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("the other direction changed:\n%s", want)
		}
	}
	fwd := chain(t, nft, "forward")
	order(t, fwd, "forward",
		`iifname "eth0" oifname "eth1" counter drop`,
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 ct state new`)
}

// chain returns the body of one nft chain, without its header line.
func chain(t *testing.T, nft, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(nft, "\n  chain "+name+" {\n")
	if !ok {
		t.Fatalf("chain %s not rendered", name)
	}
	body, _, ok := strings.Cut(rest, "\n  }\n")
	if !ok {
		t.Fatalf("chain %s never closed", name)
	}
	return body
}

func index(body, want string) int {
	for i, l := range strings.Split(body, "\n") {
		if strings.Contains(l, want) {
			return i
		}
	}
	return -1
}

func order(t *testing.T, body, name string, want ...string) {
	t.Helper()
	prev := -1
	for _, w := range want {
		i := index(body, w)
		if i < 0 {
			t.Fatalf("%s lacks %q:\n%s", name, w, body)
		}
		if i <= prev {
			t.Fatalf("%s has %q out of order at line %d:\n%s", name, w, i, body)
		}
		prev = i
	}
}

func TestExplicitHouseDNSStaysOffTheStub(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_DNS_UPSTREAM=1.1.1.1\n")
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9"
	// Without a tunnel, the plaintext forward would leave on the WAN, where
	// the DoT output pins drop it. Thus it is refused, not rendered dead.
	if _, err := Load(Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "plaintext forward") {
		t.Errorf("plaintext house forward under DoT: got %v", err)
	}
	write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_DNS_UPSTREAM=1.1.1.1\nWG_IF=wg0\n")
	c := load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if c.DNSForward != DoTAddr {
		t.Errorf("agent forward: %s", c.DNSForward)
	}
	if c.HouseDNSForward != "1.1.1.1@wg0" {
		t.Errorf("house forward through the tunnel: %s", c.HouseDNSForward)
	}
}

// The DoT output pins and a WireGuard house almost cancel each other. The
// pins drop plaintext 53 on all interfaces except lo. The house forwards
// plaintext 53 to the resolver of the tunnel. It does this as dnsmasq under
// its own user, not as pf-dns, and out WG_IF, not lo, because routing
// selected the tunnel long before chain output sees the packet. One
// carve-out must keep the two properties true.
func TestWireGuardHouseResolvesThroughTheTunnelUnderDoT(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9"
	c := load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if c.HouseDNSForward != "10.64.0.1@wg0" {
		t.Fatalf("house forward: %s", c.HouseDNSForward)
	}
	out := chain(t, c.Ruleset(labElements), "output")
	// pf dns resolves for the house. Thus its tunnel accept must come before
	// the pf-dns drop. Below it (the order of the dnsmasq era), each tunnelled
	// house lookup was dropped. The scope is pf-dns, one address, one
	// interface: no other process gets a plaintext exit.
	order(t, out, "output",
		`meta skuid "pf-dns" ip daddr { 9.9.9.9 } tcp dport 853 accept`,
		`meta skuid "pf-dns" ip daddr 10.64.0.1 udp dport 53 oifname "wg0" accept`,
		`meta skuid "pf-dns" ip daddr 10.64.0.1 tcp dport 53 oifname "wg0" accept`,
		`meta skuid "pf-dns" counter drop`,
		`udp dport 53 oifname != "lo" counter drop`,
		`tcp dport 53 oifname != "lo" counter drop`,
	)
	// The carve-out is only the tunnel. A rule that names the uplink here
	// would be the leak that the pins exist to stop.
	if strings.Contains(out, `dport 53 oifname "wlan0"`) {
		t.Errorf("plaintext 53 is accepted on the uplink:\n%s", out)
	}
	// An explicit upstream uses the same tunnel. Thus the accept must
	// follow the forward, and not hardcode the resolver of Mullvad.
	write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\nHOUSE_DNS_UPSTREAM=1.1.1.1\n")
	c = load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if out = chain(t, c.Ruleset(labElements), "output"); !strings.Contains(out, `meta skuid "pf-dns" ip daddr 1.1.1.1 udp dport 53 oifname "wg0" accept`) {
		t.Errorf("the accept does not follow HOUSE_DNS_UPSTREAM=%s:\n%s", c.HouseDNSForward, out)
	}
	// The DoT provider of the house also uses the tunnel. The house forwards
	// to its stub, which apply binds to WG_IF. Thus the tunnel needs no
	// plaintext 53 carve-out at all, and the pins of the stub join the uid
	// accept on 853.
	write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\nHOUSE_DOT_AUTH_NAME=abc123.dns.controld.com\nHOUSE_DOT_IPS=\"76.76.2.22 76.76.10.22\"\n")
	c = load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if c.HouseDNSForward != HouseDoTAddr {
		t.Fatalf("house forward under WireGuard with its own DoT: %s, want %s", c.HouseDNSForward, HouseDoTAddr)
	}
	out = chain(t, c.Ruleset(labElements), "output")
	if strings.Contains(out, `dport 53 oifname "wg0" accept`) {
		t.Errorf("a DoT house kept the plaintext tunnel carve-out:\n%s", out)
	}
	if !strings.Contains(out, `meta skuid "pf-dns" ip daddr { 9.9.9.9, 76.76.2.22, 76.76.10.22 } tcp dport 853 accept`) {
		t.Errorf("the house stub's pins are not in the 853 accept:\n%s", out)
	}
	// No tunnel, no carve-out. A house without WG_IF shares the stub of the
	// agents over lo, and must not get a plaintext exit at any location.
	write(t, dir, "house.env", "HOUSE_IF=eth1\n")
	c = load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if out = chain(t, c.Ruleset(labElements), "output"); strings.Contains(out, "dport 53 oifname \"") {
		t.Errorf("a house with no tunnel gained a plaintext 53 accept:\n%s", out)
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	cases := []struct {
		name, house, seg, want string
		net                    Net
		intIF, wanIF           string
	}{
		{name: "metachar", house: "HOUSE_IF=eth0;reboot\n", want: "house.env:1: HOUSE_IF is not an interface name"},
		{name: "unknown key", house: "PATH=/tmp\n", want: "unknown key 'PATH'"},
		{name: "no equals", house: "# c\n\nreboot\n", want: "house.env:3: not KEY=VALUE"},
		{name: "bad cidr", house: "HOUSE_NET=10.78.0.0\n", want: "HOUSE_NET is not an IPv4 CIDR"},
		{name: "house plaintext under dot", house: "HOUSE_IF=eth1\nHOUSE_DNS_UPSTREAM=76.76.2.2\n", net: Net{DoTAuthName: "abc123.dns.controld.com", DoTIPs: "76.76.2.22 76.76.10.22"}, want: "HOUSE_DNS_UPSTREAM=76.76.2.2 is a plaintext forward"},
		// Retired key: a stale house.env of an operator must fail the apply and
		// name the key. The apply must not silently ignore it and change the posture.
		{name: "dev mode renamed", house: "HOUSE_DEV_MODE=on\n", want: "HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS"},
		{name: "dev mode renamed, off", house: "HOUSE_DEV_MODE=off\n", want: "HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS"},
		{name: "private dns", house: "HOUSE_PRIVATE_DNS=yes\n", want: "HOUSE_PRIVATE_DNS is not on or off"},
		{name: "fwmark", house: "WG_BYPASS_MARK=1\n", want: "WG_BYPASS_MARK is not a hex fwmark"},
		{name: "house on agent", house: "HOUSE_IF=eth0\n", want: "HOUSE_IF=eth0 collides with INT_IF=eth0 or WAN_IF=wlan0"},
		{name: "wg without house", house: "WG_IF=wg0\n", want: "WG_IF=wg0 requires HOUSE_IF"},
		{name: "wg on wan", house: "HOUSE_IF=eth1\nWG_IF=wlan0\n", want: "WG_IF=wlan0 collides with"},
		{name: "same interface", intIF: "wlan0", wanIF: "wlan0", want: "INT_IF and WAN_IF are both wlan0: 10.77.0.1 sits on the uplink"},
		{name: "dot half", net: Net{DoTAuthName: "dns.quad9.net"}, want: "set together or not at all"},
		{name: "dot name", net: Net{DoTAuthName: "quad9", DoTIPs: "9.9.9.9"}, want: "DOT_AUTH_NAME='quad9' is not a DNS name"},
		{name: "dot ip", net: Net{DoTAuthName: "dns.quad9.net", DoTIPs: "9.9.9.999"}, want: "DOT_IPS entry '9.9.9.999' is not an IPv4 address"},
		{name: "dot dup", net: Net{DoTAuthName: "dns.quad9.net", DoTIPs: "9.9.9.9 1.1.1.1 9.9.9.9"}, want: "DOT_IPS lists an address twice"},
		{name: "uplink value", net: Net{UntrustedUplink: "yes"}, want: "UNTRUSTED_UPLINK='yes' is not 0 or 1"},
		{name: "uplink no way in", net: Net{UntrustedUplink: "1"}, want: "the only way in would be a keyboard and screen on the Pi. Nothing was changed."},
		{name: "uplink house no admin", house: "HOUSE_IF=eth1\n", net: Net{UntrustedUplink: "1"}, want: "closes SSH on WAN_IF=wlan0"},
		{name: "uplink seg not admin", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=no\n", net: Net{UntrustedUplink: "1"}, want: "closes SSH on WAN_IF=wlan0"},
		{name: "seg name", seg: "Desk.env", want: "'Desk' is not a segment name"},
		{name: "seg required", seg: "one.env:IF=eth3\n", want: "one.env: IF, NET and IP are all required"},
		{name: "seg admin", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=maybe\n", want: "one.env:4: ADMIN is not yes or no"},
		{name: "seg ssh cidr", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.0/24\n", want: "SSH_TO is not an IPv4 address or a-b range"},
		{name: "seg on agent", seg: "one.env:IF=eth0\nNET=10.80.0.0/24\nIP=10.80.0.1\n", want: "segment one: IF=eth0 collides with INT_IF=eth0, WAN_IF=wlan0 or HOUSE_IF=none"},
		{name: "seg ip outside", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.81.0.1\n", want: "IP=10.81.0.1 is not inside NET=10.80.0.0/24"},
		{name: "seg ip network", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.0\n", want: "segment one: IP=10.80.0.0 is the network address of NET=10.80.0.0/24"},
		{name: "seg ip broadcast", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.255\n", want: "segment one: IP=10.80.0.255 is the broadcast address of NET=10.80.0.0/24"},
		{name: "house admin network", house: "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.0\n", want: "house: HOUSE_ADMIN_IP=10.78.0.0 is the network address of HOUSE_NET=10.78.0.0/24"},
		{name: "house admin broadcast", house: "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.255\n", want: "house: HOUSE_ADMIN_IP=10.78.0.255 is the broadcast address of HOUSE_NET=10.78.0.0/24"},
		{name: "house dhcp network", house: "HOUSE_IF=eth1\nHOUSE_IP=10.78.0.254\nHOUSE_DHCP_START=10.78.0.0\nHOUSE_DHCP_END=10.78.0.50\n", want: "covers 10.78.0.0, the network address of HOUSE_NET=10.78.0.0/24"},
		{name: "house dhcp broadcast", house: "HOUSE_IF=eth1\nHOUSE_DHCP_START=10.78.0.200\nHOUSE_DHCP_END=10.78.0.255\n", want: "covers 10.78.0.255, the broadcast address of HOUSE_NET=10.78.0.0/24"},
		{name: "seg overlaps agent", seg: "one.env:IF=eth3\nNET=10.77.0.0/25\nIP=10.77.0.1\n", want: "NET=10.77.0.0/25 overlaps AGENT_NET=10.77.0.0/24"},
		{name: "seg overlaps house", house: "HOUSE_IF=eth1\n", seg: "one.env:IF=eth3\nNET=10.78.0.128/25\nIP=10.78.0.129\n", want: "overlaps HOUSE_NET=10.78.0.0/24"},
		{name: "seg ssh outside", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.10-10.78.0.5\n", want: "SSH_TO=10.77.0.10-10.78.0.5 is outside AGENT_NET"},
		{name: "seg ssh backwards", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nSSH_TO=10.77.0.12-10.77.0.10\n", want: "SSH_TO=10.77.0.12-10.77.0.10: 10.77.0.12 is above 10.77.0.10"},
		{name: "house ssh cidr", house: "HOUSE_IF=eth1\nHOUSE_SSH_TO=10.77.0.0/24\n", want: "HOUSE_SSH_TO is not an IPv4 address or a-b range"},
		{name: "house ssh outside", house: "HOUSE_IF=eth1\nHOUSE_SSH_TO=10.77.0.10-10.78.0.5\n", want: "HOUSE_SSH_TO=10.77.0.10-10.78.0.5 is outside AGENT_NET"},
		{name: "house ssh backwards", house: "HOUSE_IF=eth1\nHOUSE_SSH_TO=10.77.0.12-10.77.0.10\n", want: "HOUSE_SSH_TO=10.77.0.12-10.77.0.10: 10.77.0.12 is above 10.77.0.10"},
		{name: "segs share if", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n|two.env:IF=eth3\nNET=10.81.0.0/24\nIP=10.81.0.1\n", want: "segments two and one share IF=eth3"},
		{name: "segs overlap", seg: "one.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n|two.env:IF=eth4\nNET=10.80.0.0/25\nIP=10.80.0.1\n", want: "segments two and one overlap on 10.80.0.0/25"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.RemoveAll(segs)
			os.Mkdir(segs, 0755)
			house := "/nonexistent/house.env"
			if tc.house != "" {
				house = write(t, dir, "house.env", tc.house)
			}
			for _, f := range strings.Split(tc.seg, "|") {
				if name, body, ok := strings.Cut(f, ":"); ok {
					write(t, segs, name, body)
				} else if f != "" {
					write(t, segs, f, "IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
				}
			}
			net := lab
			net.DoTAuthName, net.DoTIPs = tc.net.DoTAuthName, tc.net.DoTIPs
			net.UntrustedUplink = tc.net.UntrustedUplink
			_, err := Load(Options{Net: net, HouseEnv: house, SegmentsDir: segs, IntIF: tc.intIF, WanIF: tc.wanIF})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A /31 has no network or broadcast address (RFC 3021), and a /32 is one
// address. Thus IP may be the first or the last address of such a NET.
func TestSegmentIPOnPointToPointNet(t *testing.T) {
	for _, seg := range []string{"NET=10.80.0.0/31\nIP=10.80.0.0\n", "NET=10.80.0.0/31\nIP=10.80.0.1\n", "NET=10.80.0.7/32\nIP=10.80.0.7\n"} {
		segs := filepath.Join(t.TempDir(), "segments.d")
		os.Mkdir(segs, 0755)
		write(t, segs, "one.env", "IF=eth3\n"+seg)
		if _, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs}); err != nil {
			t.Errorf("%q refused: %v", seg, err)
		}
	}
}

// On a /31 the address that is not IP is a host address too. Thus a DHCP
// range may lease it, and a reservation may hold it. A range that covers
// IP is still refused.
func TestSegmentDHCPOnPointToPointNet(t *testing.T) {
	for _, tc := range []struct{ seg, want string }{
		{"NET=10.80.0.0/31\nIP=10.80.0.0\nDHCP=on\nDHCP_START=10.80.0.1\nDHCP_END=10.80.0.1\n", ""},
		{"NET=10.80.0.0/31\nIP=10.80.0.1\nDHCP=on\nDHCP_START=10.80.0.0\nDHCP_END=10.80.0.0\n", ""},
		{"NET=10.80.0.0/31\nIP=10.80.0.1\nDHCP=on\nDHCP_START=10.80.0.0\nDHCP_END=10.80.0.1\n", "covers IP"},
		{"NET=10.80.0.0/30\nIP=10.80.0.1\nDHCP=on\nDHCP_START=10.80.0.2\nDHCP_END=10.80.0.3\n", "broadcast"},
	} {
		segs := filepath.Join(t.TempDir(), "segments.d")
		os.Mkdir(segs, 0755)
		write(t, segs, "one.env", "IF=eth3\n"+tc.seg)
		_, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs})
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%q: got %v, want %q", tc.seg, err, tc.want)
		}
	}
	p2p := "IF=eth2.30\nNET=10.30.0.0/31\nIP=10.30.0.0\nDHCP=on\nDHCP_START=10.30.0.1\nDHCP_END=10.30.0.1\n"
	if _, _, err := segHosts(t, p2p, "02:00:00:00:00:0a,10.30.0.1,cam\n"); err != nil {
		t.Errorf("a reservation of the host address of a /31 is refused: %v", err)
	}
}

// TestUntrustedUplink: docs/user_guide/public_wifi.md. The IPv6 drops are
// first in the two chains in all modes. 1 removes exactly the SSH and ping
// of the uplink, adds the name-broadcast drop, and does not change the other ways in.
func TestUntrustedUplink(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\n")
	render := func(mode, segs string) string {
		net := lab
		net.UntrustedUplink = mode
		return load(t, Options{Net: net, HouseEnv: house, SegmentsDir: segs}).Ruleset(labElements)
	}
	open, zero, shut := render("", "/nonexistent"), render("0", "/nonexistent"), render("1", "/nonexistent")
	if zero != open {
		t.Error("UNTRUSTED_UPLINK=0 renders differently from unset")
	}
	for _, nft := range []string{open, shut} {
		for name, want := range map[string]string{
			"input":  `iifname "wlan0" meta nfproto ipv6 counter drop`,
			"output": `oifname "wlan0" meta nfproto ipv6 counter drop`,
		} {
			if lines := strings.Split(chain(t, nft, name), "\n"); len(lines) < 2 || strings.TrimSpace(lines[1]) != want {
				t.Errorf("chain %s does not start with %q:\n%s", name, want, strings.Join(lines, "\n"))
			}
		}
	}

	lines := func(s string) map[string]bool {
		m := map[string]bool{}
		for l := range strings.SplitSeq(s, "\n") {
			m[strings.TrimSpace(l)] = true
		}
		return m
	}
	o, s := lines(open), lines(shut)
	var gone, added []string
	for l := range o {
		if !s[l] {
			gone = append(gone, l)
		}
	}
	for l := range s {
		if !o[l] {
			added = append(added, l)
		}
	}
	slices.Sort(gone)
	wantGone := []string{
		`iifname "wlan0" icmp type echo-request accept`,
		`iifname "wlan0" icmp type echo-request meter wan_ping { ip saddr limit rate over 10/second burst 20 packets } counter drop`,
		`iifname "wlan0" tcp dport 22 ct state new accept`,
		`iifname "wlan0" tcp dport 22 ct state new meter wan_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop`,
	}
	if !slices.Equal(gone, wantGone) {
		t.Errorf("UNTRUSTED_UPLINK=1 removed %q, want %q", gone, wantGone)
	}
	if want := []string{`oifname "wlan0" udp dport { 5353, 5355 } counter drop`}; !slices.Equal(added, want) {
		t.Errorf("UNTRUSTED_UPLINK=1 added %q, want %q", added, want)
	}
	in := chain(t, shut, "input")
	order(t, in, "input", `iifname "wlan0" udp sport 67 udp dport 68 accept`, `iifname "wlan0" counter drop`)
	if !strings.HasSuffix(in, `iifname "wlan0" counter drop`) {
		t.Errorf("the uplink drop is not the last input rule:\n%s", in)
	}
	if !o[`iifname "eth1" ip saddr 10.78.0.5 tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept`] {
		t.Error("the house admin SSH accept this test relies on moved")
	}

	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n")
	net := lab
	net.UntrustedUplink = "1"
	if _, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs}); err != nil {
		t.Errorf("an ADMIN=yes segment is a way in: %v", err)
	}
}

func TestNetHas(t *testing.T) {
	for _, tc := range []struct {
		cidr, ip string
		want     bool
	}{
		{"10.78.0.0/24", "10.78.0.200", true}, {"10.78.0.7/24", "10.78.0.200", true}, {"10.78.0.0/24", "10.78.1.1", false},
		{"0.0.0.0/0", "203.0.113.1", true}, {"10.0.0.1/32", "10.0.0.1", true}, {"10.0.0.1/32", "10.0.0.2", false},
	} {
		if got := netHas(tc.cidr, tc.ip); got != tc.want {
			t.Errorf("netHas(%s, %s) = %v", tc.cidr, tc.ip, got)
		}
	}
	if !netsOverlap("10.5.0.1/16", "10.5.9.0/24") || netsOverlap("10.5.0.0/16", "10.6.0.0/16") {
		t.Error("netsOverlap")
	}
}

func TestShellQuoting(t *testing.T) {
	if got := shq("a'b"); got != `'a'\''b'` {
		t.Errorf("shq: %s", got)
	}
}

// Paranoid removes the @direct_ip_v4 exemption from the agent gate. It
// does not move the house gate, the set or any other line.
func TestParanoidAgentGateDropsDirectCarve(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	opts := Options{Net: labFwd, HouseEnv: house, SegmentsDir: "/nonexistent"}
	par := opts
	par.Paranoid = true
	off := load(t, opts).Ruleset(labElements)
	on := load(t, par).Ruleset(labElements)
	matchOff := `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != @resolved_v4`
	matchOn := `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @resolved_v4`
	agentOff, agentOn := matchOff+" counter drop", matchOn+" counter drop"
	agentLog := matchOn + logRate + `"pi-fortress agent-directip: " level info`
	houseGate := `iifname "eth1" tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop`
	if !strings.Contains(off, agentOff) || !strings.Contains(on, agentOn) || strings.Contains(on, agentOff) {
		t.Fatalf("agent gate:\n%s", on)
	}
	for _, want := range []string{agentLog, houseGate, "set direct_ip_v4 {", "203.0.113.64/26"} {
		if !strings.Contains(on, want) {
			t.Fatalf("paranoid render lost %q", want)
		}
	}
	if strings.Count(off, matchOff) != 2 || strings.ReplaceAll(off, matchOff, matchOn) != on {
		t.Fatal("paranoid changed more than the agent gate and its log")
	}
	if e := load(t, par).EnvFile(); !strings.Contains(e, "PARANOID='1'") {
		t.Fatalf("apply.env: %s", e)
	}
	if e := load(t, opts).EnvFile(); !strings.Contains(e, "PARANOID='0'") {
		t.Fatalf("apply.env: %s", e)
	}
}

// The two features came from separate branches and splice into the same
// three lines of the template. When the two are armed together, each must
// still get exactly what its own test asserts alone.
func TestParanoidAndSSHAllowRenderTogether(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	e := labElements
	e.SSHAllow = "elements = { 203.0.113.64/26 }"
	opts := Options{Net: labFwd, HouseEnv: house, SegmentsDir: "/nonexistent"}
	par := opts
	par.Paranoid = true
	off := load(t, opts).Ruleset(e)
	on := load(t, par).Ruleset(e)

	matchOff := `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != @resolved_v4`
	matchOn := `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @resolved_v4`
	agentOff, agentOn := matchOff+" counter drop", matchOn+" counter drop"
	if !strings.Contains(on, agentOn) || strings.Contains(on, agentOff) {
		t.Fatalf("the ssh set did not leave the paranoid gate alone:\n%s", on)
	}
	if strings.Count(off, matchOff) != 2 || strings.ReplaceAll(off, matchOff, matchOn) != on {
		t.Fatal("with ssh_allow rendered, paranoid changed more than the agent gate")
	}
	order(t, chain(t, on, "filter_prerouting"), "filter_prerouting",
		`iifname "eth0" ip daddr @blacklist_v4 counter drop`,
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 accept`,
		`iifname "eth0" tcp dport 22 counter drop`)
	if !strings.Contains(chain(t, on, "resolver_gate"), agentOn) {
		t.Fatalf("resolver_gate:\n%s", chain(t, on, "resolver_gate"))
	}
	fwd := chain(t, on, "forward")
	order(t, fwd, "forward",
		"ct state established,related accept",
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 ct state new limit rate 30/minute burst 60 packets log prefix "pi-fortress ssh-allow: " level info counter accept`,
		`iifname "eth0" tcp dport 22 counter drop`)
	// Two sets are spliced at the same point. Neither set can take the
	// braces of the other.
	for _, want := range []string{
		"set ssh_allow_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { 203.0.113.64/26 }\n  }",
		"set direct_ip_v4 {",
		"set resolved_v4 {",
	} {
		if !strings.Contains(on, want) {
			t.Errorf("armed render lost %q", want)
		}
	}
	if strings.Count(on, "set ssh_allow_v4 {") != 1 {
		t.Error("ssh_allow_v4 rendered more than once")
	}
}

// The first 00000000 row in /proc/net/route is the row that the FIB hash
// put there, not the lowest metric. A Pi with a default route on Ethernet
// and on Wi-Fi must get the route that the kernel would use.
func TestDefaultRouteIFTakesTheLowestMetric(t *testing.T) {
	const hdr = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	row := func(ifc, dst, metric string) string {
		return ifc + "\t" + dst + "\t0100A00A\t0003\t0\t0\t" + metric + "\t00000000\t0\t0\t0\n"
	}
	eth, wlan := row("eth0", "00000000", "100"), row("wlan0", "00000000", "600")
	link := row("eth0", "0100A00A", "100")
	cases := []struct {
		name, table, want, wantErr string
	}{
		{name: "lower metric wins", table: hdr + wlan + eth, want: "eth0"},
		{name: "lower metric wins reversed", table: hdr + eth + wlan, want: "eth0"},
		{name: "single default", table: hdr + link + eth, want: "eth0"},
		{name: "metric is not the flags column", table: hdr + row("wlan0", "00000000", "0") + eth, want: "wlan0"},
		{name: "no default row", table: hdr + link},
		{name: "header only", table: hdr},
		{name: "empty file"},
		{name: "one device twice at one metric", table: hdr + eth + eth, want: "eth0"},
		{name: "short lines skipped", table: hdr + "eth9\t00000000\n\n" + eth, want: "eth0"},
		{name: "unparsable metric skipped", table: hdr + row("wlan0", "00000000", "ffff") + eth, want: "eth0"},
		{name: "tie refused", table: hdr + eth + row("wlan0", "00000000", "100"),
			wantErr: "eth0 and wlan0 both hold a default route with metric 100"},
		{name: "no header", table: eth + wlan, wantErr: "has no Destination and Metric columns"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := defaultRouteIFFrom(strings.NewReader(tc.table))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %q, %v, want error %q", got, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("a refusal still named an interface: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %v, want %q", err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// checkHouse: the code checks the format of house.env when it reads it,
// and the meaning here. want "" is a config that must load.
func TestCheckHouse(t *testing.T) {
	dir := t.TempDir()
	const net = "HOUSE_NET=10.78.0.0/24\n"
	cases := []struct {
		name, house, want string
	}{
		{name: "defaults", house: "HOUSE_IF=eth1\n"},
		{name: "house.env.example values", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.100\nHOUSE_DHCP_END=10.78.0.199\nHOUSE_ADMIN_IP=\n"},
		{name: "cloud lab values", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.100\nHOUSE_DHCP_END=10.78.0.199\nHOUSE_ADMIN_IP=10.78.0.20\n"},
		{name: "start below end as numbers not strings", house: "HOUSE_IF=eth1\n" + net + "HOUSE_DHCP_START=10.78.0.9\nHOUSE_DHCP_END=10.78.0.100\n"},
		{name: "admin outside the range", house: "HOUSE_IF=eth1\n" + net + "HOUSE_ADMIN_IP=10.78.0.20\nHOUSE_DHCP_START=10.78.0.100\nHOUSE_DHCP_END=10.78.0.199\n"},
		// When HOUSE_IF is unset, there is no house segment, so none of this is checked.
		{name: "no house if", house: net + "HOUSE_IP=10.99.0.1\nHOUSE_DHCP_START=10.99.9.9\nHOUSE_DHCP_END=10.99.0.1\nHOUSE_ADMIN_IP=10.99.0.9\n"},

		{name: "ip outside net", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.79.0.1\n",
			want: "house: HOUSE_IP=10.79.0.1 is not inside HOUSE_NET=10.78.0.0/24"},
		{name: "net overlaps agent net", house: "HOUSE_IF=eth1\nHOUSE_NET=10.77.0.0/24\nHOUSE_IP=10.77.0.1\nHOUSE_DHCP_START=10.77.0.100\nHOUSE_DHCP_END=10.77.0.199\n",
			want: "house: HOUSE_NET=10.77.0.0/24 overlaps AGENT_NET=10.77.0.0/24"},
		{name: "admin outside net", house: "HOUSE_IF=eth1\n" + net + "HOUSE_ADMIN_IP=10.79.0.20\n",
			want: "house: HOUSE_ADMIN_IP=10.79.0.20 is not inside HOUSE_NET=10.78.0.0/24"},
		{name: "dhcp start outside net", house: "HOUSE_IF=eth1\n" + net + "HOUSE_DHCP_START=10.79.0.100\n",
			want: "house: HOUSE_DHCP_START=10.79.0.100 is not inside HOUSE_NET=10.78.0.0/24"},
		{name: "dhcp end outside net", house: "HOUSE_IF=eth1\n" + net + "HOUSE_DHCP_END=10.79.0.199\n",
			want: "house: HOUSE_DHCP_END=10.79.0.199 is not inside HOUSE_NET=10.78.0.0/24"},
		{name: "start above end", house: "HOUSE_IF=eth1\n" + net + "HOUSE_DHCP_START=10.78.0.200\nHOUSE_DHCP_END=10.78.0.100\n",
			want: "house: HOUSE_DHCP_START=10.78.0.200 is above HOUSE_DHCP_END=10.78.0.100"},
		{name: "range covers house ip", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.78.0.150\n",
			want: "covers HOUSE_IP=10.78.0.150, so a house device would be leased an address the Pi already holds"},
		{name: "range covers admin ip", house: "HOUSE_IF=eth1\n" + net + "HOUSE_ADMIN_IP=10.78.0.150\n",
			want: "covers HOUSE_ADMIN_IP=10.78.0.150, so a house device would be leased an address the Pi already holds"},
		{name: "ip is the network address", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.78.0.0\n",
			want: "house: HOUSE_IP=10.78.0.0 is the network address of HOUSE_NET=10.78.0.0/24"},
		{name: "ip is the broadcast address", house: "HOUSE_IF=eth1\n" + net + "HOUSE_IP=10.78.0.255\n",
			want: "house: HOUSE_IP=10.78.0.255 is the broadcast address of HOUSE_NET=10.78.0.0/24"},
		{name: "range is one address and it is the pi", house: "HOUSE_IF=eth1\n" + net + "HOUSE_DHCP_START=10.78.0.1\nHOUSE_DHCP_END=10.78.0.1\n",
			want: "covers HOUSE_IP=10.78.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			house := write(t, dir, "house.env", tc.house)
			_, err := Load(Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("a valid house config was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// Under --live, an interface that a config names must be on the box.
// UNTRUSTED_UPLINK=1 must not close SSH on the uplink when the replacement
// admin path is a name that nothing answers to. That combination bricks a
// headless Pi. want "" is a config that must still load. wantNot guards
// the precedence: the generic "no such interface" must never replace the
// lockout refusal, or the reverse.
func TestLiveInterfacesMustExist(t *testing.T) {
	const admin = "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\n"
	// A Pi 5 with the agent VLAN up and the USB house adapter unplugged.
	base := map[string]bool{"lo": true, "eth0": true, "wlan0": true}
	with := func(extra ...string) map[string]bool {
		m := map[string]bool{}
		for k, v := range base {
			m[k] = v
		}
		for _, e := range extra {
			m[e] = true
		}
		return m
	}
	cases := []struct {
		name, house, seg        string
		ifaces                  map[string]bool
		notLive                 bool
		intIF, uplink           string
		want, wantNot, wantWarn string
	}{
		// The lockout guard.
		{name: "uplink shut with a missing house if", house: admin, uplink: "1", ifaces: base,
			want: "the only admin way in, HOUSE_IF=eth1, is not an interface on this box"},
		{name: "uplink shut names the way out", house: admin, uplink: "1", ifaces: base,
			want: "set UNTRUSTED_UPLINK=0"},
		{name: "uplink shut with a present house if", house: admin, uplink: "1", ifaces: with("eth1")},
		{name: "uplink shut with a missing admin segment", seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n", uplink: "1", ifaces: base,
			want: "the only admin way in, segment desk IF=eth3, is not an interface on this box"},
		{name: "uplink shut with a present admin segment", seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n", uplink: "1", ifaces: with("eth3")},
		{name: "one live admin path is enough", house: admin, seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n", uplink: "1", ifaces: with("eth3"),
			wantWarn: "WARNING HOUSE_IF=eth1: no such interface on this box"},
		{name: "uplink open does not take this path", house: admin, uplink: "0", ifaces: base,
			wantWarn: "WARNING HOUSE_IF=eth1: no such interface on this box"},
		{name: "uplink unset does not take this path", house: admin, ifaces: base,
			wantWarn: "WARNING HOUSE_IF=eth1: no such interface on this box"},
		{name: "a missing house if is the lockout refusal, not the generic one", house: admin, uplink: "1", ifaces: base,
			want: "is about to close SSH on WAN_IF=wlan0", wantNot: "no such interface on this box (check ip -br link)"},
		{name: "no admin path at all is the old refusal", uplink: "1", ifaces: base,
			want: "the only way in would be a keyboard and screen on the Pi"},
		{name: "a vlan child admin path rides on its parent", house: "HOUSE_IF=eth1.30\nHOUSE_ADMIN_IP=10.78.0.5\n", uplink: "1", ifaces: with("eth1")},
		{name: "a vlan child admin path with no parent", house: "HOUSE_IF=eth1.30\nHOUSE_ADMIN_IP=10.78.0.5\n", uplink: "1", ifaces: base,
			want: "the only admin way in, HOUSE_IF=eth1.30, is not an interface on this box"},

		// Plain existence, with no lockout risk: a warning, never a refusal.
		// A refusal here stopped the feeds of the agent segment for twelve
		// hours, because of a stuck house adapter (2026-09-22). The rules for an
		// absent interface are inert under the drop policy of the chains.
		{name: "missing house if", house: "HOUSE_IF=eth1\n", ifaces: base, wantWarn: "WARNING HOUSE_IF=eth1: no such interface on this box"},
		{name: "present house if", house: "HOUSE_IF=eth1\n", ifaces: with("eth1")},
		{name: "missing segment if", seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n", ifaces: base,
			wantWarn: "WARNING segment desk: IF=eth3: no such interface on this box"},
		{name: "present segment if", seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\n", ifaces: with("eth3")},
		// The Pi setup and the cloud lab both give apply a segment on
		// a VLAN child that apply itself creates after this render.
		{name: "segment vlan child rides on its parent", seg: "desk.env:IF=eth0.79\nNET=10.80.0.0/24\nIP=10.80.0.1\n", ifaces: base},
		{name: "segment vlan child with no parent", seg: "desk.env:IF=eth9.79\nNET=10.80.0.0/24\nIP=10.80.0.1\n", ifaces: base,
			wantWarn: "WARNING segment desk: IF=eth9.79: no such interface on this box"},
		// wg-quick creates WG_IF later in the same apply, so a render that
		// required it would refuse every first apply of the tunnel.
		{name: "wg if is never existence checked", house: "HOUSE_IF=eth1\nWG_IF=wg0\n", ifaces: with("eth1")},
		// INT_IF and WAN_IF must be up and have addresses before the fence
		// is built. Thus they get no VLAN parent allowance.
		{name: "int if is exact", intIF: "eth0.20", ifaces: base, want: "INT_IF=eth0.20: no such interface on this box"},
		{name: "missing wan if", ifaces: map[string]bool{"lo": true, "eth0": true}, want: "WAN_IF=wlan0: no such interface on this box"},

		// Without --live, a dev box has none of these, but it must still render.
		{name: "not live with everything missing", house: admin + "WG_IF=wg0\n", seg: "desk.env:IF=eth3\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n", uplink: "1", notLive: true},
		{name: "not live with a missing admin path", house: admin, uplink: "1", notLive: true},

		// Carrier is a cable matter, not a config error. NetworkManager has
		// ignore-carrier=yes for these same devices (vm/pi/apply.sh). Thus an
		// empty port is a normal state and gets only a message on stderr.
		{name: "house if with no carrier warns and loads", house: "HOUSE_IF=eth1\n", ifaces: map[string]bool{"lo": true, "eth0": true, "wlan0": true, "eth1": false},
			wantWarn: "pi-fortress: HOUSE_IF=eth1 is there but has no carrier"},
		{name: "admin path with no carrier warns and loads", house: admin, uplink: "1", ifaces: map[string]bool{"lo": true, "eth0": true, "wlan0": true, "eth1": false},
			wantWarn: "pi-fortress: HOUSE_IF=eth1 is there but has no carrier"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			segs := filepath.Join(dir, "segments.d")
			if err := os.Mkdir(segs, 0755); err != nil {
				t.Fatal(err)
			}
			house := "/nonexistent/house.env"
			if tc.house != "" {
				house = write(t, dir, "house.env", tc.house)
			}
			if name, body, ok := strings.Cut(tc.seg, ":"); ok {
				write(t, segs, name, body)
			}
			net := lab
			net.UntrustedUplink = tc.uplink
			net.EnvSrc = "/etc/pi-fortress/net.env"
			var warn strings.Builder
			intIF := tc.intIF
			if intIF == "" {
				intIF = "eth0"
			}
			_, err := Load(Options{Net: net, HouseEnv: house, SegmentsDir: segs,
				IntIF: intIF, WanIF: "wlan0", Live: !tc.notLive, ifaces: tc.ifaces, Stderr: &warn})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("a config that must load was refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if tc.wantNot != "" && err != nil && strings.Contains(err.Error(), tc.wantNot) {
				t.Fatalf("the refusal says %q, which is the wrong refusal for this config: %v", tc.wantNot, err)
			}
			if tc.wantWarn != "" && !strings.Contains(warn.String(), tc.wantWarn) {
				t.Fatalf("stderr is %q, want %q", warn.String(), tc.wantWarn)
			}
		})
	}
}

// The house config that pi-fortress ships and the one that the cloud lab
// writes are the two configs that an operator actually starts from.
// checkHouse must never refuse either.
func TestShippedHouseConfigsPass(t *testing.T) {
	root := testsupport.RepoRoot(t)
	dir := t.TempDir()
	for _, src := range []string{
		filepath.Join(root, "vm", "pi", "house.env.example"),
		filepath.Join(root, "vm", "cloudlab", "guest", "gw.sh"),
	} {
		t.Run(filepath.Base(src), func(t *testing.T) {
			raw := testsupport.ReadFile(t, src)
			var keep []string
			for line := range strings.SplitSeq(raw, "\n") {
				if strings.HasPrefix(line, "HOUSE_") && !strings.Contains(line, "$") {
					keep = append(keep, line)
				}
			}
			if len(keep) < 4 {
				t.Fatalf("%s: found only %d HOUSE_ lines, this test has gone stale", src, len(keep))
			}
			body := strings.Join(keep, "\n") + "\n"
			if !strings.Contains(body, "HOUSE_IF=") {
				body = "HOUSE_IF=eth1\n" + body
			}
			house := write(t, dir, "house.env", body)
			if _, err := Load(Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"}); err != nil {
				t.Fatalf("%s is refused by checkHouse: %v", src, err)
			}
		})
	}
}

// When HOUSE_PRIVATE_DNS is absent, empty or off, the render is exactly
// what a house.env without the key always gave: no set, and no accept
// anywhere that uses only a destination address. The bug class is the
// gate: when the key is off, nothing must be accepted before its drop.
func TestHousePrivateDNSOffRendersUnchanged(t *testing.T) {
	dir := t.TempDir()
	base := load(t, Options{Net: lab, HouseEnv: write(t, dir, "base.env", "HOUSE_IF=eth1\nWG_IF=wg0\n"), SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	e := labElements
	e.HousePrivateDNS = "elements = { 76.76.2.22 }"
	for _, v := range []string{"off", ""} {
		house := write(t, dir, "h.env", "HOUSE_IF=eth1\nWG_IF=wg0\nHOUSE_PRIVATE_DNS="+v+"\n")
		if got := load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"}).Ruleset(e); got != base {
			t.Fatalf("HOUSE_PRIVATE_DNS=%q changed the ruleset", v)
		}
	}
	if strings.Contains(base, "house_private_dns") {
		t.Fatalf("the ruleset names the private DNS set with the key off:\n%s", base)
	}
	// The chain's own "policy accept;" header is not a rule.
	gate := chain(t, base, "resolver_gate")
	for _, ln := range strings.Split(gate, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "type filter") && strings.HasSuffix(ln, "accept") {
			t.Fatalf("resolver_gate carries an accept the DNS pin does not justify:\n%s", gate)
		}
	}
	if !strings.Contains(gate, "ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop") {
		t.Fatalf("resolver_gate lost its drop:\n%s", gate)
	}
}

// HOUSE_PRIVATE_DNS=on opens TCP 853 and 443 to house_private_dns.ips in
// each chain that would otherwise stop it: the raw chain, below the
// blacklist drop and above the DoH-set and 853 drops; the resolver gate,
// above its drop (without it, DoH on 443 stayed blocked while DoT
// worked); and forward, scoped to the uplink when there is no tunnel.
// No chain accepts UDP to the same addresses (QUIC, DoQ, DoH3).
func TestHousePrivateDNSOn(t *testing.T) {
	dir := t.TempDir()
	e := labElements
	e.HousePrivateDNS = "elements = { 76.76.2.22 }"
	nft := load(t, Options{Net: lab, HouseEnv: write(t, dir, "on.env", "HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	if !strings.Contains(nft, "set house_private_dns_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { 76.76.2.22 }\n  }") {
		t.Fatalf("set not declared with its elements:\n%s", nft)
	}
	acc := `iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } accept`
	order(t, chain(t, nft, "filter_prerouting"), "filter_prerouting",
		`iifname "eth1" ip daddr @blacklist_v4 counter drop`,
		acc,
		`iifname "eth1" ip daddr @dns_bypass_v4 counter drop`,
		`iifname "eth1" udp dport 443 counter drop`,
		`iifname "eth1" tcp dport 853 counter drop`,
		`iifname "eth1" udp dport 853 counter drop`)
	gate := chain(t, nft, "resolver_gate")
	// Strict: the pins are checked by name as all TLS flows are, 853 too.
	// Thus the name of a different profile to the same address is refused.
	order(t, gate, "resolver_gate",
		`iifname "eth1" tcp dport 853 ip daddr @house_private_dns_v4 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @reserved_v4 ct mark set`,
		`iifname "eth1" tcp dport { 443, 465, 993, 5223, 5228, 8443 } ct state new`)
	if strings.Contains(gate, "@house_private_dns_v4 accept") {
		t.Errorf("strict still waves the pins past the check:\n%s", gate)
	}
	// Open keeps the old shape: the pins accepted, 443 checked on a miss.
	open := load(t, Options{Net: lab, HouseEnv: write(t, dir, "open.env", "HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\nHOUSE_EGRESS=open\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	order(t, chain(t, open, "resolver_gate"), "resolver_gate",
		`iifname "eth1" tcp dport 443 ip daddr @house_private_dns_v4 accept`,
		`tcp dport 443 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @reserved_v4 ct mark set`)
	// The blanket exemption (2026-09-23, f5f368e) is removed. A device on the
	// endpoint is checked by name as all others are, and does not pass without a check.
	if strings.Contains(nft, "house_private_dns_clients") {
		t.Fatalf("the private-DNS client exemption is back:\n%s", nft)
	}
	// The exception applies only to the DNS pin. Port 80 to the same address
	// still goes through the same gate as before.
	if strings.Contains(gate, "tcp dport 80 ip daddr @house_private_dns_v4") {
		t.Fatalf("plain HTTP opened to the resolvers:\n%s", gate)
	}
	order(t, chain(t, nft, "forward"), "forward",
		`iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } oifname "wlan0" accept`,
		`iifname "eth1" oifname "wlan0" accept`,
		`iifname "eth1" counter drop`)
	for _, ln := range strings.Split(nft, "\n") {
		if strings.Contains(ln, "house_private_dns_v4") && (strings.Contains(ln, "udp") || strings.Contains(ln, "l4proto")) {
			t.Fatalf("UDP to a private DNS provider is accepted: %s", ln)
		}
	}
	// HOUSE_BLOCK_DIRECT_IP=off has no gate, so nothing to exempt from it.
	nogate := load(t, Options{Net: lab, HouseEnv: write(t, dir, "nogate.env", "HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\nHOUSE_BLOCK_DIRECT_IP=off\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	if strings.Contains(chain(t, nogate, "resolver_gate"), "house_private_dns_v4") {
		t.Fatalf("gate accept rendered without a gate:\n%s", nogate)
	}

}

// With a tunnel, the private-DNS accept in forward names WG_IF and never
// the uplink. The kill-switch is exactly the same as with the key off.
// The exception is a hole in the DNS pin, never a way out the WAN.
func TestHousePrivateDNSOnKeepsTheKillSwitch(t *testing.T) {
	dir := t.TempDir()
	e := labElements
	e.HousePrivateDNS = "elements = { 76.76.2.22 }"
	off := load(t, Options{Net: lab, HouseEnv: write(t, dir, "off.env", "HOUSE_IF=eth1\nWG_IF=wg0\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	on := load(t, Options{Net: lab, HouseEnv: write(t, dir, "on.env", "HOUSE_IF=eth1\nWG_IF=wg0\nHOUSE_PRIVATE_DNS=on\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	fwd := chain(t, on, "forward")
	order(t, fwd, "forward",
		`pi-fortress house-killswitch`,
		`ct state established,related accept`,
		`iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } oifname "wg0" accept`,
		`iifname "eth1" oifname "wg0" accept`,
		`iifname "eth1" oifname "wlan0" limit rate 10/minute burst 20 packets log prefix "pi-fortress house-killswitch: " level warn`,
		`iifname "eth1" counter drop`)
	for _, ln := range strings.Split(on, "\n") {
		if strings.Contains(ln, "house_private_dns_v4") && strings.Contains(ln, `"wlan0"`) {
			t.Fatalf("private DNS accept names the uplink: %s", ln)
		}
	}
	// Every kill-switch line with the key off is still there with it on.
	for _, ln := range strings.Split(off, "\n") {
		if strings.Contains(ln, "house-killswitch") && !strings.Contains(on, ln) {
			t.Fatalf("kill-switch rule lost with HOUSE_PRIVATE_DNS=on: %s", ln)
		}
	}
	// The raw accept is above the vpn_bypass mark, so a provider address
	// is never marked for the uplink.
	order(t, chain(t, on, "filter_prerouting"), "filter_prerouting",
		`iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } accept`,
		`iifname "eth1" ip daddr @vpn_bypass_v4 meta mark set`)
}

// The WG collision check covered agent, WAN and house. The plain-segment
// check covered those three and its siblings, but not WG. A segment that
// claimed WG_IF changed tunnel traffic into the traffic of that segment,
// with the admin and SSH holes of that segment.
func TestSegmentCannotClaimTheTunnelInterface(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", "IF=wg0\nNET=10.80.0.0/24\nIP=10.80.0.1\nADMIN=yes\n")
	_, err := Load(Options{Net: lab, HouseEnv: house, SegmentsDir: segs})
	if err == nil || !strings.Contains(err.Error(), "WG_IF") {
		t.Fatalf("a segment took the tunnel interface: %v", err)
	}
}

// The code read each final dot as VLAN syntax and never checked the
// suffix. Thus the firewall loaded rules for a child interface that
// NetworkManager would later refuse to create.
func TestVLANSuffixIsCheckedBeforeTheRulesAreWritten(t *testing.T) {
	segment := func(ifname string) error {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		if err := os.Mkdir(segs, 0755); err != nil {
			t.Fatal(err)
		}
		write(t, segs, "desk.env", "IF="+ifname+"\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
		_, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs})
		return err
	}
	for _, bad := range []string{"eth3.abc", "eth3.", "eth3.0", "eth3.4095", "eth3.07", "eth3.1.2"} {
		if err := segment(bad); err == nil || !strings.Contains(err.Error(), "VLAN") {
			t.Errorf("IF=%s accepted: %v", bad, err)
		}
	}
	for _, good := range []string{"eth3", "eth3.1", "eth3.20", "eth3.4094"} {
		if err := segment(good); err != nil {
			t.Errorf("IF=%s refused: %v", good, err)
		}
	}
}

// Each discovery error read as "the operator removed it". Thus an
// unreadable house.env or segments.d rendered a fence without them, and
// apply then removed what they had configured.
func TestUnreadableConfigurationIsNotAbsence(t *testing.T) {
	dir := t.TempDir()
	notDir := write(t, dir, "wall", "not a directory\n")
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(segs, "desk.env"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, house, segs, want string }{
		{"house behind a file", filepath.Join(notDir, "house.env"), "/nonexistent", "house.env"},
		{"segments dir is a file", "/nonexistent/house.env", notDir, "not a directory"},
		{"segments behind a file", "/nonexistent/house.env", filepath.Join(notDir, "segments.d"), "segments.d"},
		{"segment is a directory", "/nonexistent/house.env", segs, "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(Options{Net: lab, HouseEnv: tc.house, SegmentsDir: tc.segs})
			if err == nil {
				t.Fatal("an unreadable configuration rendered as an absent one")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name the path: %v", err)
			}
		})
	}
}

// House and segment values were validated for format and for what they
// mean together. The primary network, on which the full ruleset is
// built, was copied in as strings.
func TestPrimaryNetIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Net)
		opt  func(*Options)
		want string
	}{
		{"no agent net", func(n *Net) { n.AgentNet = "" }, nil, "AGENT_NET"},
		{"agent net not a cidr", func(n *Net) { n.AgentNet = "10.77.0.0" }, nil, "AGENT_NET"},
		{"agent net bad prefix", func(n *Net) { n.AgentNet = "10.77.0.0/33" }, nil, "AGENT_NET"},
		{"agent net not canonical", func(n *Net) { n.AgentNet = "10.77.0.1/24" }, nil, "10.77.0.0/24"},
		{"no pi ip", func(n *Net) { n.PiIP = "" }, nil, "PI_IP"},
		{"pi ip malformed", func(n *Net) { n.PiIP = "10.77.0.256" }, nil, "PI_IP"},
		{"pi ip outside", func(n *Net) { n.PiIP = "10.88.0.1" }, nil, "is not inside AGENT_NET"},
		{"agent ip outside", func(n *Net) { n.AgentIP = "10.88.0.10" }, nil, "is not inside AGENT_NET"},
		{"agent ip is the pi", func(n *Net) { n.AgentIP = "10.77.0.1" }, nil, "PI_IP"},
		{"upstream malformed", func(n *Net) { n.DNSUpstream = "nope" }, nil, "DNS_UPSTREAM"},
		{"no upstream", func(n *Net) { n.DNSUpstream = "" }, nil, "DNS_UPSTREAM"},
		{"upstream port", func(n *Net) { n.DNSUpstream = "9.9.9.9#0" }, nil, "not a port"},
		{"upstream port word", func(n *Net) { n.DNSUpstream = "9.9.9.9#dns" }, nil, "not a port"},
		{"int if grammar", nil, func(o *Options) { o.IntIF = "eth0 x" }, "INT_IF"},
		{"wan if grammar", nil, func(o *Options) { o.WanIF = "wlan0;reboot" }, "WAN_IF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := lab
			if tc.mut != nil {
				tc.mut(&net)
			}
			o := Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}
			if tc.opt != nil {
				tc.opt(&o)
			}
			_, err := Load(o)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name the field: %v", err)
			}
		})
	}
	// The values of the lab load. The address#port form of DNS_UPSTREAM,
	// which apply.sh rewrites for the Go resolver, also loads.
	for _, upstream := range []string{"9.9.9.9", "9.9.9.9#5353"} {
		net := lab
		net.DNSUpstream = upstream
		if _, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}); err != nil {
			t.Fatalf("DNS_UPSTREAM=%s refused: %v", upstream, err)
		}
	}
}

// A plain segment resolves through this box. Thus the ruleset must give
// it what the agent segment has: port 53 reachable, a flood meter in
// front of it, its own set, and the 80/443 gate that checks that set.
// Before this, the input chain of the segment went directly from the
// optional ssh hole to a counter drop. Thus the socket of the resolver was
// unreachable, and the segment had no resolver at all.
func TestAPlainSegmentGetsAResolverProfile(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\n")
	c := load(t, Options{Net: lab, SegmentsDir: segs})
	nft := c.Ruleset(labElements)
	for _, want := range []string{
		"  set resolved_desk_v4 {",
		`iifname "eth3" tcp dport 53 accept`,
		`iifname "eth3" udp dport 53 accept`,
		`iifname "eth3" tcp dport 53 meter desk_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop`,
		`iifname "eth3" udp dport 53 meter desk_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop`,
		`iifname "eth3" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress desk-directip: " level info` + "\n" +
			`    iifname "eth3" meta l4proto { tcp, udp } th dport != 53 ct state new ip daddr != 10.79.0.1 ip daddr != @resolved_desk_v4 counter drop`,
		// A third-party resolver would leave the gate empty and all names
		// unreachable. Thus the lookup must fail here instead.
		`iifname "eth3" udp dport 53 reject with icmp type port-unreachable`,
		`iifname "eth3" tcp dport 53 reject with tcp reset`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n%s", want)
		}
	}
	// The port must open before the drop of the chain. If not, the accept is
	// rendered but never reached.
	in := chain(t, nft, "input")
	order(t, in, "input", `iifname "eth3" udp dport 53 accept`, `iifname "eth3" counter drop`)
}

// BLOCK_DIRECT_IP=off is the twin of the house key for a plain segment.
// The gate goes. The set and all other parts of the segment stay. Any
// other value is refused, not read as on.
func TestASegmentCanTurnItsDirectIPGateOff(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\nBLOCK_DIRECT_IP=off\n")
	nft := load(t, Options{Net: lab, SegmentsDir: segs}).Ruleset(labElements)
	if strings.Contains(nft, "desk-directip") || strings.Contains(nft, "ip daddr != @resolved_desk_v4") {
		t.Error("the gate is still rendered with BLOCK_DIRECT_IP=off")
	}
	for _, want := range []string{"  set resolved_desk_v4 {", `iifname "eth3" udp dport 53 reject with icmp type port-unreachable`, "desk-blacklist"} {
		if !strings.Contains(nft, want) {
			t.Errorf("BLOCK_DIRECT_IP=off took more than the gate: missing %s", want)
		}
	}
	write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\nBLOCK_DIRECT_IP=on\n")
	if nft := load(t, Options{Net: lab, SegmentsDir: segs}).Ruleset(labElements); !strings.Contains(nft, "desk-directip") {
		t.Error("BLOCK_DIRECT_IP=on renders no gate")
	}
	write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\nBLOCK_DIRECT_IP=no\n")
	if _, err := Load(Options{Net: lab, SegmentsDir: segs}); err == nil || !strings.Contains(err.Error(), "BLOCK_DIRECT_IP") {
		t.Errorf("BLOCK_DIRECT_IP=no accepted: %v", err)
	}
}

// A segment name can have a dash (reSegName), but an nftables set or
// meter identifier cannot. Thus the name is sanitised only at the places
// where it becomes an identifier. The log prefix and the chain comments
// still show the name that the operator wrote.
func TestADashedSegmentNameIsAnNftIdentifier(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "lab-desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	c := load(t, Options{Net: lab, SegmentsDir: segs})
	nft := c.Ruleset(labElements)
	for _, want := range []string{
		"  set resolved_lab_desk_v4 {",
		"meter lab_desk_dnsflood_tcp {",
		"meter lab_desk_dnsflood_udp {",
		`ip daddr != @resolved_lab_desk_v4`,
		`log prefix "pi-fortress lab-desk-directip: "`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n%s", want)
		}
	}
	if strings.Contains(nft, "resolved_lab-desk_v4") || strings.Contains(nft, "lab-desk_dnsflood") {
		t.Error("a dash reached an nftables identifier")
	}
}

// A policy change does not flush conntrack. Thus the invariants that it
// can make true of an already-admitted flow are before the conntrack
// accept: a tunnel start and DoT on. After the accept, they would control
// only new flows. A flow NATed out the uplink, or a plaintext query
// socket opened, before the apply would
// continue to leave.
func TestPolicyTransitionsReachEstablishedFlows(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nWG_IF=wg0\n")
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9"
	c := load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	nft := c.Ruleset(labElements)
	order(t, chain(t, nft, "forward"), "forward",
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 limit rate`,
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 counter drop`,
		"ct state established,related accept",
	)
	order(t, chain(t, nft, "output"), "output",
		`meta skuid "pf-dns" tcp dport 853 ip daddr != { 9.9.9.9 } ct state established,related counter drop`,
		`udp dport 53 oifname != { "lo", "wg0" } ct state established,related counter drop`,
		`udp dport 53 oifname "wg0" ip daddr != 10.64.0.1 ct state established,related counter drop`,
		`tcp dport 53 oifname != { "lo", "wg0" } ct state established,related counter drop`,
		`tcp dport 53 oifname "wg0" ip daddr != 10.64.0.1 ct state established,related counter drop`,
		"ct state established,related accept",
	)
	// Without a tunnel, the house shares the stub over lo. Thus lo is the
	// only exemption, and nothing names wg0.
	write(t, dir, "house.env", "HOUSE_IF=eth1\n")
	c = load(t, Options{Net: net, HouseEnv: house, SegmentsDir: "/nonexistent"})
	nft = c.Ruleset(labElements)
	order(t, chain(t, nft, "output"), "output",
		`udp dport 53 oifname != "lo" ct state established,related counter drop`,
		`tcp dport 53 oifname != "lo" ct state established,related counter drop`,
		"ct state established,related accept",
	)
	if strings.Contains(nft, "meta mark != ") {
		t.Errorf("no tunnel, yet a kill-switch was rendered:\n%s", chain(t, nft, "forward"))
	}
	// No DoT, no tunnel: nothing new ahead of the accept.
	c = load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: "/nonexistent"})
	if out := chain(t, c.Ruleset(labElements), "output"); strings.Contains(out, "established,related counter drop") {
		t.Errorf("DoT is off, yet output gained a pre-conntrack drop:\n%s", out)
	}
}

// HOUSE_BLOCK_VPN is on unless set to off. The house raw chain drops
// WireGuard by its header on any port, and OpenVPN on 1194. The drop is
// after the blacklist and before all accepts there. Thus WireGuard sent
// to port 53 or to a private DNS pin is still caught.
func TestHouseBlockVPN(t *testing.T) {
	dir := t.TempDir()
	e := labElements
	e.HousePrivateDNS = "elements = { 76.76.2.22 }"
	nft := load(t, Options{Net: lab, HouseEnv: write(t, dir, "on.env", "HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	raw := chain(t, nft, "filter_prerouting")
	order(t, raw, "filter_prerouting",
		`iifname "eth1" ip daddr @blacklist_v4 counter drop`,
		`iifname "eth1" udp length 156 @th,64,32 0x01000000 limit rate 10/second burst 20 packets log prefix "pi-fortress house-vpn: " level info`,
		`iifname "eth1" udp length 156 @th,64,32 0x01000000 counter drop`,
		`iifname "eth1" udp length 100 @th,64,32 0x02000000 counter drop`,
		`iifname "eth1" udp length 72 @th,64,32 0x03000000 counter drop`,
		`iifname "eth1" udp length >= 40 @th,64,32 0x04000000 counter drop`,
		`iifname "eth1" meta l4proto { tcp, udp } th dport 1194 counter drop`,
		`iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 }`,
		`iifname "eth1" meta l4proto { tcp, udp } th dport 53 accept`)
	// Only the house: the agent and desk have no own VPN to drop (the
	// forward of the agent ends in a drop). The tunnel of the Pi never
	// comes in on eth1.
	for _, ln := range strings.Split(nft, "\n") {
		if strings.Contains(ln, "@th,64,32") && !strings.Contains(ln, `iifname "eth1"`) {
			t.Fatalf("a VPN drop outside the house: %s", ln)
		}
	}
	off := load(t, Options{Net: lab, HouseEnv: write(t, dir, "off.env", "HOUSE_IF=eth1\nHOUSE_BLOCK_VPN=off\n"), SegmentsDir: "/nonexistent"}).Ruleset(e)
	if strings.Contains(off, "house-vpn") {
		t.Fatalf("HOUSE_BLOCK_VPN=off still drops VPNs:\n%s", chain(t, off, "filter_prerouting"))
	}
}

// The SNI check: the gate marks a house 443 miss as pending and does not
// drop it. forward holds the packets of that flow for pf dns. The verdict
// marks are copied to the flow and cleared from the packet. All of this is
// before the conntrack accept, because a pending flow is established when
// its handshake is done. The WireGuard kill switch comes first. A queued
// packet that pf dns accepts leaves forward at the queue. Thus a kill
// switch after it never saw the SYN or the ClientHello.
func TestHouseSNICheck(t *testing.T) {
	dir := t.TempDir()
	c := load(t, Options{Net: lab, HouseEnv: write(t, dir, "wg.env", "HOUSE_IF=eth1\nWG_IF=wg0\n"), SegmentsDir: "/nonexistent"})
	nft := c.Ruleset(labElements)
	order(t, chain(t, nft, "forward"), "forward",
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 limit rate 10/minute burst 20 packets log prefix "pi-fortress house-killswitch: " level warn`,
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x1 counter drop`,
		`meta mark and 0x00f00000 == 0x00200000 ct mark set ct mark and 0xff0fffff or 0x00200000 meta mark set meta mark and 0xff0fffff`,
		`meta mark and 0x00f00000 == 0x00300000 ct mark set ct mark and 0xff0fffff or 0x00300000 meta mark set meta mark and 0xff0fffff`,
		`ct mark and 0x00f00000 == 0x00300000 limit rate 10/second burst 20 packets log prefix "pi-fortress house-sni: " level info`,
		`ct mark and 0x00f00000 == 0x00300000 counter reject with tcp reset`,
		`ct mark and 0x00f00000 == 0x00100000 meter house_sni_queue { ip saddr limit rate over 100/second burst 300 packets } jump house_sni_flood`,
		`ct mark and 0x00f00000 == 0x00100000 counter queue num 1`,
		`ct state established,related accept`)
	// A packet over the meter is logged and dropped, never accepted or
	// returned. Each of these would let a TLS flow past the name check.
	flood := chain(t, nft, "house_sni_flood")
	order(t, flood, "house_sni_flood",
		`limit rate 10/second burst 20 packets log prefix "pi-fortress house-sniflood: " level info`,
		`counter drop`)
	if strings.Contains(flood, "accept") || strings.Contains(flood, "return") {
		t.Errorf("house_sni_flood lets a packet on:\n%s", flood)
	}
	// Only the direction of the house, and never with a bypass flag. When pf
	// dns is down, the packet is dropped, as the gate did before.
	for _, ln := range strings.Split(chain(t, nft, "forward"), "\n") {
		if strings.Contains(ln, "0x00f00000") && !strings.Contains(ln, `iifname "eth1"`) {
			t.Errorf("an SNI rule outside the house: %s", ln)
		}
		if strings.Contains(ln, "queue") && strings.Contains(ln, "bypass") {
			t.Errorf("the SNI queue fails open: %s", ln)
		}
	}
	if !strings.Contains(c.EnvFile(), "HOUSE_SNI_QUEUE='1'\n") {
		t.Errorf("apply is not told the queue:\n%s", c.EnvFile())
	}
	off := load(t, Options{Net: lab, HouseEnv: write(t, dir, "off.env", "HOUSE_IF=eth1\nHOUSE_BLOCK_DIRECT_IP=off\n"), SegmentsDir: "/nonexistent"})
	if r := off.Ruleset(labElements); strings.Contains(r, "0x00f00000") || strings.Contains(r, "house_sni") || !strings.Contains(off.EnvFile(), "HOUSE_SNI_QUEUE=''\n") {
		t.Error("the SNI check outlived HOUSE_BLOCK_DIRECT_IP=off")
	}
}

// TestHouseEgress: HOUSE_EGRESS and its toggles. Strict (unset) jumps to
// a chain that returns the allowed ports and drops the rest. Audit logs
// the rest under its own prefix and lets it pass. Open has no chain. The
// local-network drop is in all modes, before the uplink accept.
func TestHouseEgress(t *testing.T) {
	dir := t.TempDir()
	render := func(extra string) string {
		return load(t, Options{Net: lab, HouseEnv: write(t, dir, "house.env", "HOUSE_IF=eth1\n"+extra), SegmentsDir: "/nonexistent"}).Ruleset(labElements)
	}
	local := `iifname "eth1" ip daddr @reserved_v4 counter drop`
	jump := `iifname "eth1" jump house_egress`
	strict := render("")
	if render("HOUSE_EGRESS=strict\n") != strict {
		t.Error("strict renders differently from unset")
	}
	order(t, chain(t, strict, "forward"), "forward", local, jump, `iifname "eth1" oifname "wlan0" accept`)
	eg := chain(t, strict, "house_egress")
	order(t, eg, "house_egress",
		"tcp dport 80 return",
		"tcp dport { 443, 465, 993, 5223, 5228, 8443 } return",
		"tcp dport { 143, 587 } return",
		"udp dport 123 return",
		"icmp type echo-request limit rate 10/second burst 20 packets return",
		`log prefix "pi-fortress house-port: "`,
		"counter drop")
	for _, off := range []string{"4500", "esp", "19302", "house-audit"} {
		if strings.Contains(eg, off) {
			t.Errorf("strict default opens %s:\n%s", off, eg)
		}
	}

	// WhatsApp (on by default): its chat port and its port 80 fallback,
	// only to the ranges of Meta. When off: neither, and no set.
	if !strings.Contains(eg, "tcp dport 5222 ip daddr @house_whatsapp_v4 return") || !strings.Contains(strict, "set house_whatsapp_v4 {") ||
		!strings.Contains(strict, "tcp dport 80 ct state new ip daddr != 10.78.0.1 ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4 ip daddr != @house_whatsapp_v4 counter drop") {
		t.Errorf("WhatsApp is not open by default:\n%s\n%s", eg, chain(t, strict, "resolver_gate"))
	}
	if waOff := render("HOUSE_ALLOW_WHATSAPP=off\n"); strings.Contains(waOff, "house_whatsapp_v4") {
		t.Errorf("HOUSE_ALLOW_WHATSAPP=off still opens Meta:\n%s", chain(t, waOff, "house_egress"))
	}

	audit := chain(t, render("HOUSE_EGRESS=audit\n"), "house_egress")
	if !strings.Contains(audit, `log prefix "pi-fortress house-audit: "`) || strings.Contains(audit, "drop") {
		t.Errorf("audit must log and pass:\n%s", audit)
	}

	open := render("HOUSE_EGRESS=open\n")
	if strings.Contains(open, "house_egress") || !strings.Contains(open, local) {
		t.Errorf("open: no egress chain, local drop kept:\n%s", chain(t, open, "forward"))
	}

	wg := render("WG_IF=wg0\n")
	order(t, chain(t, wg, "forward"), "forward", local, jump, `iifname "eth1" oifname "wlan0" meta mark 0x1 counter accept`, `iifname "eth1" oifname "wg0" accept`)

	on := chain(t, render("HOUSE_ALLOW_WIFI_CALLING=on\nHOUSE_ALLOW_CALL_UDP=on\nHOUSE_ALLOW_PORTS=\"tcp:27015-27030 udp:3074 tcp:5223\"\n"), "house_egress")
	for _, want := range []string{
		"udp dport { 500, 4500 } return",
		"meta l4proto esp return",
		"udp dport { 3478-3497, 8801-8810, 16384-16403, 19302-19309 } return",
		"tcp dport { 27015-27030, 5223 } return",
		"udp dport { 3074 } return",
	} {
		if !strings.Contains(on, want) {
			t.Errorf("house_egress lacks %q:\n%s", want, on)
		}
	}
	// A TLS port that the operator opened is no longer checked by name. This
	// is the way out for a client that sends no name.
	// The STARTTLS mail ports send no ClientHello first, so the name check
	// must not see them.
	if g := chain(t, strict, "resolver_gate"); strings.Contains(g, "143") || strings.Contains(g, "587") {
		t.Errorf("the name check sees a STARTTLS port:\n%s", g)
	}
	gate := chain(t, render("HOUSE_ALLOW_PORTS=tcp:5223\n"), "resolver_gate")
	if !strings.Contains(gate, "tcp dport { 443, 465, 993, 5228, 8443 } ct state new") {
		t.Errorf("an allowed TLS port is still checked:\n%s", gate)
	}

	for _, bad := range []string{"HOUSE_EGRESS=closed", "HOUSE_ALLOW_PORTS=tcp:0", "HOUSE_ALLOW_PORTS=sctp:5", "HOUSE_ALLOW_PORTS=udp:9-3", "HOUSE_ALLOW_CALL_UDP=yes", "HOUSE_ALLOW_WHATSAPP=maybe"} {
		if _, err := Load(Options{Net: lab, HouseEnv: write(t, dir, "bad.env", "HOUSE_IF=eth1\n"+bad+"\n"), SegmentsDir: "/nonexistent"}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// TestWGBypassMark: the mark that the kill switch compares whole, and that
// wg-routes.sh routes around the tunnel. Zero is each unmarked packet (all
// of the house would leave by the uplink, accepted). Bits 20-23 are for
// the SNI check, which rewrites them on each checked flow.
func TestWGBypassMark(t *testing.T) {
	for _, v := range []string{"", "0x1", "0x2", "0x10", "0xff0fffff", "0x80000000"} {
		if err := CheckWGBypassMark(v); err != nil {
			t.Errorf("CheckWGBypassMark(%q): %v", v, err)
		}
	}
	for _, v := range []string{"0x0", "0x00", "1", "0x", "0xg", "0x100000000", "0x00100000", "0x00300001", "0xffffffff"} {
		if err := CheckWGBypassMark(v); err == nil {
			t.Errorf("CheckWGBypassMark(%q) accepted", v)
		}
	}
	dir := t.TempDir()
	if _, err := Load(Options{Net: lab, HouseEnv: write(t, dir, "zero.env", "HOUSE_IF=eth1\nWG_IF=wg0\nWG_BYPASS_MARK=0x0\n"), SegmentsDir: "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "WG_BYPASS_MARK") {
		t.Errorf("WG_BYPASS_MARK=0x0: %v", err)
	}
	c := load(t, Options{Net: lab, HouseEnv: write(t, dir, "two.env", "HOUSE_IF=eth1\nWG_IF=wg0\nWG_BYPASS_MARK=0x2\n"), SegmentsDir: "/nonexistent"})
	nft := c.Ruleset(labElements)
	for _, want := range []string{
		`iifname "eth1" ip daddr @vpn_bypass_v4 meta mark set 0x2`,
		`iifname "eth1" oifname "wlan0" meta mark 0x2 counter accept`,
		`iifname "eth1" oifname "wlan0" meta mark and 0xff0fffff != 0x2 counter drop`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("mark 0x2 not rendered: %s", want)
		}
	}
	if !strings.Contains(c.EnvFile(), "WG_BYPASS_MARK='0x2'\n") {
		t.Errorf("apply is not told the mark:\n%s", c.EnvFile())
	}
}

// TestPiOwnTimeSyncIsNotDropped: chrony (apply.sh) reaches its NTS
// servers from the Pi itself, NTS-KE on TCP 4460 and NTP on UDP 123, as
// the _chrony user. The output chain accepts by policy. The scope of each
// drop in it is a thing that is not chrony: the uid of a pf daemon, DNS
// ports, the name broadcasts of the uplink, IPv6. The test uses the mode
// with the most output rules (DoT, fakeip, an untrusted uplink, a
// WireGuard house). Thus a future rule that widens a drop fails here, not
// at the next boot of the Pi.
func TestPiOwnTimeSyncIsNotDropped(t *testing.T) {
	dir := t.TempDir()
	net := lab
	net.DoTAuthName, net.DoTIPs = "dns.quad9.net", "9.9.9.9"
	net.UntrustedUplink = "1"
	net.AgentDNS = AgentDNSFakeIP
	c := load(t, Options{Net: net, HouseEnv: write(t, dir, "wg.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.5\nWG_IF=wg0\n"), SegmentsDir: "/nonexistent"})
	out := chain(t, c.Ruleset(labElements), "output")
	if !strings.Contains(out, "type filter hook output priority filter; policy accept;") {
		t.Fatalf("output no longer accepts by policy:\n%s", out)
	}
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, "drop") && !strings.Contains(ln, "reject") {
			continue
		}
		scoped := strings.Contains(ln, "meta skuid") || strings.Contains(ln, "dport 53 ") ||
			strings.Contains(ln, "dport 853") || strings.Contains(ln, "{ 5353, 5355 }") ||
			strings.Contains(ln, "nfproto ipv6") || strings.Contains(ln, "policy accept")
		if !scoped || strings.Contains(ln, "4460") || strings.Contains(ln, "dport 123") {
			t.Errorf("an output drop that can reach chrony's NTS-KE or NTP: %s", strings.TrimSpace(ln))
		}
	}
}

// TestAntiSpoofOpensRawPrerouting: each segment that the Pi serves drops
// a source outside its own subnet before all accepts in raw prerouting.
// The house lets DHCP from 0.0.0.0 of a client without a lease back to the
// chain. A segment without a net renders no check at all.
func TestAntiSpoofOpensRawPrerouting(t *testing.T) {
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_PRIVATE_DNS=on\n")
	segs := filepath.Join(dir, "segments.d")
	os.Mkdir(segs, 0755)
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\n")
	write(t, segs, "guest.env", "IF=eth2\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
	c := load(t, Options{Net: lab, HouseEnv: house, SegmentsDir: segs, IntIF: "eth0.20"})
	nft := c.Ruleset(labElements)
	raw := chain(t, nft, "filter_prerouting")
	spoof := func(ifname, name, net string) []string {
		m := `iifname "` + ifname + `" ip saddr != ` + net
		return []string{m + ` limit rate 10/second burst 20 packets log prefix "pi-fortress ` + name + `-spoof: " level info`, m + " counter drop"}
	}
	var want []string
	want = append(want, spoof("eth0.20", "agent", "10.77.0.0/24")...)
	want = append(want, `iifname "eth1" ip saddr != 10.78.0.0/24 jump house_spoof`)
	want = append(want, spoof("eth0.79", "desk", "10.79.0.0/30")...)
	want = append(want, spoof("eth2", "guest", "10.80.0.0/24")...)
	// First in the chain, before the drops of the agent and before the port
	// 53 and private-DNS accepts of the house, which would end the chain.
	want = append(want, `iifname "eth0.20" meta nfproto ipv6 counter drop`,
		`iifname "eth1" ip daddr @house_private_dns_v4 tcp dport { 443, 853 } accept`,
		`iifname "eth1" meta l4proto { tcp, udp } th dport 53 accept`)
	order(t, raw, "filter_prerouting", want...)
	if !strings.HasPrefix(strings.TrimLeft(raw, " "), "type filter hook prerouting priority raw; policy accept;\n    "+want[0]) {
		t.Errorf("the agent's source check does not open raw prerouting:\n%s", raw)
	}
	hs := chain(t, nft, "house_spoof")
	order(t, hs, "house_spoof",
		`ip saddr 0.0.0.0 udp sport 68 udp dport 67 ip daddr { 10.78.0.1, 255.255.255.255 } counter return`,
		`log prefix "pi-fortress house-spoof: " level info`,
		"counter drop")
	if strings.Contains(hs, "accept") {
		t.Errorf("the DHCP exception must return to raw prerouting, not accept past it:\n%s", hs)
	}
	for _, ln := range strings.Split(nft, "\n") {
		if strings.Contains(ln, "spoof") && (strings.Contains(ln, `"wlan0"`) || strings.Contains(ln, "wg0")) {
			t.Errorf("the uplink or the tunnel got a source check: %s", strings.TrimSpace(ln))
		}
	}

	// No house, no house check; a segment without a net renders nothing.
	c = load(t, Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
	c.Segments = append(c.Segments, Segment{Name: "bare", IF: "eth3", IP: "10.81.0.1"})
	nft = c.Ruleset(labElements)
	if strings.Contains(nft, "house_spoof") || strings.Contains(nft, "house-spoof") {
		t.Error("a box without a house rendered the house's source check")
	}
	if strings.Contains(nft, `iifname "eth3" ip saddr`) || strings.Contains(nft, "bare-spoof") {
		t.Error("a segment without a net rendered a source check")
	}
	if strings.Count(nft, "-spoof: ") != 1 || !strings.Contains(nft, `iifname "eth0" ip saddr != 10.77.0.0/24 counter drop`) {
		t.Errorf("want the agent's check alone:\n%s", chain(t, nft, "filter_prerouting"))
	}
}

// With --live, INT_IF and WAN_IF come from the kernel when net.env does
// not declare them. A detected name goes into the ruleset inside a quoted
// iifname match, the same as a declared one. Thus it must pass the same
// name check, and a name that fails it stops the render.
func TestLiveDetectedInterfaceNames(t *testing.T) {
	cases := []struct {
		name, intIF, wanIF string // detected names
		declaredIntIF      string
		want               string // "" means the config loads
	}{
		{name: "detected names load", intIF: "eth0", wanIF: "wlan0"},
		{name: "detected int if with a quote", intIF: `eth0"x`, wanIF: "wlan0",
			want: `INT_IF="eth0\"x", found on this box, is not an interface name`},
		{name: "detected wan if with a brace", intIF: "eth0", wanIF: "wlan0}",
			want: `WAN_IF="wlan0}", found on this box, is not an interface name`},
		{name: "detected name too long", intIF: "eth0", wanIF: "w234567890123456",
			want: `WAN_IF="w234567890123456", found on this box, is not an interface name`},
		{name: "declared int if skips detection", declaredIntIF: "eth0", intIF: `bad"`, wanIF: "wlan0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			segs := filepath.Join(dir, "segments.d")
			if err := os.Mkdir(segs, 0755); err != nil {
				t.Fatal(err)
			}
			detect := func(key, piIP string) (string, error) {
				if piIP != lab.PiIP {
					t.Fatalf("detection got PI_IP=%s", piIP)
				}
				if key == "INT_IF" {
					return tc.intIF, nil
				}
				return tc.wanIF, nil
			}
			ifaces := map[string]bool{"lo": true, "eth0": true, "wlan0": true}
			c, err := Load(Options{Net: lab, HouseEnv: "/nonexistent/house.env", SegmentsDir: segs,
				IntIF: tc.declaredIntIF, Live: true, ifaces: ifaces, liveIF: detect, Stderr: &strings.Builder{}})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("a config that must load was refused: %v", err)
			}
			if c.IntIF != "eth0" || c.WanIF != "wlan0" {
				t.Fatalf("INT_IF=%q WAN_IF=%q", c.IntIF, c.WanIF)
			}
		})
	}
}
