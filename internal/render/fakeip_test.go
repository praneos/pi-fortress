package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeipBox is a box with a house, a desk segment and a guest segment.
// Thus the forward/fakeip comparisons run over each splice point that the
// agent gate and the output chain share with the others.
func fakeipBox(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.20\n")
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\n")
	write(t, segs, "guest.env", "IF=eth2\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
	return Options{Net: labFwd, HouseEnv: house, SegmentsDir: segs}
}

// AGENT_DNS=forward is each box that existed before fakeip became the
// default. When it is written, with or without a pool, it must render the
// forward golden byte for byte. Absent (or fakeip) renders the default
// golden. On a full box, a pinned forward must give the ruleset that the
// forward fragments always gave. The fakeip fragments exist only in fakeip.
func TestAgentDNSForwardRendersExactlyWhatItDidBefore(t *testing.T) {
	for _, n := range []struct{ mode, pool, golden string }{
		{"forward", "", "nft.no-house.forward.golden"},
		{"forward", "198.18.0.0/16", "nft.no-house.forward.golden"},
		{"forward", "100.64.8.0/22", "nft.no-house.forward.golden"},
		{"", "", "nft.no-house.golden"},
		{"fakeip", "198.18.0.0/16", "nft.no-house.golden"},
	} {
		golden, err := os.ReadFile("../../vm/pi/testdata/" + n.golden)
		if err != nil {
			t.Fatal(err)
		}
		net := lab
		net.AgentDNS, net.FakeIPNet = n.mode, n.pool
		c := load(t, Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
		if got := c.Ruleset(labElements); got != string(golden) {
			t.Fatalf("AGENT_DNS=%q FAKEIP_NET=%q drifted from %s:\n%s", n.mode, n.pool, n.golden, got)
		}
	}
	o := fakeipBox(t)
	env := load(t, o).EnvFile()
	for _, want := range []string{"AGENT_DNS='forward'\n", "FAKEIP_NET='198.18.0.0/16'\n"} {
		if !strings.Contains(env, want) {
			t.Fatalf("apply.env lacks %q:\n%s", want, env)
		}
	}
	o.Net.AgentDNS = ""
	if env := load(t, o).EnvFile(); !strings.Contains(env, "AGENT_DNS='fakeip'\n") {
		t.Fatalf("an absent AGENT_DNS is not fakeip:\n%s", env)
	}
}

const (
	fakeGateLog     = `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != 198.18.0.0/16 limit rate 10/second burst 20 packets log prefix "pi-fortress agent-directip: " level info`
	fakeGateDrop    = `iifname "eth0" tcp dport 443 ct state new ip daddr != 10.77.0.1 ip daddr != 192.0.2.0/24 ip daddr != @direct_ip_v4 ip daddr != 198.18.0.0/16 counter drop`
	brokerBlacklist = `
    meta skuid "pf-broker" ip daddr @blacklist_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress broker-blacklist: " level info
    meta skuid "pf-broker" ip daddr @blacklist_v4 counter drop`
	brokerDNS = `
    meta skuid "pf-broker" ip daddr 9.9.9.9 udp dport 53 accept
    meta skuid "pf-broker" ip daddr 9.9.9.9 tcp dport 53 accept`
	brokerDoH = `
    meta skuid "pf-broker" ip daddr @dns_bypass_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress broker-doh: " level info
    meta skuid "pf-broker" ip daddr @dns_bypass_v4 counter drop`
	brokerBlock = brokerBlacklist + brokerDNS + brokerDoH
)

// Under fakeip, the agent gate lets the pool through where it let
// @resolved_v4 through. It keeps PI_IP, the echo range and the
// DirectCarve. The output of the broker gets the address blocklist before
// the conntrack accept, and a path to its resolver before the reserved
// drop. That is all: a reversal of exactly those edits gives the
// forward render. Thus nothing else about the box changed with the mode.
const (
	sshPoolCarve  = `iifname "eth0" tcp dport 22 ip daddr != 198.18.0.0/16 counter drop`
	sshPoolReject = `iifname "eth0" ip daddr 198.18.0.0/16 tcp dport 22 counter reject with tcp reset`
)

func TestFakeIPSwapsTheAgentGateAndBlocksTheBrokersDials(t *testing.T) {
	o := fakeipBox(t)
	forward := load(t, o).Ruleset(labElements)
	o.Net.AgentDNS = AgentDNSFakeIP
	c := load(t, o)
	nft := c.Ruleset(labElements)

	gate := chain(t, nft, "resolver_gate")
	for _, want := range []string{fakeGateLog, fakeGateDrop} {
		if !strings.Contains(gate, want) {
			t.Fatalf("resolver_gate lacks\n%s\n%s", want, gate)
		}
	}
	if strings.Contains(gate, "@resolved_v4") {
		t.Fatalf("the fakeip agent gate still consults @resolved_v4:\n%s", gate)
	}
	// The house and the plain segments keep their own resolved sets.
	for _, want := range []string{"@resolved_house_v4", "@resolved_guest_v4", "@resolved_desk_v4"} {
		if !strings.Contains(gate, want) {
			t.Fatalf("resolver_gate lost %s:\n%s", want, gate)
		}
	}
	if !strings.Contains(nft, "set resolved_v4 {") {
		t.Fatal("resolved_v4 is no longer declared; pf dns, status.sh and nftsets still name it")
	}

	out := chain(t, nft, "output")
	if !strings.Contains(out, brokerBlock) {
		t.Fatalf("output lacks the broker rules:\n%s", out)
	}
	order(t, out, "output",
		`log prefix "pi-fortress broker-blacklist: "`,
		`meta skuid "pf-broker" ip daddr 9.9.9.9 udp dport 53 accept`,
		`ip daddr @dns_bypass_v4 counter drop`,
		"ct state established,related accept",
		`oifname "lo" accept`,
		`meta skuid "pf-broker" ip daddr @reserved_v4 counter drop`,
		`meta skuid "pf-broker" tcp dport 443 accept`,
		`meta skuid "pf-broker" counter drop`,
	)

	// SSH to a pool address fails fast. The raw drop skips the pool, and
	// forward resets it. The reset is first after the conntrack verdicts, and
	// before the ssh_allow accept and the drops of the agent.
	raw := chain(t, nft, "filter_prerouting")
	if !strings.Contains(raw, "\n    "+sshPoolCarve+"\n") {
		t.Fatalf("the raw TCP 22 drop does not skip the pool:\n%s", raw)
	}
	fwd := chain(t, nft, "forward")
	order(t, fwd, "forward",
		"ct state established,related accept",
		"ct state invalid drop",
		sshPoolReject,
		`iifname "eth0" oifname "eth1" counter drop`,
		`iifname "eth0" tcp dport 22 counter drop`,
		`iifname "eth0" counter drop`)

	undone := strings.NewReplacer(sshPoolCarve, `iifname "eth0" tcp dport 22 counter drop`, "\n    "+sshPoolReject, "",
		" ip daddr != 198.18.0.0/16 ", " ip daddr != @resolved_v4 ", brokerBlock, "").Replace(nft)
	if undone != forward {
		t.Fatal("fakeip changed more than the agent gate, the broker's output rules and SSH to the pool")
	}
	// Forward mode has neither: the raw drop takes all agent TCP 22.
	if strings.Contains(forward, "198.18.0.0/16") || strings.Contains(forward, "tcp dport 22 counter reject") {
		t.Fatal("forward mode renders the pool's SSH rules")
	}
	// With ssh_allow.ips, the raw accept and the forward accept stay, and
	// the reset is before the forward accept.
	e := labElements
	e.SSHAllow = "elements = { 203.0.113.22 }"
	withSSH := c.Ruleset(e)
	order(t, chain(t, withSSH, "filter_prerouting"), "filter_prerouting",
		`iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 accept`, sshPoolCarve)
	order(t, chain(t, withSSH, "forward"), "forward",
		sshPoolReject, `iifname "eth0" tcp dport 22 ip daddr @ssh_allow_v4 ct state new`, `iifname "eth0" tcp dport 22 counter drop`)
	if env := c.EnvFile(); !strings.Contains(env, "AGENT_DNS='fakeip'\n") {
		t.Fatalf("apply.env: %s", env)
	}
}

// The DNS_UPSTREAM of the broker is usually a public resolver that the
// DoH/DoT feed lists. With the bypass drop before the upstream accept, the
// broker resolved nothing, and each agent connection got a 502 (a new cloud
// lab, 2026-10-03). The blacklist drop still wins over the upstream.
func TestFakeIPBrokerReachesAListedUpstream(t *testing.T) {
	net := lab
	net.AgentDNS = AgentDNSFakeIP
	e := labElements
	e.DoH = "elements = { 9.9.9.9, 198.51.100.7 }"
	out := chain(t, load(t, Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}).Ruleset(e), "output")
	order(t, out, "output",
		`meta skuid "pf-broker" ip daddr @blacklist_v4 counter drop`,
		`meta skuid "pf-broker" ip daddr 9.9.9.9 udp dport 53 accept`,
		`meta skuid "pf-broker" ip daddr 9.9.9.9 tcp dport 53 accept`,
		`meta skuid "pf-broker" ip daddr @dns_bypass_v4 counter drop`,
		`meta skuid "pf-broker" tcp dport 443 accept`)
	if strings.Contains(out, `meta skuid "pf-broker" ip daddr 9.9.9.9 tcp dport 443`) || strings.Contains(out, "dport 853 accept") {
		t.Fatalf("the upstream carve opened more than port 53:\n%s", out)
	}
}

// With DoT on, the resolver of the broker is the stub on 127.0.0.1. The lo
// accept already passes it, so the ruleset opens no upstream to it. A port
// on DNS_UPSTREAM is the port that the ruleset opens. Paranoid still
// removes the carve. A pool that the operator moved is the pool that the gate names.
func TestFakeIPVariants(t *testing.T) {
	net := lab
	net.AgentDNS = AgentDNSFakeIP
	base := Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}

	dot := base
	dot.Net.DoTAuthName, dot.Net.DoTIPs = "dns.quad9.net", "9.9.9.9 149.112.112.112"
	nft := load(t, dot).Ruleset(labElements)
	if strings.Contains(nft, `meta skuid "pf-broker" ip daddr 9.9.9.9`) || !strings.Contains(nft, brokerBlacklist+brokerDoH) {
		t.Fatalf("DoT on: the broker must resolve over lo and nothing else:\n%s", chain(t, nft, "output"))
	}

	ported := base
	ported.Net.DNSUpstream = "9.9.9.9#5353"
	if nft := load(t, ported).Ruleset(labElements); !strings.Contains(nft, `meta skuid "pf-broker" ip daddr 9.9.9.9 udp dport 5353 accept`) {
		t.Fatalf("DNS_UPSTREAM#port:\n%s", chain(t, nft, "output"))
	}

	par := base
	par.Paranoid = true
	gate := chain(t, load(t, par).Ruleset(labElements), "resolver_gate")
	if strings.Contains(gate, "@direct_ip_v4") || !strings.Contains(gate, `ip daddr != 192.0.2.0/24 ip daddr != 198.18.0.0/16 counter drop`) {
		t.Fatalf("paranoid fakeip gate:\n%s", gate)
	}

	moved := base
	moved.Net.FakeIPNet = "100.64.8.0/22"
	if gate := chain(t, load(t, moved).Ruleset(labElements), "resolver_gate"); !strings.Contains(gate, "ip daddr != 100.64.8.0/22 counter drop") {
		t.Fatalf("moved pool:\n%s", gate)
	}
}

func TestFakeIPNetIsValidated(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "lab.env", "IF=eth2\nNET=198.18.4.0/24\nIP=198.18.4.1\n")
	house := write(t, dir, "house.env", "HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\n")
	for _, tc := range []struct {
		name, mode, pool, segs, house, want string
	}{
		{name: "mode", mode: "fake", want: "AGENT_DNS='fake'"},
		{name: "not a prefix", pool: "198.18.0.0", want: "FAKEIP_NET='198.18.0.0' is not an IPv4 CIDR"},
		{name: "not an address", pool: "nope/16", want: "FAKEIP_NET='nope/16' is not an IPv4 CIDR"},
		{name: "host bits", pool: "198.18.0.1/16", want: "write the network itself, 198.18.0.0/16"},
		{name: "too small", pool: "198.18.0.0/25", want: "FAKEIP_NET='198.18.0.0/25' is a /25"},
		{name: "too large", pool: "198.18.0.0/15", want: "FAKEIP_NET='198.18.0.0/15' is a /15"},
		{name: "loopback", pool: "127.0.0.0/16", want: "overlaps 127.0.0.0/8"},
		{name: "link-local", pool: "169.254.0.0/16", want: "overlaps 169.254.0.0/16"},
		{name: "public", pool: "8.8.0.0/16", want: "FAKEIP_NET='8.8.0.0/16' is not inside"},
		{name: "echo range", pool: "192.0.2.0/24", want: "is not inside"},
		{name: "agent net", pool: "10.77.0.0/16", want: "FAKEIP_NET=10.77.0.0/16 overlaps AGENT_NET=10.77.0.0/24"},
		{name: "house net", pool: "10.78.0.0/24", house: house, want: "overlaps HOUSE_NET=10.78.0.0/24"},
		{name: "segment", segs: segs, want: "FAKEIP_NET=198.18.0.0/16 overlaps segment lab NET=198.18.4.0/24"},
		{name: "segment under forward too", mode: "forward", segs: segs, want: "overlaps segment lab NET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := lab
			net.AgentDNS, net.FakeIPNet = tc.mode, tc.pool
			if tc.mode == "" {
				net.AgentDNS = AgentDNSFakeIP
			}
			o := Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}
			if tc.segs != "" {
				o.SegmentsDir = tc.segs
			}
			if tc.house != "" {
				o.HouseEnv = tc.house
			}
			_, err := Load(o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want one containing %q", err, tc.want)
			}
		})
	}
	// The ends of the size range and each home range load.
	for _, pool := range []string{"198.18.0.0/16", "198.19.255.0/24", "10.200.0.0/16", "172.20.0.0/20", "192.168.200.0/24", "100.127.0.0/16"} {
		net := lab
		net.AgentDNS, net.FakeIPNet = AgentDNSFakeIP, pool
		if _, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}); err != nil {
			t.Fatalf("FAKEIP_NET=%s refused: %v", pool, err)
		}
	}
}

// An AGENT_NET wider than a /8 holds public addresses, and a /0 holds all
// of them. No pool can be outside it. The refusal names AGENT_NET, the key
// to change, and not FAKEIP_NET.
func TestAgentNetTooWideIsRefused(t *testing.T) {
	for _, v := range []string{"0.0.0.0/0", "0.0.0.0/1", "10.0.0.0/7"} {
		net := lab
		net.AgentNet = v
		_, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
		if err == nil || !strings.HasPrefix(err.Error(), "AGENT_NET="+v+" is wider than /8") {
			t.Errorf("AGENT_NET=%s: err=%v", v, err)
		}
	}
	net := lab
	net.AgentNet = "10.0.0.0/8"
	if _, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"}); err != nil {
		t.Fatalf("AGENT_NET=10.0.0.0/8 refused: %v", err)
	}
}

// The refusal names net.env when the caller gave it, and has no empty
// brackets when not.
func TestFakeIPOverlapNamesTheEnvFile(t *testing.T) {
	net := lab
	net.AgentDNS, net.FakeIPNet = AgentDNSFakeIP, "10.77.0.0/16"
	_, err := Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
	if err == nil || strings.Contains(err.Error(), "()") || !strings.HasSuffix(err.Error(), "a network the Pi is on") {
		t.Fatalf("no EnvSrc: err=%v", err)
	}
	net.EnvSrc = "/etc/pi-fortress/net.env"
	_, err = Load(Options{Net: net, HouseEnv: "/nonexistent/house.env", SegmentsDir: "/nonexistent"})
	if err == nil || !strings.HasSuffix(err.Error(), "a network the Pi is on (/etc/pi-fortress/net.env)") {
		t.Fatalf("with EnvSrc: err=%v", err)
	}
}
