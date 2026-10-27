package render

import (
	"strconv"
	"strings"
	"text/template"
)

// Elements are the nft set bodies that pf compile wrote, without the trailing
// newline. Thus an empty list renders an empty set exactly as before.
type Elements struct {
	Blacklist, DoH, DirectIP, SSHAllow string
	// HouseDirectIP is house_direct_ip.allow. DirectIP is the list of the agent.
	HouseDirectIP string
	// HousePrivateDNS is house_private_dns.ips, rendered only with
	// HOUSE_PRIVATE_DNS=on.
	HousePrivateDNS string
	// HouseWhatsApp is house_whatsapp.ips, rendered unless
	// HOUSE_ALLOW_WHATSAPP=off.
	HouseWhatsApp string
	// NTPPass is ntp_pass.ips, the NTP and NTS servers that a segment with
	// NTP=pass can reach. It is rendered only when a segment has NTP=pass.
	NTPPass string
}

type fragments struct {
	*Config
	Elements
	HouseSet, HouseRaw, HouseInput, HouseIsolate, HouseForward, HouseNAT, HouseGate string
	HouseDNSFlood                                                                   string
	SegRaw, SegInput, SegIsolate, SegForward, SegNAT, TrunkDrop                     string
	SegSet, SegDNSFlood, SegGate, SegEgressChains                                   string
	// SegPrerouting is the 443 redirect of each INSPECT=on segment, in nat
	// prerouting next to the redirect of the agent network.
	SegPrerouting string
	// NTPRedirect is the NTP redirect of the house and of each plain segment,
	// in nat prerouting (ntpRedirect).
	NTPRedirect string
	// NTPPassSet is the ntp_pass_v4 set, only when a segment has NTP=pass.
	NTPPassSet             string
	SSHSet, SSHRaw, SSHFwd string
	DoTOutput              string
	// DoTOutputCT is before the conntrack accept in output. It holds
	// only the invariant that a policy change can make true of an
	// already-admitted flow. An apply that enables DoT does not flush
	// conntrack. Without this, a plaintext query socket opened before DoT
	// would continue to use the established accept. Its scope is
	// established,related. The rules further down decide new flows.
	DoTOutputCT string
	// HouseKill is the kill switch of the WireGuard house for each state.
	// It is first in forward, before HouseSNI and the conntrack accept. House
	// traffic leaves by the uplink only with the bypass mark.
	HouseKill string
	// HouseSNI holds the pending 443 flows of the house for the name check
	// of pf dns (houseSNI). It is in forward, after HouseKill.
	HouseSNI string
	// HouseSNIChain is house_sni_flood, where a packet over the per-source
	// meter of the SNI queue is logged and dropped (sniQueueRate).
	HouseSNIChain string
	// HouseEgressChain is the house_egress chain HouseForward jumps to
	// unless HOUSE_EGRESS=open (houseEgress).
	HouseEgressChain string
	// WanSSH and WanPing are the way in through the uplink. WanOutput stops
	// name broadcasts out of it. UNTRUSTED_UPLINK=1 replaces the first two with
	// the third (docs/user_guide/public_wifi.md).
	WanSSH, WanPing, WanOutput string
	// DirectCarve is the @direct_ip_v4 exemption of the agent gate. Paranoid
	// removes it (docs/paranoid_mode.md K5), so the address list of the
	// operator cannot skip the forward allow set. The house gate reads its own
	// @house_direct_ip_v4, which paranoid does not change.
	DirectCarve string
	// AgentGateAllow is the last exemption on the agent gate: the answers of
	// the resolver. Forward mode checks @resolved_v4. fakeip checks the pool
	// (fakeIPGate).
	AgentGateAllow string
	// AgentResolvedSet is the declaration of resolved_v4 (resolvedSet).
	AgentResolvedSet string
	// BrokerBlockCT is the fakeip output rules for the connections of the
	// broker (fakeIPGate): the blocklists and the path to its resolver. Empty
	// under forward.
	BrokerBlockCT string
	// SSHPoolCarve and SSHPoolReject are the fakeip fast failure for SSH to a
	// pool address (fakeIPGate). The raw TCP 22 drop skips the pool, and
	// forward answers it with a reset. Both are empty under forward.
	SSHPoolCarve, SSHPoolReject string
	// AgentConnLimit (input) and ConnLimitFwd (top of forward) are the
	// connection budgets. ConnSets and ConnChains are the dynamic sets and
	// the over-limit chains that they use (connlimit.go).
	AgentConnLimit, ConnLimitFwd, ConnSets, ConnChains string
	// AgentPing is the per-source echo meter of the agent (pingMeter).
	AgentPing string
	// SpoofRaw opens filter_prerouting with the source check of each segment.
	// SpoofChain is house_spoof, the DHCP exception of the house
	// (antiSpoof).
	SpoofRaw, SpoofChain string
	// DNSNoTrack (raw prerouting), DNSNoTrackOut (raw output) and
	// DNSReplyOut (filter output) exclude UDP DNS to the Pi from the
	// conntrack table (dnsNoTrack).
	DNSNoTrack, DNSNoTrackOut, DNSReplyOut string
	// IsolateCT is in forward, before the conntrack accept. It sends each
	// established packet to IsolateCTChain, isolate_ct (isolateCT). ctHoles
	// and ctDrops are its rules, which house and segments collect.
	IsolateCT, IsolateCTChain string
	ctHoles, ctDrops          []string
}

// Ruleset renders /etc/nftables.conf. Each fragment starts with a newline
// and goes at the end of an existing rule line. Thus an absent house, no
// segments and no DoT render byte-for-byte what they rendered before each
// existed. vm/pi/testdata/nft.no-house.golden holds that.
func (c *Config) Ruleset(e Elements) string {
	f := fragments{Config: c, Elements: e, DirectCarve: " ip daddr != @direct_ip_v4", AgentGateAllow: " ip daddr != @resolved_v4", AgentResolvedSet: resolvedSet("resolved_v4")}
	if c.Paranoid {
		f.DirectCarve = ""
	}
	if c.AgentDNS == AgentDNSFakeIP {
		f.fakeIPGate()
	}
	f.antiSpoof()
	f.dnsNoTrack()
	f.house()
	f.segments()
	f.isolateCT()
	f.sshAllow()
	f.ntpPassSet()
	f.uplink()
	f.connLimits()
	f.AgentPing = pingMeter("\n    iifname \""+c.IntIF+"\" ", "agent")
	if c.DoTIPs != "" {
		f.DoTOutput = "\n    meta skuid \"pf-dns\" ip daddr { " + strings.Join(c.dotPinIPs(), ", ") + " } tcp dport 853 accept" +
			f.tunnelDNS() +
			"\n    meta skuid \"pf-dns\" counter drop" +
			"\n    udp dport 53 oifname != \"lo\" counter drop" +
			"\n    tcp dport 53 oifname != \"lo\" counter drop"
		f.DoTOutputCT = "\n    meta skuid \"pf-dns\" tcp dport 853 ip daddr != { " + strings.Join(c.dotPinIPs(), ", ") + " } ct state established,related counter drop" +
			f.tunnelDNSCT()
	}
	var b strings.Builder
	if err := nftTemplate.Execute(&b, f); err != nil {
		panic(err)
	}
	return b.String()
}

// tunnelDNS is the single plaintext port 53 that the DoT output pins let
// past them. It exists only for a WireGuard house. That house resolves at
// the far end of the tunnel, not through its own stub. config.go sets
// HouseDNSForward to 10.64.0.1@WG_IF, and pf dns forwards the house
// segment there over a socket bound to WG_IF (internal/dnsd). The reason:
// the far end is reached over an encrypted link, and a DoT stub would
// instead send the queries of the house out the WAN.
//
// pf dns is the resolver that sends it. Thus the scope of the accept is the
// pf-dns user, and the accept is above the drop of that user. Before, it
// was below that drop, from the time when dnsmasq resolved for the house
// under its own user. With pf dns as the house resolver, that order dropped
// each tunnelled lookup (found on the first hardware run, 2026-09-23). The
// opening is one address, on one interface that exists only while the
// tunnel is up, for one user. The pin of the stub to its provider does not
// change otherwise. Nothing gets plaintext 53 over the WAN, which is the
// property that the pins hold.
func (f *fragments) tunnelDNS() string {
	if f.WGIF == "" {
		return ""
	}
	addr, _, ok := strings.Cut(f.HouseDNSForward, "@")
	if !ok || addr == "" {
		return ""
	}
	return "\n    meta skuid \"pf-dns\" ip daddr " + addr + " udp dport 53 oifname \"" + f.WGIF + "\" accept" +
		"\n    meta skuid \"pf-dns\" ip daddr " + addr + " tcp dport 53 oifname \"" + f.WGIF + "\" accept"
}

// tunnelDNSCT is the pre-conntrack form of the plaintext 53 drops. lo is
// always exempt. With a tunnel resolver, that one address on the tunnel
// is also exempt -- the same carve-out that tunnelDNS makes for new flows.
// It is written as drops, so nothing here can accept past the uid pins below.
func (f *fragments) tunnelDNSCT() string {
	addr, _, _ := strings.Cut(f.HouseDNSForward, "@")
	var out string
	for _, p := range []string{"udp", "tcp"} {
		if f.tunnelDNS() == "" {
			out += "\n    " + p + " dport 53 oifname != \"lo\" ct state established,related counter drop"
			continue
		}
		out += "\n    " + p + " dport 53 oifname != { \"lo\", \"" + f.WGIF + "\" } ct state established,related counter drop" +
			"\n    " + p + " dport 53 oifname \"" + f.WGIF + "\" ip daddr != " + addr + " ct state established,related counter drop"
	}
	return out
}

// dotPinIPs is all addresses that a stub can connect to: the addresses of
// the agent provider first, in the order from DOT_IPS, then the addresses
// that the house provider adds. The two stubs run as pf-dns. Thus one uid
// rule carries the union, not two rules that must agree about which stub
// is which. Because the DOT_IPS order stays, a box that gets a house
// provider sees the rule grow, not change its order.
func (c *Config) dotPinIPs() []string {
	seen := map[string]bool{}
	var out []string
	for _, ips := range []string{c.DoTIPs, c.HouseDoTIPs} {
		for _, d := range strings.Fields(ips) {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// fakeIPGate is the AGENT_DNS=fakeip side of the ruleset. pf dns stops
// forwarding for the agent segment. It answers each A query with an
// address from FAKEIP_NET, one name for each address. Thus the only
// addresses that an agent can have learned by name are pool addresses. Its
// 443 connections to them are redirected to the TLS engine, as for all
// other agent 443 flows. The broker resolves and connects to the real name
// itself, from the Pi.
//
// The agent gate thus replaces @resolved_v4 with the pool. It keeps all
// else that it had: PI_IP, the 192.0.2.0/24 echo range, and the
// DirectCarve. direct_ip.allow is operator policy for destinations that
// have no name, and fakeip has no name to give them. Thus they stay
// reachable by address. paranoid still removes the carve as before.
// @resolved_v4 itself stays declared: pf dns can still feed it, status.sh
// counts it, nftsets keeps it across a reload, and a set that nothing
// reads costs nothing.
//
// What moves is the address blocklist. In forward mode, the packets of the
// agent carry the real address, and filter_prerouting drops @blacklist_v4
// and @dns_bypass_v4 on the way in. Under fakeip, they carry a pool
// address, which is in neither set. The real address only appears on the
// connection of the broker out of the Pi -- the output hook. Thus the
// ruleset enforces the same two sets there, on the pf-broker uid. They are
// before the conntrack accept for the same reason as DoTOutputCT: a feed
// refresh that lists an address must end a connection that the broker
// already has to it. The raw-priority drop on the agent side always did
// this. The prefixes end in -blacklist and -doh, so pf observe files them
// as the "broker" segment with the threat that it already knows.
//
// The rest of the broker output is the rule that was already there: lo
// (the resolvers of the Pi), then TCP 443 to all addresses not in
// @reserved_v4, then drop. Its lookups need a resolver that it can reach.
// With DoT on, that is the stub on 127.0.0.1, over lo, which the lo accept
// already passes. With DoT off, /etc/resolv.conf is what the DHCP of the
// uplink gave, usually a LAN router in @reserved_v4, and the broker drop
// refuses it. Thus the broker is pointed at DNS_FORWARD. This rule opens
// exactly that address and port for the pf-broker uid, the same plaintext
// forward that pf dns itself makes to it in forward mode. It is before the
// @reserved_v4 drop, because the DNS_UPSTREAM of an operator can be their
// own router. It is before the @dns_bypass_v4 drop, because DNS_UPSTREAM
// is more often a public resolver (the 9.9.9.9 of the lab) that the
// DoH/DoT feed lists. That drop is for 443 and 853 to a resolver. With
// that drop first, the broker could resolve nothing, and each agent
// connection was a 502. The rule stays after the @blacklist_v4 drop, so a
// listed address is still dropped.
func (f *fragments) fakeIPGate() {
	f.AgentGateAllow = " ip daddr != " + f.FakeIPNet
	// SSH to a name resolves to a pool address that TCP 22 never reaches:
	// only 443 is redirected to the engine. The raw drop made
	// `ssh host.example` wait for the full connect timeout. A reset in
	// forward makes it fail at once with "connection refused". The raw drop
	// still takes all other addresses, so it gives forward only TCP 22 to the
	// pool. The reject is the first rule after the conntrack verdicts, before
	// the isolation drops and the ssh_allow accept. Thus it applies whatever
	// the pool route or ssh_allow.ips says. A rejected SYN never confirms a
	// conntrack entry. Thus a flood of them costs the table nothing, and each
	// reset goes to its sender.
	f.SSHPoolCarve = " ip daddr != " + f.FakeIPNet
	f.SSHPoolReject = "\n    iifname \"" + f.IntIF + "\" ip daddr " + f.FakeIPNet + " tcp dport 22 counter reject with tcp reset"
	b := "\n    meta skuid \"pf-broker\" "
	block := func(set, name string) string {
		return b + "ip daddr @" + set + logRate + "\"pi-fortress broker-" + name + ": \" level info" +
			b + "ip daddr @" + set + " counter drop"
	}
	f.BrokerBlockCT = block("blacklist_v4", "blacklist")
	if f.DNSForward != DoTAddr {
		addr, port, ok := strings.Cut(f.DNSForward, "#")
		if !ok {
			port = "53"
		}
		for _, p := range []string{"udp", "tcp"} {
			f.BrokerBlockCT += b + "ip daddr " + addr + " " + p + " dport " + port + " accept"
		}
	}
	f.BrokerBlockCT += block("dns_bypass_v4", "doh")
}

// uplink: a trusted uplink answers SSH and ping. An untrusted uplink answers
// only DHCP replies, and the Pi stops the announcement of its name on it.
func (f *fragments) uplink() {
	wan := "\n    iifname \"" + f.WanIF + "\" "
	if f.UntrustedUplink == "1" {
		f.WanOutput = "\n    oifname \"" + f.WanIF + "\" udp dport { 5353, 5355 } counter drop"
		return
	}
	// Per source, not shared. The single 30/minute budget that this replaced
	// was shared by all hosts. Any host on the uplink could use it with a SYN
	// every two seconds and lock the owner out of the Pi. The numbers are
	// the old ones -- make pi-ship and the real-Pi e2e open a burst of
	// sessions from the one desktop, and that source alone still gets the
	// full budget. It is an over-limit drop followed by the accept, not an
	// accept inside the meter, so it fails open. A spoofing flood that fills
	// the set of the meter disables the limit (the MaxStartups of sshd still
	// applies). It does not refuse each source that it has not seen yet, the
	// owner included.
	f.WanSSH = wan + "tcp dport 22 ct state new meter wan_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop" +
		wan + "tcp dport 22 ct state new accept"
	f.WanPing = pingMeter(wan, "wan") + wan + "icmp type echo-request accept"
}

// pingMeter limits echo requests to the Pi for each source address, before
// the echo accept of each segment. Before, the agent, house and segment
// accepts had no limit at all, and the uplink accept had one budget shared
// by all hosts on it. Ten each second with a burst of twenty is far more
// than what ping or a monitoring probe sends. It fails open for the same
// reason as WanSSH. The excess goes on to the drop of the chain.
func pingMeter(in, name string) string {
	return in + "icmp type echo-request meter " + name + "_ping { ip saddr limit rate over 10/second burst 20 packets } counter drop"
}

// An empty ssh_allow.ips emits nothing: no set, no accept, and the TCP 22
// drops stay as they always were.
func (f *fragments) sshAllow() {
	if f.SSHAllow == "" {
		return
	}
	in := func(s string) string { return "\n    iifname \"" + f.IntIF + "\" " + s }
	f.SSHSet = "\n\n  set ssh_allow_v4 {\n    type ipv4_addr\n    flags interval\n    " + f.SSHAllow + "\n  }"
	// No ct state and no rate limit here. Priority raw is before conntrack,
	// so ct state new is never true, and a per-packet limit would stop the
	// session at burst. forward has both.
	f.SSHRaw = in("tcp dport 22 ip daddr @ssh_allow_v4 accept")
	f.SSHFwd = in("tcp dport 22 ip daddr @ssh_allow_v4 ct state new limit rate 30/minute burst 60 packets log prefix \"pi-fortress ssh-allow: \" level info counter accept")
}

// houseVPN drops the VPN of a house device, so its traffic and its DNS
// cannot go around the house resolver and gates. The match for WireGuard
// is its message header, not a port, because a client can select any port
// (Mullvad offers 53 and 443, and others). The first four payload bytes
// are the message type and three zero bytes. The handshake messages have
// fixed sizes (initiation 148, response 92, cookie 64, plus 8 for the UDP
// header). Transport data is a minimum of 32 bytes. OpenVPN has no such
// fixed header, so the match is its port. These rules are above the
// private-DNS and port-53 accepts, which would otherwise pass WireGuard
// sent to 53. IPsec (UDP 500/4500) does not change: Wi-Fi calling uses it.
// The tunnel of the Pi leaves from the Pi, not eth1, and does not change.
func houseVPN(in func(string) string) string {
	var out string
	for _, m := range []string{
		"udp length 156 @th,64,32 0x01000000",
		"udp length 100 @th,64,32 0x02000000",
		"udp length 72 @th,64,32 0x03000000",
		"udp length >= 40 @th,64,32 0x04000000",
		"meta l4proto { tcp, udp } th dport 1194",
	} {
		out += in(m+logRate+"\"pi-fortress house-vpn: \" level info") + in(m+" counter drop")
	}
	return out
}

// The marks of the SNI check are in bits 20-23 of the conntrack mark and
// of the packet mark, away from the WireGuard bypass mark (0x1). The house
// gate sets pending. ok and bad come back from pf dns as the packet mark
// on a repeat verdict, and are copied to the flow here.
const (
	sniBits    = "0x00f00000"
	sniKeep    = "0xff0fffff"
	sniPending = "0x00100000"
	sniOK      = "0x00200000"
	sniBad     = "0x00300000"
	// SNIQueue is the NFQUEUE number from which pf dns reads the pending
	// flows. No bypass: when pf dns is down, the packets are dropped. The
	// gate did this before it asked.
	SNIQueue = "1"
)

// houseSNI is near the top of forward. It is after the WireGuard kill
// switch (HouseKill, which masks the SNI bits out of its mark compare,
// because an accepted queued packet leaves forward here). It is before
// the conntrack accept (a pending flow is established after its
// handshake, but must still be held). The bits are cleared from the
// packet here, so the bypass accept further down compares the full mark.
// Only the direction of the device is queued. The handshake itself passes,
// because the name arrives only with the first data. An ok flow is never
// queued again. By then, the addresses that its name resolved to are in
// resolved_house_v4, so the next flow skips all of this.
func houseSNI(in func(string) string) string {
	return in("meta mark and "+sniBits+" == "+sniOK+" ct mark set ct mark and "+sniKeep+" or "+sniOK+" meta mark set meta mark and "+sniKeep) +
		in("meta mark and "+sniBits+" == "+sniBad+" ct mark set ct mark and "+sniKeep+" or "+sniBad+" meta mark set meta mark and "+sniKeep) +
		in("ct mark and "+sniBits+" == "+sniBad+logRate+"\"pi-fortress house-sni: \" level info") +
		in("ct mark and "+sniBits+" == "+sniBad+" counter reject with tcp reset") +
		in("ct mark and "+sniBits+" == "+sniPending+" meter house_sni_queue { ip saddr limit rate over "+sniQueueRate+" } jump house_sni_flood") +
		in("ct mark and "+sniBits+" == "+sniPending+" counter queue num "+SNIQueue)
}

// sniQueueRate is the number of packets of pending flows that one house
// address can put on the SNI queue. The kernel queue holds 1024 packets
// (internal/nfq) for the full house. pf dns keeps the packets of a flow on
// it until the name gets an answer or sniWait (5 s) ends. Without a
// per-source meter, one device that opens flows and never completes its
// ClientHello holds all slots. The pending flows of all other devices are
// dropped while it does. At this rate, one address holds a maximum of
// 100 x 5 + 300 = 800 packets. This leaves a quarter of the queue for the
// rest of the house, also against a device that does its worst. A flow
// that the check passes is never queued again.
//
// A browser puts about four packets of a new flow on the queue (SYN, ACK
// and a ClientHello of one or two segments, two with a post-quantum key
// share). Thus the burst is about 75 new TLS flows at the same time, and
// the rate is 25 each second after it. This is far more than a page load,
// which uses its connections again and opens a maximum of six per host.
const sniQueueRate = "100/second burst 300 packets"

// houseSNIFlood is where a packet over sniQueueRate goes. It is dropped,
// not accepted, because an accept would let a TLS flow past the name check
// (strict egress checks each new flow on the TLS ports). It is not reset,
// because the next retransmit usually fits under the meter again, and a
// reset would change the burst of a device into a failed page load. It is
// logged at most ten times each second under its own prefix. Thus a
// device that hits the meter appears by address in the journal.
const houseSNIFlood = "\n\n  chain house_sni_flood {" +
	"\n   " + logRate + "\"pi-fortress house-sniflood: \" level info" +
	"\n    counter drop\n  }"

// houseTLSPorts are the TCP ports that strict egress lets out as TLS, with
// each new flow checked by name: HTTPS, 8443, Apple and Google push (5223,
// 5228), IMAPS and SMTPS. Push on a phone with Private DNS works because
// the check resolves the name that the phone sends, not a name that the
// house gave out.
var houseTLSPorts = []string{"443", "465", "993", "5223", "5228", "8443"}

// houseSTARTTLSPorts are the mail ports that strict egress lets out with no
// name check: IMAP (143) and SMTP submission (587). These start in clear
// text and change to TLS with STARTTLS. Thus the first packet is not a TLS
// ClientHello and has no name to check. Do not put them in houseTLSPorts:
// the name check would drop each flow.
const houseSTARTTLSPorts = "143, 587"

// houseCallUDP is the STUN/TURN and media of the call apps: 3478-3497 STUN
// and TURN (Teams, WhatsApp, FaceTime), 8801-8810 Zoom, 16384-16403
// FaceTime, 19302-19309 Google Meet. Without it, these apps relay over
// TCP 443, which strict lets out after the name check.
const houseCallUDP = "3478-3497, 8801-8810, 16384-16403, 19302-19309"

// houseEgress is the port policy of the house. It is a regular chain that
// forward jumps to after the isolation and the local-network drop, and
// before the tunnel and uplink accepts. Thus the kill switch below it does
// not change. Allowed traffic returns to forward. Strict drops the rest.
// Audit logs it under its own prefix and returns. Thus the log shows what
// strict would break before an operator enables strict.
// It has no time port: NTP never comes here (ntpRedirect).
func (f *fragments) houseEgress() string {
	r := func(s string) string { return "\n    " + s }
	body := r("tcp dport 80 return") +
		r("tcp dport { "+strings.Join(houseTLSPorts, ", ")+" } return") +
		r("tcp dport { "+houseSTARTTLSPorts+" } return") +
		r("icmp type echo-request limit rate 10/second burst 20 packets return")
	if f.HouseAllowWiFiCalling == "on" {
		body += r("udp dport { 500, 4500 } return") + r("meta l4proto esp return")
	}
	if f.HouseAllowWhatsApp != "off" {
		body += r("tcp dport 5222 ip daddr @house_whatsapp_v4 return")
	}
	if f.HouseAllowCallUDP == "on" {
		body += r("udp dport { " + houseCallUDP + " } return")
	}
	if f.HouseAllowTCP != "" {
		body += r("tcp dport { " + f.HouseAllowTCP + " } return")
	}
	if f.HouseAllowUDP != "" {
		body += r("udp dport { " + f.HouseAllowUDP + " } return")
	}
	if f.HouseEgress == "audit" {
		body += r("limit rate 10/second burst 20 packets log prefix \"pi-fortress house-audit: \" level info") + r("counter")
	} else {
		body += r("limit rate 10/second burst 20 packets log prefix \"pi-fortress house-port: \" level info") + r("counter drop")
	}
	return "\n\n  chain house_egress {" + body + "\n  }"
}

// houseSNIPorts are the TLS ports that the strict gate checks by name: all
// of houseTLSPorts except each port that HOUSE_ALLOW_PORTS names for TCP.
// That is the way out for the operator, for a client that sends no name.
func (f *fragments) houseSNIPorts() string {
	allowed := map[string]bool{}
	for _, p := range strings.Split(f.HouseAllowTCP, ", ") {
		if lo, hi, ok := strings.Cut(p, "-"); ok {
			for _, t := range houseTLSPorts {
				if atoiOK(lo) <= atoiOK(t) && atoiOK(t) <= atoiOK(hi) {
					allowed[t] = true
				}
			}
			continue
		}
		allowed[p] = true
	}
	var out []string
	for _, t := range houseTLSPorts {
		if !allowed[t] {
			out = append(out, t)
		}
	}
	return strings.Join(out, ", ")
}

func atoiOK(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// logRate is the limit of the blacklist log. The direct-IP and DoH/DoT
// logs use it too. observe classifies by the prefix suffix.
const logRate = " limit rate 10/second burst 20 packets log prefix "

// antiSpoof is the source check on each segment that the Pi serves: the
// agent segment, the house and each plain segment in segments.d (the desk
// seat is one). If the source of a packet is not in the subnet of its
// interface, the packet is logged as <segment>-spoof and dropped. This is
// the first step in raw prerouting, before all accepts in that chain (the
// port 53 and private-DNS accepts of the house end it) and before
// conntrack. Without it, a desk seat that forwards could carry packets of
// an agent in on the desk VLAN. The forward accept of the desk would pass
// them. The agent-net masquerade rule, which matches only on source, would
// NAT them out. The uplink is not checked: anything can arrive on it. The
// tunnel is not checked either: its replies come from anywhere.
//
// The one legitimate outside source is the DHCP of the house. A client with
// no lease sends DISCOVER and REQUEST from 0.0.0.0, to broadcast or to the
// Pi. The house jumps to house_spoof, which returns those packets to the
// chain and does not accept them. Thus the rest of raw prerouting still
// sees them. The house gets this exception, and a plain segment with
// DHCP=on also gets it, each in its own chain. The agent segment and a
// plain segment without DHCP are static, and their input chains drop port
// 67 in all cases.
//
// rp_filter does not change (loose, 2, on these interfaces: the
// per-interface default of systemd, which wins over all=1 from provision
// because the kernel uses the larger of the two). Strict rp_filter would
// drop the same packets as this check on a directly connected subnet, but
// silently, with no log for pf observe and no counter in the ruleset. It
// would need a sysctl key for each interface, including the VLAN children
// that apply creates, kept the same as segments.d. Its verdict is a route
// lookup through the policy rules that wg-routes.sh adds and removes with
// the tunnel (fwmark WG_BYPASS_MARK, from HOUSE_NET to table 100, the
// blackhole behind it). Thus a routing change there could silently start
// to drop a house. One check, with the nets written out, logged and
// tested here, is the correct one to keep.
func (f *fragments) antiSpoof() {
	drop := func(ifname, name, net string) string {
		m := "\n    iifname \"" + ifname + "\" ip saddr != " + net
		return m + logRate + "\"pi-fortress " + name + "-spoof: \" level info" + m + " counter drop"
	}
	if f.AgentNet != "" {
		f.SpoofRaw = drop(f.IntIF, "agent", f.AgentNet)
	}
	if f.HouseIF != "" && f.HouseNet != "" {
		f.SpoofRaw += "\n    iifname \"" + f.HouseIF + "\" ip saddr != " + f.HouseNet + " jump house_spoof"
		f.SpoofChain = dhcpSpoofChain("house_spoof", "house", f.HouseIP)
	}
	for _, s := range f.Segments {
		if s.IF == "" || s.Net == "" {
			continue
		}
		// A plain segment with DHCP=on serves leases as the house does, and
		// gets the exception of the house. It is in its own chain, so the
		// spoof log keeps the name of the segment.
		if s.DHCP == "on" {
			chain := "seg_" + nftName(s.Name) + "_spoof"
			f.SpoofRaw += "\n    iifname \"" + s.IF + "\" ip saddr != " + s.Net + " jump " + chain
			f.SpoofChain += dhcpSpoofChain(chain, s.Name, s.IP)
			continue
		}
		f.SpoofRaw += drop(s.IF, s.Name, s.Net)
	}
}

// dhcpSpoofChain is the source check of a segment on which the Pi leases
// addresses. A client with no lease sends DISCOVER and REQUEST from
// 0.0.0.0 to broadcast or to the Pi. Only those packets are returned to raw
// prerouting. All other packets from outside the subnet are logged and dropped.
func dhcpSpoofChain(chain, name, ip string) string {
	return "\n\n  chain " + chain + " {" +
		"\n    ip saddr 0.0.0.0 udp sport 68 udp dport 67 ip daddr { " + ip + ", 255.255.255.255 } counter return" +
		"\n   " + logRate + "\"pi-fortress " + name + "-spoof: \" level info" +
		"\n    counter drop\n  }"
}

// dnsNoTrack excludes UDP DNS between a segment and the Pi from the
// conntrack table. When tracked, each query took an entry for the 30 s
// UDP timeout before a meter saw it. One source under the 200/s meter
// held about 6000 entries. A root agent that aliases across its /24 (the
// spoof check only stops sources outside the subnet), or a busy house,
// could fill the table that all segments and the DoT and SSH of the Pi
// share.
//
// A short `ct timeout` object for these flows was the first choice. But
// the Raspberry Pi kernel is built without CONFIG_NF_CONNTRACK_TIMEOUT:
// nft 1.1.3 on 6.18.50+rpt-rpi-2712 answers ENOENT for the object
// (checked with a scratch table, 2026-09-27). Thus the queries go
// untracked in raw prerouting, below the spoof check and above the port
// 53 accept of the house that ends that chain. The answers of pf dns go
// untracked in raw output. If not, each answer would open its own flow.
//
// DNSReplyOut now states what conntrack gave the answers. With DoT on,
// output ends in the pf-dns uid drop, and the answers passed only as ct
// state established. The accept is as narrow as the notrack that feeds
// it: the pf-dns uid, UDP from port 53, untracked, out an internal
// interface. The WAN is never an internal interface. Thus nothing here
// widens the pin that keeps pf dns on its DoT upstream. The tunnel is not
// an internal interface either (the forwarder of the house there is a
// client from an ephemeral port and stays tracked).
//
// Nothing else reads these entries. The flood meters and the input port
// 53 accepts are before or outside the conntrack match. pf observe skips
// flows to the address of the segment and reads the query logs for DNS.
// TCP 53 stays tracked and counted. This does not change daddrs other than
// the address of the Pi. Those of the agent are dropped in raw, and those
// of the house and of a segment are rejected in forward. Thus their
// entries are never confirmed.
func (f *fragments) dnsNoTrack() {
	// One rule for each interface, not one set. Thus a new house or segment
	// does not change the lines of the agent (apply_test.sh keeps each
	// no-house golden line in the house render).
	ifs := []string{f.IntIF}
	if f.HouseIF != "" {
		ifs = append(ifs, f.HouseIF)
	}
	for _, s := range f.Segments {
		if s.IF != "" {
			ifs = append(ifs, s.IF)
		}
	}
	for _, i := range ifs {
		f.DNSNoTrack += "\n    iifname \"" + i + "\" udp dport 53 fib daddr type local notrack"
		f.DNSNoTrackOut += "\n    oifname \"" + i + "\" meta skuid \"pf-dns\" udp sport 53 notrack"
		f.DNSReplyOut += "\n    oifname \"" + i + "\" meta skuid \"pf-dns\" udp sport 53 ct state untracked accept"
	}
}

// ntpRedirect sends NTP (UDP 123) of the house or of a plain segment to
// chrony on the gateway address ip of that network (apply.sh). NTP to a
// server of the device can carry data (the transmit timestamp, the
// extension fields), so it never leaves. The device keeps its own server
// name: conntrack changes the source of the reply back to the address
// that the device asked. A device that asks the gateway itself is not
// changed. It is the first packet of a flow that nat sees. Thus each flow
// that starts after this ruleset goes to the gateway.
//
// The blacklist in raw prerouting runs before nat, so a query to a
// blacklisted address is dropped there and never redirected. The resolver
// gate of a segment runs before nat too, so it has an accept for UDP 123:
// nat then sends the flow to the gateway. The redirect is in all modes of
// EGRESS, so no new NTP flow reaches forward. Forward drops UDP 123 from the
// house and the segments all the same (ntpForwardDrop), so a later change
// to nat cannot let NTP out. Input
// accepts UDP 123 only to ip on the interface of that network. The agent
// network gets no redirect and no accept: its clock comes from the HTTP
// Date header of the gateway (vm/agent/setup.sh).
//
// NTP=pass on a segment is for a device that needs NTS end to end, for
// example a second gateway. It cannot sync through a plain NTP server. NTP
// of that segment to an address in ntp_pass.ips (@ntp_pass_v4, the
// well-known NTP and NTS servers) is not redirected and not dropped. NTP to
// each other address still goes to the gateway. The blacklist in raw still
// runs first. The gate lets UDP 123 and 4123 and TCP 4460 to the set
// through, as it lets ssh_allow.ips through: the set holds addresses, not
// names. Strict egress returns the same three ports to the set only
// (segEgress). Input still accepts UDP 123 to ip, and chrony still serves
// the segment.
//
// ntpForwardDrop is the guard behind ntpRedirect: NTP from the house or a
// segment never goes out, whatever EGRESS says. Under NTP=pass, NTP to
// @ntp_pass_v4 is the one exception.
func ntpForwardDrop(in func(string) string, pass bool) string {
	return in("udp dport 123" + ntpPassExcept(pass) + " counter drop")
}

func ntpRedirect(in func(string) string, ip string, pass bool) string {
	return in("udp dport 123 ip daddr != " + ip + ntpPassExcept(pass) + " counter dnat ip to " + ip)
}

// ntpPassExcept is the match that keeps the NTP=pass servers out of the
// redirect and of the forward drop. It is empty for each other network.
func ntpPassExcept(pass bool) string {
	if pass {
		return " ip daddr != @ntp_pass_v4"
	}
	return ""
}

// ntpPassMatches are the time flows that NTP=pass lets go to
// @ntp_pass_v4: NTP (UDP 123), NTP on a port that an NTS server can give
// in its key exchange (UDP 4123), and NTS key exchange (TCP 4460).
var ntpPassMatches = []string{"udp dport { 123, 4123 } ip daddr @ntp_pass_v4", "tcp dport 4460 ip daddr @ntp_pass_v4"}

// ntpPassSet declares ntp_pass_v4 when a segment has NTP=pass. Without
// one, it is empty, so the ruleset of a box without NTP=pass does not
// change. An empty list gives an empty set: the rules still load, and no
// time flow goes out.
func (f *fragments) ntpPassSet() {
	for _, s := range f.Segments {
		if s.NTP == "pass" {
			elems := ""
			if f.NTPPass != "" {
				elems = "\n    " + f.NTPPass
			}
			f.NTPPassSet = "\n\n  set ntp_pass_v4 {\n    type ipv4_addr\n    flags interval" + elems + "\n  }"
			return
		}
	}
}

func (f *fragments) house() {
	h := f.HouseIF
	if h == "" {
		return
	}
	in := func(s string) string { return "\n    iifname \"" + h + "\" " + s }
	// The house resolves through its own dnsmasq, so it feeds its own set.
	// If it shared the set of the agent, a name resolved on one segment would
	// open an address on the other.
	// It has its own direct-IP list too: an address opened for a house TV must
	// not open for the agents, and an agent entry must not open for the house.
	f.HouseSet = "\n\n" + resolvedSet("resolved_house_v4") +
		"\n\n  set house_direct_ip_v4 {\n    type ipv4_addr\n    flags interval\n    " + f.HouseDirectIP + "\n  }"
	// HOUSE_PRIVATE_DNS=on: the secure-DNS providers of the operator are an
	// exception in three chains. The drops that stop DoT and DoH are in two
	// prerouting chains, and an accept there ends only that chain. privDNS is
	// the match that all three share: TCP only. Thus QUIC, DoQ and DoH3 to the
	// same addresses stay dropped.
	privDNS := ""
	if f.Config.HousePrivateDNS == "on" {
		privDNS = "ip daddr @house_private_dns_v4 tcp dport { 443, 853 } "
		f.HouseSet += "\n\n  set house_private_dns_v4 {\n    type ipv4_addr\n    flags interval\n    " + f.Elements.HousePrivateDNS + "\n  }"
	}
	if f.HouseBlockDirectIP != "off" {
		f.houseGate(in, privDNS)
	}
	if f.HouseAllowWhatsApp != "off" {
		f.HouseSet += "\n\n  set house_whatsapp_v4 {\n    type ipv4_addr\n    flags interval\n    " + f.Elements.HouseWhatsApp + "\n  }"
	}
	if f.WGIF != "" {
		// No flags interval: dnsmasq adds single IPs, and interval sets
		// reject those dynamic adds on some libnftables versions.
		f.HouseSet += "\n\n  set vpn_bypass_v4 {\n    type ipv4_addr\n  }"
	}
	f.HouseRaw = in("meta nfproto ipv6 counter drop") +
		in("ip daddr @blacklist_v4 limit rate 10/second burst 20 packets log prefix \"pi-fortress house-blacklist: \" level info") +
		in("ip daddr @blacklist_v4 counter drop")
	if f.HouseBlockVPN != "off" {
		f.HouseRaw += houseVPN(in)
	}
	// This is below the blacklist drop on purpose: it is a hole in the DNS
	// pin, never in the blocklist. It is above the DoH-set and 853 drops,
	// which it exempts. It is also above the vpn_bypass mark, so a provider
	// address that is also in vpn_bypass_v4 is never marked for the uplink.
	// It names no oifname, because prerouting runs before routing and has no
	// oifname to match. forward decides where the flow can leave, and this
	// accept does not skip forward.
	if privDNS != "" {
		f.HouseRaw += in(privDNS + "accept")
	}
	doh := func(match string) string {
		return in(match+logRate+"\"pi-fortress house-doh: \" level info") + in(match+" counter drop")
	}
	// Port 53 skips the DoH-set drop, so the reject in forward answers it.
	// The resolvers that devices hardcode (8.8.8.8, 1.1.1.1) are in that set.
	// A silent drop makes a Chromecast or an IoT box wait for the full DNS
	// timeout before it uses the Pi.
	f.HouseRaw += in("meta l4proto { tcp, udp } th dport 53 accept") +
		doh("ip daddr @dns_bypass_v4") + in("udp dport 443 counter drop") +
		doh("tcp dport 853") + doh("udp dport 853")
	if f.WGIF != "" {
		// Mark in prerouting (raw), not forward: routing happens first.
		f.HouseRaw += in("ip daddr @vpn_bypass_v4 meta mark set " + f.WGBypassMark)
	}
	// One meter for each proto, keyed on ip saddr. Thus a single house
	// client that floods the resolver is rate-limited, and the others are not
	// affected. Input path only: forward already rejects port 53. The meters
	// are before the conntrack accept, as for the agent. One UDP socket is one
	// flow, and after the first reply each query on it would be established
	// and skip the meter.
	f.HouseDNSFlood = in("tcp dport 53 meter house_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop") +
		in("udp dport 53 meter house_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop")
	f.NTPRedirect += ntpRedirect(in, f.HouseIP, false)
	f.HouseInput = in("tcp dport 53 accept") +
		in("udp dport 53 accept") + in("udp sport 68 udp dport 67 accept") + in("ip daddr "+f.HouseIP+" udp dport 123 accept") +
		pingMeter("\n    iifname \""+h+"\" ", "house") + in("icmp type echo-request accept")
	if f.HouseAdminIP != "" {
		f.HouseInput += in("ip saddr " + f.HouseAdminIP + " tcp dport 22 ct state new limit rate 30/minute burst 60 packets accept")
	}
	f.HouseInput += in("limit rate 10/minute burst 20 packets log prefix \"pi-fortress house-drop: \" level warn") + in("counter drop")
	f.HouseIsolate = "\n    iifname \"" + f.IntIF + "\" oifname \"" + h + "\" counter drop"
	f.ctDrop(f.IntIF, h)
	f.ctDrop(h, f.IntIF)
	// HOUSE_SSH_TO widens the destination past the first agent, as
	// AGENT_COUNT can put more than one VM on the agent segment. When unset,
	// it uses AgentIP, so an existing house.env renders the same hole as
	// always. The ip saddr pin stays HouseAdminIP in the two cases -- this
	// key only widens where the admin machine can go, never who can connect.
	sshTo := f.AgentIP
	if f.HouseSSHTo != "" {
		sshTo = f.HouseSSHTo
	}
	if f.HouseAdminIP != "" && sshTo != "" {
		f.HouseIsolate += in("oifname \"" + f.IntIF + "\" ip saddr " + f.HouseAdminIP + " ip daddr " + sshTo + " tcp dport 22 ct state new accept")
		f.ctHole("\""+h+"\"", "\""+f.IntIF+"\"", f.HouseAdminIP, sshTo)
	}
	f.HouseIsolate += in("oifname \"" + f.IntIF + "\" counter drop")
	f.HouseForward = in("meta nfproto ipv6 counter drop") + ntpForwardDrop(in, false) + in("udp dport 53 reject with icmp type port-unreachable") + in("tcp dport 53 reject with tcp reset")
	if f.HouseBlockHTTP == "on" {
		// A reset, not a drop: the browser fails at once, and an HTTPS-first
		// browser continues and does not wait on port 80.
		f.HouseForward += in("tcp dport 80"+logRate+"\"pi-fortress house-http: \" level info") + in("tcp dport 80 counter reject with tcp reset")
	}
	// Local addresses (RFC 1918, CGNAT, the LAN of the uplink with the admin
	// page of the router on it) are never a house destination, whatever
	// HOUSE_EGRESS says. Without a tunnel, the uplink accept below would
	// route 192.168.x.x to the router. The ssh hole of the admin to the agent
	// is in HouseIsolate, above.
	f.HouseForward += in("ip daddr @reserved_v4"+logRate+"\"pi-fortress house-local: \" level info") + in("ip daddr @reserved_v4 counter drop")
	f.HouseNAT = "\n    ip saddr " + f.HouseNet + " oifname \"" + f.WanIF + "\" counter masquerade"
	// In forward, the private-DNS accept names the one interface that house
	// traffic can leave by: the tunnel when there is one, the uplink when
	// there is not. The general egress accept below would admit the same
	// flow. This accept is here so that the exception states its own scope
	// and can never be the way around the kill-switch. With the tunnel down,
	// routing blackholes the house, and nothing here matches the uplink. It
	// has no mark test, so a bypass mark cannot widen it.
	if privDNS != "" {
		egress := f.WanIF
		if f.WGIF != "" {
			egress = f.WGIF
		}
		f.HouseForward += in(privDNS + "oifname \"" + egress + "\" accept")
	}
	if f.HouseEgress != "open" {
		f.HouseForward += in("jump house_egress")
		f.HouseEgressChain = f.houseEgress()
	}
	if f.WGIF != "" {
		f.HouseForward += in("oifname \""+f.WanIF+"\" meta mark "+f.WGBypassMark+" counter accept") +
			in("oifname \""+f.WGIF+"\" tcp flags syn tcp option maxseg size set rt mtu") +
			in("oifname \""+f.WGIF+"\" accept") +
			in("oifname \""+f.WanIF+"\" limit rate 10/minute burst 20 packets log prefix \"pi-fortress house-killswitch: \" level warn")
		f.HouseNAT += "\n    ip saddr " + f.HouseNet + " oifname \"" + f.WGIF + "\" counter masquerade"
		// The kill-switch again, first in forward, for each state. A flow NATed
		// out the uplink before the tunnel came up is established. Without this,
		// it would use the conntrack accept. A packet that the SNI queue gives
		// back with an accept (the SYN and pure ACKs of a pending flow, and its
		// ClientHello after the name passes) leaves forward there and never
		// reaches the rules below. The SNI bits are masked out, because the
		// repeat verdict of pf dns sets them on a packet that can also carry the
		// bypass mark.
		kill := "oifname \"" + f.WanIF + "\" meta mark and " + sniKeep + " != " + f.WGBypassMark + " "
		f.HouseKill = in(kill+"limit rate 10/minute burst 20 packets log prefix \"pi-fortress house-killswitch: \" level warn") +
			in(kill+"counter drop")
	} else {
		f.HouseForward += in("oifname \"" + f.WanIF + "\" accept")
	}
	f.HouseForward += in("counter drop")
}

// houseGate is the direct-IP gate of the house (HOUSE_BLOCK_DIRECT_IP on).
// privDNS is the private-DNS match of the house, or "" when it is off.
func (f *fragments) houseGate(in func(string) string, privDNS string) {
	// The gate drops a new 80/443 flow to an address that the house resolver
	// did not give. With HOUSE_BLOCK_HTTP=on, forward rejects all 80 instead.
	// Thus the gate keeps only 443, and a direct-IP HTTP attempt logs as
	// house-http, the rule that actually stops it.
	ports := "{ 80, 443 }"
	if f.HouseBlockHTTP == "on" {
		ports = "443"
	}
	strict := f.HouseEgress == "" || f.HouseEgress == "strict"
	// The gate asks for an address that the house resolver gave. A private
	// resolver exists so that the Pi never sees the lookup. Thus, without
	// this, DoH on 443 stays blocked while DoT on 853 works, because the
	// gate does not cover 853 (under the old HOUSE_DEV_MODE). One port,
	// and an accept, not a hole in the gate match: the gate also covers 80.
	// This is an exception to the DNS pin, not a permission to reach them
	// in clear.
	//
	// A device on the endpoint was once exempt from the gate. The gate
	// passes addresses that the house resolver gave, and the lookups of
	// that device never reach it. Thus each site that it opened was a
	// "direct IP" (the phone on Private DNS, 2026-09-23: HN, Google, Meta
	// all dropped). That blanket exemption is removed: the gate checks
	// this device by name, as it checks all other devices.
	//
	// Strict egress checks each new flow on the TLS ports by name, for a
	// resolved address or not. An address that the house gave for one
	// name belongs to a CDN, and a blocked name on the same CDN could
	// otherwise use it. The pins of the private DNS endpoint are checked
	// too, 853 included. Thus the name of a different profile to the same
	// anycast address is refused (its parent zone is sinkholed). Local
	// addresses are never marked: the accept of the check would let a
	// flow past the isolation below, and forward drops them.
	if strict {
		all := " ct state new ip daddr != " + f.HouseIP + " ip daddr != @house_direct_ip_v4 ip daddr != @reserved_v4"
		if privDNS != "" {
			f.HouseGate = in("tcp dport 853 ip daddr @house_private_dns_v4" + all + " ct mark set ct mark and " + sniKeep + " or " + sniPending)
		}
		if p := f.houseSNIPorts(); p != "" {
			f.HouseGate += in("tcp dport { " + p + " }" + all + " ct mark set ct mark and " + sniKeep + " or " + sniPending)
		}
	} else if privDNS != "" {
		f.HouseGate = in("tcp dport 443 ip daddr @house_private_dns_v4 accept")
	}
	miss := " ct state new ip daddr != " + f.HouseIP + " ip daddr != @house_direct_ip_v4 ip daddr != @resolved_house_v4"
	// WhatsApp uses its own protocol on 80 as a fallback, to addresses that
	// it carries, not to addresses that it resolved. Only the ranges of Meta.
	miss80 := miss
	if f.HouseAllowWhatsApp != "off" {
		miss80 += " ip daddr != @house_whatsapp_v4"
	}
	// On a miss, 443 is not dropped but checked by name. A device on
	// Private DNS never asks the house resolver, so each site that it
	// opened was a miss (the phone, 2026-09-23: HN, Google, Meta). The
	// flow is marked pending, and its first packets go to pf dns
	// (houseSNI). pf dns reads the name that the device sends in the TLS
	// ClientHello and asks the house resolver about it.
	if !strict {
		f.HouseGate += in("tcp dport 443" + miss + " ip daddr != @reserved_v4 ct mark set ct mark and " + sniKeep + " or " + sniPending)
	}
	if ports != "443" {
		f.HouseGate += in("tcp dport 80"+miss80+logRate+"\"pi-fortress house-directip: \" level info") + in("tcp dport 80"+miss80+" counter drop")
	}
	f.HouseSNI = houseSNI(in)
	f.HouseSNIChain = houseSNIFlood
}

// Segment fragments come after the house fragments at the same splice
// points. trunk_drop is the exception: it goes first in input and forward,
// before the conntrack accept. An untagged frame on a trunk port is a
// misconfiguration or a spoof, and must not use an
// established flow.
func (f *fragments) segments() {
	used := append([]string{f.IntIF, f.WanIF, f.HouseIF}, f.segmentIFs()...)
	for _, p := range f.VLANParents {
		if !contains(used, p) {
			f.TrunkDrop += "\n    iifname \"" + p + "\" counter drop"
		}
	}
	sshFrom := ""
	for i, s := range f.Segments {
		in := func(x string) string { return "\n    iifname \"" + s.IF + "\" " + x }
		// A plain segment resolves through this box as the agents do. Thus it
		// needs the same three things as the agent segment: the port open, a
		// flood meter in front of it, and its own set for the gate to check. Its
		// own set, not a shared one -- a name resolved on one segment must not
		// open an address on a different segment. The house already follows
		// this rule.
		set := "resolved_" + nftName(s.Name) + "_v4"
		f.SegSet += "\n\n" + resolvedSet(set)
		f.SegDNSFlood += in("tcp dport 53 meter "+nftName(s.Name)+"_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop") +
			in("udp dport 53 meter "+nftName(s.Name)+"_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop")
		// The gate covers each new TCP and UDP flow and ping, not only
		// 80/443. The ruleset treats a desk as possibly compromised (an agent
		// that escaped its VM). Thus any port to an address that this box did
		// not resolve is a way out. Port 53 goes to the reject in forward, so a
		// client with a hardcoded resolver fails at once, not after a
		// timeout. The agents of SSH_TO are inside the box, never resolved.
		miss := "ct state new ip daddr != " + s.IP + " ip daddr != @" + set
		if s.SSHTo != "" {
			miss += " ip daddr != " + s.SSHTo
		}
		// All other protocols (GRE, ESP, SCTP, ICMP other than echo) also go
		// through the gate. Under EGRESS=open or audit, nothing further down stops
		// them. Under strict, the port policy would drop them without a log.
		gates := []string{"meta l4proto { tcp, udp } th dport != 53 " + miss, "icmp type echo-request " + miss,
			"meta l4proto != { tcp, udp, icmp } " + miss, "icmp type != echo-request " + miss}
		// BLOCK_DIRECT_IP=off removes the gate and keeps the set. Thus, when it is
		// on again, the resolver needs no restart. It is for software that
		// connects to addresses that it got out of band (the relays of Tailscale).
		if s.BlockDirectIP != "off" {
			// The gate of the house covers only TCP and never sees DHCP. This
			// gate covers UDP. A DISCOVER, or a REQUEST from a client that is not
			// yet bound or that rebinds, goes to 255.255.255.255, which no
			// resolver gave. The accept ends only this chain: the spoof check
			// already ran, and input decides. A unicast renewal goes to s.IP,
			// which the gate never drops.
			if s.DHCP == "on" {
				f.SegGate += in("ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept")
			}
			// NTP to any address goes to the gateway (ntpRedirect). This chain
			// runs before nat prerouting, and the resolver gave no NTP
			// address. The accept ends only this chain. Under NTP=pass, it
			// is still for NTP to each address outside @ntp_pass_v4: nat
			// sends it to the gateway.
			f.SegGate += in("udp dport 123 accept")
			// NTP=pass: ntp_pass.ips is a list of addresses, as ssh_allow.ips
			// is. Only the time ports to it get past the gate.
			if s.NTP == "pass" {
				for _, m := range ntpPassMatches {
					f.SegGate += in(m + " accept")
				}
			}
			// ssh_allow.ips is a list of addresses, not names. Thus the resolver
			// did not give them, and the gate would drop them. The accept is for
			// TCP 22 only and ends only this chain. forward then accepts it
			// (below). Other ports to these addresses still meet the gate.
			if f.SSHAllow != "" {
				f.SegGate += in("tcp dport 22 ip daddr @ssh_allow_v4 accept")
			}
			for _, gate := range gates {
				f.SegGate += in(gate+logRate+"\"pi-fortress "+s.Name+"-directip: \" level info") + in(gate+" counter drop")
			}
		}
		doh := func(match string) string {
			return in(match+logRate+"\"pi-fortress "+s.Name+"-doh: \" level info") + in(match+" counter drop")
		}
		// The DNS pin of the house: QUIC, DoT and the addresses of the DoH
		// resolvers are dropped. Port 53 goes through to the reject in forward, for
		// the reason that the house gives (a hardcoded 8.8.8.8 must fail fast).
		f.SegRaw += in("meta nfproto ipv6 counter drop") +
			in("ip daddr @blacklist_v4 limit rate 10/second burst 20 packets log prefix \"pi-fortress "+s.Name+"-blacklist: \" level info") +
			in("ip daddr @blacklist_v4 counter drop") +
			in("meta l4proto { tcp, udp } th dport 53 accept") +
			doh("ip daddr @dns_bypass_v4") + in("udp dport 443 counter drop") +
			doh("tcp dport 853") + doh("udp dport 853")
		// Per source, as for the uplink (uplink): a second device on an admin
		// segment must not be able to use the SSH budget of the seat.
		if s.Admin == "yes" {
			f.SegInput += in("tcp dport 22 ct state new meter seg_"+nftName(s.Name)+"_ssh { ip saddr limit rate over 30/minute burst 60 packets } counter drop") +
				in("tcp dport 22 ct state new accept")
		}
		if s.Inspect == "on" {
			// The fence of the agent network, for this segment. nat prerouting
			// sends 443 to the engine on the address of the segment, so the flow
			// is local and the forward budget of the segment never sees it. Thus
			// it gets its own budget here, with the limits of the segment, before
			// the accept. The resolver gate at priority -150 already ran on the
			// original address.
			f.SegPrerouting += in("tcp dport 443 redirect to :8080")
			fence := in("tcp dport 8080 ct state new")
			set, rules, chain := connLimit("seg_"+nftName(s.Name)+"_fence", s.Name, fence, s.conn)
			f.ConnSets += set
			f.ConnChains += chain
			f.SegInput += rules + in("tcp dport 8080 accept")
		}
		f.NTPRedirect += ntpRedirect(in, s.IP, s.NTP == "pass")
		f.SegInput += in("tcp dport 53 accept") + in("udp dport 53 accept") + in("ip daddr "+s.IP+" udp dport 123 accept")
		if s.DHCP == "on" {
			f.SegInput += in("udp sport 68 udp dport 67 accept")
		}
		f.SegInput += pingMeter("\n    iifname \""+s.IF+"\" ", "seg_"+nftName(s.Name)) + in("icmp type echo-request accept") +
			in("limit rate 10/minute burst 20 packets log prefix \"pi-fortress "+s.Name+"-drop: \" level warn") + in("counter drop")
		f.SegIsolate += "\n    iifname \"" + f.IntIF + "\" oifname \"" + s.IF + "\" counter drop"
		f.ctDrop(f.IntIF, s.IF)
		if s.SSHTo != "" {
			f.SegIsolate += in("oifname \"" + f.IntIF + "\" ip daddr " + s.SSHTo + " tcp dport 22 ct state new accept")
			f.ctHole("\""+s.IF+"\"", "\""+f.IntIF+"\"", "", s.SSHTo)
		}
		f.SegIsolate += in("oifname \"" + f.IntIF + "\" counter drop")
		f.ctDrop(s.IF, f.IntIF)
		if f.HouseIF != "" {
			f.SegIsolate += in("oifname \""+f.HouseIF+"\" counter drop") +
				"\n    iifname \"" + f.HouseIF + "\" oifname \"" + s.IF + "\" counter drop"
			f.ctDrop(s.IF, f.HouseIF)
			f.ctDrop(f.HouseIF, s.IF)
		}
		for j, t := range f.Segments {
			if j != i {
				f.SegIsolate += in("oifname \"" + t.IF + "\" counter drop")
				f.ctDrop(s.IF, t.IF)
			}
		}
		// The gate above opens only addresses that this box resolved. Thus a
		// segment that asks a different resolver gets a working lookup but no
		// web. Reject, not drop, as the house does: a client that ignores its
		// configured server learns this at once, and does not wait
		// for a timeout.
		f.SegForward += in("meta nfproto ipv6 counter drop") + ntpForwardDrop(in, s.NTP == "pass") +
			in("udp dport 53 reject with icmp type port-unreachable") + in("tcp dport 53 reject with tcp reset")
		// Local addresses (RFC 1918, CGNAT, the LAN of the uplink) are never a
		// segment destination, as in the house rule. A compromised desk must not
		// reach the admin page of the router, a NAS or the other machines at
		// home. SSH_FROM is the one way in, and it is inbound only.
		f.SegForward += in("ip daddr @reserved_v4"+logRate+"\"pi-fortress "+s.Name+"-local: \" level info") + in("ip daddr @reserved_v4 counter drop")
		// git over SSH: only to the ssh_allow.ips of the agent, the one list of
		// SSH destinations of the operator, before the port policy.
		if f.SSHAllow != "" {
			f.SegForward += in("tcp dport 22 ip daddr @ssh_allow_v4 ct state new counter accept")
		}
		if s.Egress != "open" {
			chain := "seg_" + nftName(s.Name) + "_egress"
			f.SegForward += in("jump " + chain)
			f.SegEgressChains += segEgress(chain, s)
		}
		f.SegForward += in("oifname \""+f.WanIF+"\" accept") + in("counter drop")
		f.SegNAT += "\n    ip saddr " + s.Net + " oifname \"" + f.WanIF + "\" counter masquerade"
		if s.SSHFrom != "" {
			if from := f.sshFromIFs(i); from != "" {
				sshFrom += "\n    iifname " + from + " oifname \"" + s.IF + "\" ip saddr " + s.SSHFrom + " tcp dport 22 ct state new counter accept"
				f.ctHole(from, "\""+s.IF+"\"", s.SSHFrom, "")
			}
		}
	}
	// Before all isolation drops, including those of the other segments and
	// the local drop of the house further down. Each of these would refuse it.
	f.SegIsolate = sshFrom + f.SegIsolate
}

// sshFromIFs is where the SSH_FROM of segment i can arrive: the house and
// the other plain segments, as an nft iifname operand, or "" when there is
// none. It is an allow-list, not "anything but the uplink and the agents".
// The tunnel (WG_IF) has no source check, so its far end could claim the
// admin address. Each interface listed here has a source check (antiSpoof).
// Thus only the network that SSH_FROM is really on can carry it.
func (f *fragments) sshFromIFs(i int) string {
	var ifs []string
	if f.HouseIF != "" {
		ifs = append(ifs, "\""+f.HouseIF+"\"")
	}
	for j, t := range f.Segments {
		if j != i && t.IF != "" {
			ifs = append(ifs, "\""+t.IF+"\"")
		}
	}
	switch len(ifs) {
	case 0:
		return ""
	case 1:
		return ifs[0]
	}
	return "{ " + strings.Join(ifs, ", ") + " }"
}

// isolateCT applies the segment isolation to flows that conntrack already
// tracks. The conntrack accept is above the isolation drops, and an apply
// does not flush conntrack. Thus, without this chain, a flow between two
// segments continues after an apply that removes its SSH hole, until the
// flow ends. isolate_ct has the same holes and drops as forward, and the
// current policy decides each established packet again:
//
//   - A hole matches the original direction as forward does, and the reply
//     direction with the addresses and the port reversed.
//   - A packet that crosses no segment pair falls through to the
//     conntrack accept, as before.
//   - related (an ICMP error for a flow) carries no data and is not sent here.
//
// The agent needs no rule here. Its forward is SSH to ssh_allow.ips only,
// and the raw chain checks each packet of that, new or not. A box with no
// house and no segments renders nothing.
func (f *fragments) isolateCT() {
	if len(f.ctDrops) == 0 {
		return
	}
	f.IsolateCT = "\n    ct state established jump isolate_ct"
	f.IsolateCTChain = "\n\n  chain isolate_ct {" + strings.Join(f.ctHoles, "") + strings.Join(f.ctDrops, "") + "\n  }"
}

// ctHole adds an SSH hole of forward to isolate_ct, for the two directions
// of the flow. iif and oif are nft operands (a quoted name or a set).
// saddr and daddr are the addresses of the hole; empty is any address.
func (f *fragments) ctHole(iif, oif, saddr, daddr string) {
	ip := func(k, v string) string {
		if v == "" {
			return ""
		}
		return " ip " + k + " " + v
	}
	f.ctHoles = append(f.ctHoles,
		"\n    iifname "+iif+" oifname "+oif+ip("saddr", saddr)+ip("daddr", daddr)+" tcp dport 22 ct direction original return",
		"\n    iifname "+oif+" oifname "+iif+ip("saddr", daddr)+ip("daddr", saddr)+" tcp sport 22 ct direction reply return")
}

// ctDrop adds an isolation drop of forward, from iif to oif, to isolate_ct.
func (f *fragments) ctDrop(iif, oif string) {
	f.ctDrops = append(f.ctDrops, "\n    iifname \""+iif+"\" oifname \""+oif+"\" counter drop")
}

// segEgress is the port policy of a plain segment: the strict set of the
// house (web, the mail and push ports, ping) plus ALLOW_PORTS. Time is not
// here: NTP goes to the gateway (ntpRedirect). NTP=pass is the exception:
// the time ports to @ntp_pass_v4 return (ntpPassMatches). They come before
// the log, so audit does not log them. No
// WhatsApp, Wi-Fi calling or call-media switches: a desk that needs one
// names the ports.
func segEgress(chain string, s Segment) string {
	r := func(x string) string { return "\n    " + x }
	body := r("tcp dport 80 return") +
		r("tcp dport { "+strings.Join(houseTLSPorts, ", ")+" } return") +
		r("tcp dport { "+houseSTARTTLSPorts+" } return")
	if s.NTP == "pass" {
		for _, m := range ntpPassMatches {
			body += r(m + " return")
		}
	}
	body += r("icmp type echo-request limit rate 10/second burst 20 packets return")
	if s.AllowTCP != "" {
		body += r("tcp dport { " + s.AllowTCP + " } return")
	}
	if s.AllowUDP != "" {
		body += r("udp dport { " + s.AllowUDP + " } return")
	}
	if s.Egress == "audit" {
		body += r("limit rate 10/second burst 20 packets log prefix \"pi-fortress "+s.Name+"-audit: \" level info") + r("counter")
	} else {
		body += r("limit rate 10/second burst 20 packets log prefix \"pi-fortress "+s.Name+"-port: \" level info") + r("counter drop")
	}
	return "\n\n  chain " + chain + " {" + body + "\n  }"
}

// resolvedSetSize is the maximum number of elements in each set that the
// resolver fills: resolved_v4, resolved_house_v4 and one set for each plain
// segment. Each answer adds its addresses, and each element stays for the
// timeout of the set. Thus without a size, the answers alone decide how much
// kernel memory the set uses. 65535 is the size of the connlimit sets
// (connlimit.go) and the meter default of nft. A segment that gets a new
// address each second for 2 hours has 7200 elements. When the set is full, the kernel refuses the add. pf dns then logs the
// error and answers SERVFAIL. The gate does not open. A full set gets space
// again as its elements expire.
const resolvedSetSize = 65535

// resolvedSet is the declaration of one set that the resolver fills. The
// elements get the 2h timeout of the set.
func resolvedSet(name string) string {
	return "  set " + name + " {\n    type ipv4_addr\n    size " + strconv.Itoa(resolvedSetSize) + "\n    flags timeout\n    timeout 2h\n  }"
}

// nftTemplate starts with `flush ruleset` on purpose: pf owns the whole
// ruleset of the Pi. apply loads this file, and nftables.service loads it
// again at each boot. Thus each table that pf did not write (docker,
// fail2ban, firewalld, an operator table) goes, and no such table can
// send traffic around the fence. pf doctor names those tables (rung nft).
var nftTemplate = template.Must(template.New("nft").Parse(`#!/usr/sbin/nft -f
flush ruleset

table inet fortress {
  set blacklist_v4 {
    type ipv4_addr
    flags interval
    {{.Blacklist}}
  }

  set dns_bypass_v4 {
    type ipv4_addr
    flags interval
    {{.DoH}}
  }

{{.AgentResolvedSet}}

  set direct_ip_v4 {
    type ipv4_addr
    flags interval
    {{.DirectIP}}
  }{{.SSHSet}}{{.NTPPassSet}}{{.HouseSet}}{{.SegSet}}{{.ConnSets}}

  set reserved_v4 {
    type ipv4_addr
    flags interval
    elements = {
      0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
      169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
      192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
      224.0.0.0/4, 240.0.0.0/4
    }
  }

  chain filter_prerouting {
    type filter hook prerouting priority raw; policy accept;{{.SpoofRaw}}{{.DNSNoTrack}}
    iifname "{{.IntIF}}" meta nfproto ipv6 counter drop
    iifname "{{.IntIF}}" ip daddr @blacklist_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress agent-blacklist: " level info
    iifname "{{.IntIF}}" ip daddr @blacklist_v4 counter drop
    iifname "{{.IntIF}}" ip daddr @dns_bypass_v4 limit rate 10/second burst 20 packets log prefix "pi-fortress agent-doh: " level info
    iifname "{{.IntIF}}" ip daddr @dns_bypass_v4 counter drop
    iifname "{{.IntIF}}" udp dport 443 counter drop
    iifname "{{.IntIF}}" tcp dport 80 ip daddr != {{.PiIP}} counter drop{{.SSHRaw}}
    iifname "{{.IntIF}}" tcp dport 22{{.SSHPoolCarve}} counter drop
    iifname "{{.IntIF}}" udp dport 53 ip daddr != {{.PiIP}} counter drop
    iifname "{{.IntIF}}" tcp dport 53 ip daddr != {{.PiIP}} counter drop
    iifname "{{.IntIF}}" tcp dport 853 limit rate 10/second burst 20 packets log prefix "pi-fortress agent-doh: " level info
    iifname "{{.IntIF}}" tcp dport 853 counter drop
    iifname "{{.IntIF}}" udp dport 853 limit rate 10/second burst 20 packets log prefix "pi-fortress agent-doh: " level info
    iifname "{{.IntIF}}" udp dport 853 counter drop{{.HouseRaw}}{{.SegRaw}}
  }

  chain raw_output {
    type filter hook output priority raw; policy accept;{{.DNSNoTrackOut}}
  }

  chain resolver_gate {
    type filter hook prerouting priority -150; policy accept;
    iifname "{{.IntIF}}" tcp dport 443 ct state new ip daddr != {{.PiIP}} ip daddr != 192.0.2.0/24{{.DirectCarve}}{{.AgentGateAllow}} limit rate 10/second burst 20 packets log prefix "pi-fortress agent-directip: " level info
    iifname "{{.IntIF}}" tcp dport 443 ct state new ip daddr != {{.PiIP}} ip daddr != 192.0.2.0/24{{.DirectCarve}}{{.AgentGateAllow}} counter drop{{.HouseGate}}{{.SegGate}}
  }

  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "{{.IntIF}}" tcp dport 443 redirect to :8080{{.SegPrerouting}}{{.NTPRedirect}}
  }

  chain input {
    type filter hook input priority filter; policy drop;{{.TrunkDrop}}
    iifname "{{.WanIF}}" meta nfproto ipv6 counter drop
    iifname "{{.IntIF}}" tcp dport 53 meter agent_dnsflood_tcp { ip saddr limit rate over 200/second burst 400 packets } counter drop
    iifname "{{.IntIF}}" udp dport 53 meter agent_dnsflood_udp { ip saddr limit rate over 200/second burst 400 packets } counter drop{{.HouseDNSFlood}}{{.SegDNSFlood}}
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept{{.AgentConnLimit}}
    iifname "{{.IntIF}}" tcp dport 80 accept
    iifname "{{.IntIF}}" tcp dport 8080 accept
    iifname "{{.IntIF}}" tcp dport 53 accept
    iifname "{{.IntIF}}" udp dport 53 accept{{.AgentPing}}
    iifname "{{.IntIF}}" icmp type echo-request accept
    iifname "{{.IntIF}}" limit rate 10/minute burst 20 packets log prefix "pi-fortress agent-drop: " level warn
    iifname "{{.IntIF}}" counter drop{{.HouseInput}}{{.SegInput}}{{.WanSSH}}
    iifname "{{.WanIF}}" udp sport 67 udp dport 68 accept{{.WanPing}}
    iifname "{{.WanIF}}" counter drop
  }

  chain output {
    type filter hook output priority filter; policy accept;
    oifname "{{.WanIF}}" meta nfproto ipv6 counter drop{{.WanOutput}}{{.DoTOutputCT}}{{.BrokerBlockCT}}
    ct state established,related accept{{.DNSReplyOut}}
    oifname "lo" accept
    meta skuid "pf-engine" counter drop
    meta skuid "pf-broker" ip daddr @reserved_v4 counter drop
    meta skuid "pf-broker" tcp dport 443 accept
    meta skuid "pf-broker" counter drop{{.DoTOutput}}
  }

  chain forward {
    type filter hook forward priority filter; policy drop;{{.TrunkDrop}}{{.ConnLimitFwd}}{{.HouseKill}}{{.HouseSNI}}{{.IsolateCT}}
    ct state established,related accept
    ct state invalid drop{{.SSHPoolReject}}{{.HouseIsolate}}{{.SegIsolate}}
    iifname "{{.IntIF}}" meta nfproto ipv6 counter drop
    iifname "{{.IntIF}}" udp dport 443 counter drop
    iifname "{{.IntIF}}" tcp dport 80 counter drop{{.SSHFwd}}
    iifname "{{.IntIF}}" tcp dport 22 counter drop
    iifname "{{.IntIF}}" counter drop{{.HouseForward}}{{.SegForward}}
  }{{.IsolateCTChain}}{{.HouseEgressChain}}{{.SegEgressChains}}{{.HouseSNIChain}}{{.ConnChains}}{{.SpoofChain}}

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {{.AgentNet}} oifname "{{.WanIF}}" counter masquerade{{.HouseNAT}}{{.SegNAT}}
  }
}
`))

// nftName is a segment name as an nftables identifier. A segment name
// can have a dash (reSegName), but a set or meter name cannot.
func nftName(s string) string { return strings.ReplaceAll(s, "-", "_") }
