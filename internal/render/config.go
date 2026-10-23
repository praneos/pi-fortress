// Package render is the configuration and ruleset stage of pf apply. It
// reads house.env, segments.d and the DoT keys. It refuses each value that
// would not isolate. It detects the two interfaces. It renders the nftables
// ruleset and the variables that apply.sh then uses. It changes nothing on
// the box. apply.sh installs what it writes.
package render

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"pi-fortress/internal/base"
	"pi-fortress/internal/corepolicy"
)

const DoTAddr = "127.0.0.1"

// HouseDoTAddr is the second stub, for a house that resolves through a
// different provider from the agents. Both stubs run
// as pf-dns on lo. Thus one uid pin and one "oifname lo accept" cover
// them. Only the upstream behind them is different.
const HouseDoTAddr = "127.0.0.2"

// Net is what apply.sh sourced from net.env and hands over unchanged.
type Net struct {
	AgentNet    string
	PiIP        string
	AgentIP     string
	DNSUpstream string
	DoTAuthName string
	DoTIPs      string
	// UntrustedUplink "1" closes the uplink to SSH and ping
	// (docs/user_guide/public_wifi.md). "" and "0" keep it open.
	UntrustedUplink string
	// AgentDNS is how pf dns answers the agent segment. With "forward" (and
	// ""), it resolves upstream and feeds @resolved_v4, which the agent gate
	// examines. With "fakeip", it answers each A query with an address from
	// FakeIPNet and never forwards. The broker then resolves the real name
	// itself from the Pi. See fakeIPGate for the effect on the rules.
	AgentDNS string
	// FakeIPNet is the pool that fakeip answers from. "" is DefaultFakeIPNet.
	// The validation also occurs in forward mode, so a typo fails at once.
	FakeIPNet string
	// ConnLimits is the connection budget for each device and each segment.
	// It maps ConnLimitKeys to the value from net.env. An absent or "" key is
	// the default (connlimit.go).
	ConnLimits map[string]string
	// EnvSrc names the net.env in use; only error text mentions it.
	EnvSrc string
}

type Options struct {
	Net         Net
	HouseEnv    string
	SegmentsDir string
	// If IntIF and WanIF are empty, they come from the kernel when Live. Else
	// they are eth0 and wlan0, the lab defaults that apply_test.sh renders with.
	IntIF, WanIF string
	// Live is a real apply. The pf-dns account must exist when DoT is on. The
	// interfaces come from the addresses and the default route. When Live is
	// off, the render needs no root and no Pi.
	Live bool
	// Paranoid is docs/paranoid_mode.md armed on the agent segment. The gate
	// then no longer exempts @direct_ip_v4 from its drop. Thus an operator
	// address list cannot skip the forward allow set.
	Paranoid bool
	// Diagnostics that accompany a refusal (ip addr, ip route) go here.
	Stderr io.Writer
	// ifaces replaces the interface table of the kernel in the Live
	// existence checks: name to "has carrier". Only the tests set it. nil
	// reads the box. It is unexported, so the injection cannot become an
	// API that a caller uses to tell the renderer that an interface is there.
	ifaces map[string]bool
}

type Segment struct {
	Name, IF, Net, IP, Admin, SSHTo string
	// BlockDirectIP is the resolved-address gate. "off" keeps the resolved
	// set of the segment filled but not checked, as HOUSE_BLOCK_DIRECT_IP
	// does for the house. Empty means on.
	BlockDirectIP string
	// Egress is EGRESS, the port policy of the house for a plain segment:
	// strict (empty), audit or open. AllowTCP and AllowUDP are ALLOW_PORTS
	// as nft set bodies, the output of ParsePorts.
	Egress, AllowPorts, AllowTCP, AllowUDP string
	// SSHFrom is SSH_FROM: one address that can open SSH into the segment
	// from a different network (never from the uplink). The segment never
	// gets a path back to it.
	SSHFrom string
	// DNSTypes is DNS_TYPES, space separated: the record types that this
	// segment can ask for on each name, as an exception to address-only answers.
	DNSTypes string
	// ConnLimits are the CONN_PER_IP, NEW_PER_IP, CONN_TOTAL and NEW_TOTAL of
	// the segment, as written. For a missing key, the value comes from the SEG_
	// key in net.env (connlimit.go, segConnBudget). conn is the checked result.
	ConnLimits map[string]string
	conn       connBudget
	// Paranoid is PARANOID=on. The resolver of the segment then answers only
	// the names in AllowPath. The resolved-address gate of the segment must
	// stay on (docs/paranoid_mode.md). This gate drops a connection to an
	// address that the resolver did not give. The ruleset itself does not
	// change: the gate is the same as on an unarmed segment. Empty means off.
	// AllowPath is set only when Paranoid is on. Paranoid is independent of the
	// PARANOID=0|1 of the agent, which is Config.Paranoid.
	Paranoid  string
	AllowPath string
	// Inspect is INSPECT=on: the segment gets the credential fence of the
	// agent network. Its 443 goes to the engine, and the broker serves its
	// addresses (segInspect). Empty means off, the default.
	Inspect string
	// DHCP is DHCP=on. The Pi then leases DHCPStart to DHCPEnd on this
	// segment from its own dnsmasq instance, which is DHCP-only as the house
	// instance is. Empty means off, the default. An explicit off becomes
	// empty, so it renders the same as an absent line.
	DHCP, DHCPStart, DHCPEnd string
	// Hosts are the fixed leases of the segment from HostsPath, which is
	// dhcp.<name>.hosts next to segments.d (seg_hosts.go). HostsPath is
	// empty when that file does not exist.
	Hosts     []SegHost
	HostsPath string
}

// SegmentAllowPath is the location of the paranoid allowlist of a plain
// segment: allow.<name>.domains next to segments.d, which on the box is
// /etc/pi-fortress/allow.desk.domains. It is next to segments.d, not in
// it, because segments.d holds only one <name>.env for each segment. It is
// not in the policy tree, because the segment itself is box-local state
// that a ship never changes.
func SegmentAllowPath(segmentsDir, name string) string {
	return filepath.Join(filepath.Dir(segmentsDir), "allow."+name+".domains")
}

// SegmentDHCPUnit and SegmentLeases are the dnsmasq instance and the lease
// file of a DHCP=on segment. They use the names from seg_dhcp_sync in
// apply.sh (vm/pi/lib/dhcp.sh).
func SegmentDHCPUnit(name string) string { return "pi-fortress-dhcp@" + name + ".service" }

func SegmentLeases(name string) string { return "/var/lib/pi-fortress/dhcp-" + name + ".leases" }

// CheckSegmentAllow is the refusal check for the allowlist of a paranoid
// plain segment. render and doctor share it. The allowlist must be present,
// readable by pf dns (which runs as pf-dns, not root), and hold a minimum
// of one usable name. It returns that count. A desk that can reach nothing
// is a refusal, not a silent outage.
func CheckSegmentAllow(path string) (int, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("%s is missing or unreadable (%v)", path, err)
	}
	if !st.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm()&0004 == 0 {
		return 0, fmt.Errorf("%s is not readable by pf dns, which runs as pf-dns (chmod 0644 %s)", path, path)
	}
	f, err := corepolicy.LoadAllow(path)
	if err != nil {
		return 0, fmt.Errorf("%s is missing or unreadable (%v)", path, err)
	}
	n := len(f.Names())
	if n == 0 {
		return 0, fmt.Errorf("%s has no usable name (one name per line; a name covers its subdomains)", path)
	}
	return n, nil
}

// Config is everything config.sh used to leave in apply's shell.
type Config struct {
	Net
	IntIF, WanIF string

	HouseIF, HouseNet, HouseIP     string
	HouseDHCPStart, HouseDHCPEnd   string
	HouseAdminIP, HouseDNSUpstream string
	// HouseSSHTo widens the destination of the HouseAdminIP hole past the
	// first agent. It is an address or an a-b range inside AGENT_NET, with the
	// same format as the SSH_TO of a segment. Empty renders exactly the old
	// hole to the single AgentIP.
	HouseSSHTo       string
	HouseDNSExplicit bool
	// The DoT provider of the house, when the house does not share the
	// provider of the agents. Empty means that it shares it.
	HouseDoTAuthName, HouseDoTIPs string
	// HouseBlockDirectIP "off" removes the house direct-IP gate. "" is on.
	// HouseBlockHTTP "on" rejects all house TCP 80. "" is off.
	// HouseBlockVPN "off" lets house devices run their own VPN. "" is on: the
	// ruleset drops WireGuard (any port) and OpenVPN (1194), and apply adds
	// the VPN/proxy domain feed to the house sinkhole.
	HouseBlockDirectIP, HouseBlockHTTP, HouseBlockVPN string
	// HousePrivateDNS "on" lets house devices reach the providers in
	// house_private_dns.ips over DoT and DoH (TCP 853/443). It also excludes
	// house_private_dns.domains from the house DoH sinkhole. "" is off.
	HousePrivateDNS string
	// HouseEgress sets the ports that the house can use to go out. "" (strict)
	// allows web, the TLS ports, NTP, ping and the toggles below. It checks
	// each new TLS flow by name. "audit" logs what strict would drop, and lets
	// it pass. "open" is all ports, as before 2026-09-23.
	HouseEgress string
	// HouseAllowWiFiCalling and HouseAllowCallUDP "on" open IPsec and
	// the UDP media of the call apps under strict. "" is off.
	HouseAllowWiFiCalling, HouseAllowCallUDP string
	// HouseAllowWhatsApp "off" stops the non-TLS chat protocol of WhatsApp.
	// "" is on: TCP 5222 and 80, and a non-TLS 443 flow (pf dns), can go to
	// the ranges of Meta (house_whatsapp.ips) and to no other place.
	HouseAllowWhatsApp string
	// HouseAllowPorts is HOUSE_ALLOW_PORTS, checked: "tcp:N" or "udp:N-M"
	// tokens. HouseAllowTCP and HouseAllowUDP are its nft set bodies.
	HouseAllowPorts, HouseAllowTCP, HouseAllowUDP string
	WGIF, WGBypassMark                            string

	DNSForward, HouseDNSForward string
	Segments                    []Segment
	VLANParents                 []string
	Paranoid                    bool
	// connBudgets is ConnLimits read and checked, by segment class.
	connBudgets map[string]connBudget
}

var (
	reIface   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,14}$`)
	octets    = `((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	reIPv4    = regexp.MustCompile(`^` + octets + `$`)
	reCIDR4   = regexp.MustCompile(`^` + octets + `/([0-9]|[12][0-9]|3[0-2])$`)
	reRange4  = regexp.MustCompile(`^` + octets + `(-` + octets + `)?$`)
	reSegName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,15}$`)
	reDNSName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reFwmark  = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
)

// ValidIfaceName reports whether render takes name as an interface name
// (INT_IF, WAN_IF, HOUSE_IF, segments.d IF). pf install and the TUI edit
// checks (internal/admin) use it. Thus they refuse the same names before
// they write them.
func ValidIfaceName(name string) bool { return reIface.MatchString(name) }

// DefaultHouseIP is the address of the house segment when house.env
// names an interface but no address. doctor also asserts against it.
const DefaultHouseIP = "10.78.0.1"

// AGENT_DNS values. fakeip is the default since 2026-09-27. In forward
// mode, a name that the agent resolves leaves the Pi. Thus its labels were
// the last way out that the strip never scans. The fake-IP lab group and
// the full lab passed on the Pi in fakeip mode. The WebFetch of Claude Code
// and the usual HTTP clients connect to the pool.
const (
	AgentDNSForward = "forward"
	AgentDNSFakeIP  = "fakeip"
)

// DefaultFakeIPNet is half of the RFC 2544 benchmarking range. The
// internet never routes it. A home router or a cloud never gives it out.
// It is already inside @reserved_v4, the set that the ruleset refuses to
// the broker output. The placement rule of the pool (checkFakeIP) exists
// to keep that last property.
const DefaultFakeIPNet = "198.18.0.0/16"

// The size limits of the pool. A /24 is 254 names live at the same time.
// One busy agent session can reach that, so nothing smaller is allowed. A
// /16 is 65k. A larger pool starts to use ranges that an operator actually
// uses for segments.
const (
	minFakeIPBits = 16
	maxFakeIPBits = 24
)

// fakeIPHomes are the ranges that can hold a pool. Each one is inside
// @reserved_v4. Thus the existing "ip daddr @reserved_v4 drop" of the
// broker also refuses the pool. If a broker ever connects to the synthetic
// address that it got, and not to the name behind it, the Pi drops it. The
// connection does not reach the holder of that address on the internet.
// A pool in public space would change that one bug into a connection to a
// stranger. It would also shadow a real host for each agent that asked.
var fakeIPHomes = []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15"}

// Load runs all checks that config.sh ran, in the same sequence, with the
// same messages. Thus a refusal reads the same from the TUI or the shell.
func Load(o Options) (*Config, error) {
	c := &Config{Net: o.Net, Paranoid: o.Paranoid}
	if err := c.checkNet(o); err != nil {
		return nil, err
	}
	if err := c.loadConnLimits(); err != nil {
		return nil, err
	}
	// Only "there is no such file" means that the operator has no house. All
	// other answers -- a permission error, a broken symlink, a component of
	// the path that is not a directory -- tell that the file can be there but
	// is not readable. A render without it is not a render of their
	// configuration. apply then removes the house firewall paths and stops
	// the house resolver. That is a bigger change than the one
	// that failed.
	if _, err := os.Stat(o.HouseEnv); err == nil {
		if err := c.loadHouse(o.HouseEnv); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s cannot be read (%v), and an unreadable house.env is not an absent one. Nothing was changed.", o.HouseEnv, err)
	}
	setDefault(&c.HouseNet, "10.78.0.0/24")
	setDefault(&c.HouseIP, DefaultHouseIP)
	setDefault(&c.HouseDHCPStart, "10.78.0.100")
	setDefault(&c.HouseDHCPEnd, "10.78.0.199")
	c.HouseDNSExplicit = c.HouseDNSUpstream != ""
	setDefault(&c.HouseDNSUpstream, c.DNSUpstream)
	if c.WGIF != "" && c.WGBypassMark == "" {
		c.WGBypassMark = "0x1"
	}
	if err := c.checkDoT(o.Live); err != nil {
		return nil, err
	}
	if err := c.dnsForwards(); err != nil {
		return nil, err
	}
	if err := c.loadSegments(o.SegmentsDir); err != nil {
		return nil, err
	}
	// One enumeration of the interfaces of the kernel. All existence checks
	// below share it. It is nil without --live: a render on a dev machine has
	// none of the Pi interfaces, but it must still produce a ruleset.
	var have map[string]bool
	if o.Live {
		var err error
		if have, err = ifaceStates(o.ifaces); err != nil {
			return nil, err
		}
	}
	if err := c.interfaces(o, have); err != nil {
		return nil, err
	}
	if err := c.vlans(); err != nil {
		return nil, err
	}
	if err := c.checkHouse(); err != nil {
		return nil, err
	}
	if err := c.checkSegments(); err != nil {
		return nil, err
	}
	c.warnInspectAdmin(o.Stderr)
	if err := c.checkHouseCable(o.Stderr); err != nil {
		return nil, err
	}
	if err := c.checkFakeIP(); err != nil {
		return nil, err
	}
	// This runs before checkDeclaredIFs. A missing HOUSE_IF that is also the
	// only way in must refuse with the lockout message, not the generic one.
	if err := c.checkUplink(have, o.Stderr); err != nil {
		return nil, err
	}
	if err := c.checkDeclaredIFs(have, o.Stderr); err != nil {
		return nil, err
	}
	return c, nil
}

// dnsForwards sets DNSForward and HouseDNSForward, the resolvers that the
// agent and the house dnsmasq forward to.
func (c *Config) dnsForwards() error {
	c.DNSForward = c.DNSUpstream
	c.HouseDNSForward = c.HouseDNSUpstream
	if c.DoTIPs != "" {
		c.DNSForward = DoTAddr
		switch {
		case c.HouseDoTIPs != "":
			// The house has its own provider. Thus it forwards to its own
			// stub. checkDoT already refused this together with an
			// explicit HOUSE_DNS_UPSTREAM. With WireGuard, the stub connects to
			// it through the tunnel (apply.sh stub_config, dot_iface).
			c.HouseDNSForward = HouseDoTAddr
		case !c.HouseDNSExplicit:
			c.HouseDNSForward = DoTAddr
		case c.HouseIF != "" && c.WGIF == "":
			// The DoT output pins drop plaintext 53 that leaves the box. Thus this
			// forward would never get an answer.
			return fmt.Errorf("HOUSE_DNS_UPSTREAM=%s is a plaintext forward, and with DOT_IPS set the Pi drops plaintext DNS leaving the box; clear HOUSE_DNS_UPSTREAM so the house uses the DoT stub too", c.HouseDNSUpstream)
		}
	}
	if c.WGIF != "" && c.HouseIF != "" && c.HouseDoTIPs == "" {
		if c.HouseDNSExplicit {
			c.HouseDNSForward = c.HouseDNSUpstream + "@" + c.WGIF
		} else {
			c.HouseDNSForward = "10.64.0.1@" + c.WGIF
		}
	}
	return nil
}

// The 802.1Q id space without the two ends. 0 is a priority-tagged frame,
// not a VLAN. 4095 is reserved. The kernel refuses both, but only long
// after the ruleset that names them is loaded.
const (
	minVLANID = 1
	maxVLANID = 4094
)

// vlans reads the dotted interface names as the VLANs that apply.sh will
// later build from them. It refuses the names that apply.sh could not build.
//
// Before, the code read a dot in an interface name as VLAN syntax, and
// nothing examined the text after it. nft loads a rule for a quoted iifname
// that does not exist. Thus eth0.abc produced a firewall that referred to
// a segment that nm_profile would then fail to create. At that time the
// new ruleset is already installed. It possibly removed the path that the
// operator used to reach the box. The id must be read here, where a
// refusal still costs nothing.
func (c *Config) vlans() error {
	declared := []declaredIF{{"INT_IF", c.IntIF}, {"HOUSE_IF", c.HouseIF}}
	for _, s := range c.Segments {
		declared = append(declared, declaredIF{"segment " + s.Name + ": IF", s.IF})
	}
	for _, d := range declared {
		if d.val == "" {
			continue
		}
		i := strings.LastIndex(d.val, ".")
		if i < 0 {
			if err := c.checkWANCable(d); err != nil {
				return err
			}
			continue
		}
		parent, id := d.val[:i], d.val[i+1:]
		// The code refuses a leading zero and does not read it as decimal.
		// eth0.07 and eth0.7 would name the same VLAN here, but two different
		// interfaces for the kernel.
		n, err := strconv.Atoi(id)
		if err != nil || n < minVLANID || n > maxVLANID || id != strconv.Itoa(n) {
			return fmt.Errorf("%s=%s: '%s' is not a VLAN id (%d to %d), and a dotted interface name is read as parent.vlan. Nothing was changed.", d.key, d.val, id, minVLANID, maxVLANID)
		}
		if strings.Contains(parent, ".") {
			return fmt.Errorf("%s=%s: %s is itself a VLAN, and a VLAN inside a VLAN is not a segment pi-fortress builds. Nothing was changed.", d.key, d.val, parent)
		}
		// Tagged frames on the uplink come from any other device on that
		// wire. Thus a VLAN of WAN_IF would give them the segment.
		if parent == c.WanIF {
			return fmt.Errorf("%s=%s: %s is WAN_IF, the uplink, and a VLAN on it would carry tagged frames from the uplink's wire straight into the segment. Put the segment on a cable of its own. Nothing was changed.", d.key, d.val, parent)
		}
		if err := c.checkWANCable(d); err != nil {
			return err
		}
		if !contains(c.VLANParents, parent) {
			c.VLANParents = append(c.VLANParents, parent)
		}
	}
	return nil
}

// cableOf is the physical port of an interface name: the parent of a VLAN
// child, split the same way as vlans splits it, or the name itself.
func cableOf(name string) string {
	if i := strings.LastIndex(name, "."); i > 0 {
		return name[:i]
	}
	return name
}

// checkWANCable is the VLAN-of-WAN_IF refusal for an uplink that is
// itself a VLAN (an ISP VLAN such as eth0.35). The wire of the uplink is
// then its parent. A sibling VLAN or the untagged parent uses the same
// wire as all other devices on it. An uplink that is not a VLAN adds
// nothing here: the parent == WAN_IF check in vlans covers its cable.
// The comparison of names is exact, so eth00.30 is not on the cable of eth0.
func (c *Config) checkWANCable(d declaredIF) error {
	wan := c.WanIF
	cable := cableOf(wan)
	if wan == "" || cable == wan || d.val == wan || cableOf(d.val) != cable {
		return nil
	}
	how := "untagged"
	if d.val != cable {
		how = "tagged with its own VLAN id"
	}
	return fmt.Errorf("%s=%s shares a cable with WAN_IF=%s, the uplink: that VLAN rides %s, and whoever else is on the uplink's wire can send frames %s straight into the segment. Put it on a cable of its own. Nothing was changed.", d.key, d.val, wan, cable, how)
}

// onHouseCable tells how name shares the port of the house, or "" when it
// does not. It does not include HOUSE_IF itself: interfaces and
// checkSegments already refuse a second claim on that exact name.
func (c *Config) onHouseCable(name string) string {
	if c.HouseIF == "" || name == "" || name == c.HouseIF || cableOf(name) != cableOf(c.HouseIF) {
		return ""
	}
	if cableOf(name) == c.HouseIF {
		return "is a VLAN on HOUSE_IF=" + c.HouseIF
	}
	return "shares a cable with HOUSE_IF=" + c.HouseIF
}

// checkHouseCable gives each network on the port of the house only house
// trust. The far end of that cable is usually a consumer AP that maps an
// SSID to a VLAN. Its tags are only as good as its isolation. A client of
// the AP, or the AP itself, can tag a frame into any VLAN on the cable. It
// is then on that segment, as if it had joined it. Thus nothing there can
// SSH to the Pi or into the agents, and the agents must not be there at
// all. When the house is itself a VLAN, the cable is its parent. Thus a
// sibling VLAN and the untagged parent are on it too. The checks allow
// what remains, with a warning that tells what it depends on.
func (c *Config) checkHouseCable(w io.Writer) error {
	if how := c.onHouseCable(c.IntIF); how != "" {
		return fmt.Errorf("INT_IF=%s %s: whatever is behind the house AP could tag its frames straight onto the agent network. Put the agents on a cable of their own. Nothing was changed.", c.IntIF, how)
	}
	var on []string
	dhcp := false
	for _, s := range c.Segments {
		how := c.onHouseCable(s.IF)
		if how == "" {
			continue
		}
		dhcp = dhcp || s.DHCP == "on"
		grant, fix := "", ""
		switch {
		case s.Admin == "yes":
			grant, fix = "ADMIN=yes would let it SSH to the Pi", "Set ADMIN=no"
		case s.SSHTo != "":
			grant, fix = "SSH_TO="+s.SSHTo+" would let it SSH into the agent network", "Clear SSH_TO"
		case s.Inspect == "on":
			grant, fix = "INSPECT=on would let it use the credentials of the fence", "Set INSPECT=off"
		}
		if grant != "" {
			return fmt.Errorf("segment %s: IF=%s %s, and %s. Whatever is behind the house AP can tag its frames into any VLAN on that cable, so a segment there is trusted no more than the house. %s, or put the segment on a cable of its own. Nothing was changed.", s.Name, s.IF, how, grant, fix)
		}
		on = append(on, s.Name+" (IF="+s.IF+")")
	}
	if len(on) == 0 || w == nil {
		return nil
	}
	what, verb, pron := "segment", "rides", "it is"
	if len(on) > 1 {
		what, verb, pron = "segments", "ride", "they are"
	}
	// DHCP=on grants nothing past house trust, so it is allowed here. It needs
	// only one thing from the AP: the Pi must be the only DHCP server on that
	// SSID. An AP in access-point (bridge) mode already does this.
	apDHCP := ""
	if dhcp {
		apDHCP = " With DHCP=on the AP must not run its own DHCP on that SSID (in AP mode it does not)."
	}
	fmt.Fprintf(w, "pi-fortress: WARNING %s %s %s the house cable (HOUSE_IF=%s), so %s only as isolated as the AP or switch on that cable.\n  It must map each SSID to its own VLAN tag and must not pass tagged frames from its clients; ADMIN, SSH_TO, INSPECT and the agent network are refused there.%s\n", what, strings.Join(on, ", "), verb, c.HouseIF, pron, apDHCP)
	return nil
}

// checkNet validates the network that each chain in the ruleset is built
// on. The code reads house.env and segments.d field by field and checks
// them against each other. net.env was copied in as strings, and only the
// code that used a value checked it. This asymmetry is backwards -- these
// values are the agent fence itself. A render that cannot refuse them can
// only produce a ruleset that is wrong in a way that the nft syntax check
// cannot see. A PI_IP outside AGENT_NET loads without error and fences
// nothing, because no agent packet ever has that daddr.
//
// It runs before the code opens house.env. Thus the field named in the
// refusal is the one that the operator must fix. It runs with and without
// --live: a render on a laptop writes the same nftables.conf that a Pi loads.
func (c *Config) checkNet(o Options) error {
	if !reCIDR4.MatchString(c.AgentNet) {
		return fmt.Errorf("AGENT_NET='%s' is not an IPv4 CIDR (%s)", c.AgentNet, c.EnvSrc)
	}
	p, err := netip.ParsePrefix(c.AgentNet)
	if err != nil {
		return fmt.Errorf("AGENT_NET='%s' is not an IPv4 CIDR (%s)", c.AgentNet, c.EnvSrc)
	}
	// nft and the NAT rule use the prefix verbatim. For a reader, 10.77.0.1/24
	// is the same network. For each comparison below, it is a different
	// string. Thus the code requires the one spelling and does not silently
	// mask it. An operator who wrote the host address had a reason
	// for it.
	if masked := p.Masked(); masked != p {
		return fmt.Errorf("AGENT_NET=%s carries a host address; write the network itself, %s (%s)", c.AgentNet, masked, c.EnvSrc)
	}
	for _, x := range []struct{ key, val string }{{"PI_IP", c.PiIP}, {"AGENT_IP", c.AgentIP}} {
		if x.val == "" {
			// AGENT_IP is the reservation of the first agent. A Pi with no enrolled
			// agent yet has none. PI_IP is the address that the fence redirects to.
			// Without it, there is no fence.
			if x.key == "AGENT_IP" {
				continue
			}
			return fmt.Errorf("PI_IP is empty; it is the address the agent segment reaches the Pi on (%s)", c.EnvSrc)
		}
		if !reIPv4.MatchString(x.val) {
			return fmt.Errorf("%s='%s' is not an IPv4 address (%s)", x.key, x.val, c.EnvSrc)
		}
		if !netHas(c.AgentNet, x.val) {
			return fmt.Errorf("%s=%s is not inside AGENT_NET=%s, so no packet on the agent segment can carry it (%s)", x.key, x.val, c.AgentNet, c.EnvSrc)
		}
	}
	if c.AgentIP != "" && c.AgentIP == c.PiIP {
		return fmt.Errorf("AGENT_IP=%s is PI_IP; the agent and the Pi cannot share an address (%s)", c.AgentIP, c.EnvSrc)
	}
	// The forward goes to apply as DNS_FORWARD in the dnsmasq server= form:
	// an address or address#port. apply.sh changes the second form into
	// host:port for the Go resolver. Thus the code supports and checks the two
	// forms. With DoT on, the stub replaces this value. But the code still
	// refuses a typo in the file. It does not keep the typo until the
	// day that DoT is disabled again.
	if err := checkForward(c.DNSUpstream); err != nil {
		return fmt.Errorf("DNS_UPSTREAM='%s' %s; it is the resolver the Pi forwards to (%s)", c.DNSUpstream, err, c.EnvSrc)
	}
	// Absent means fakeip (above). A box that must keep real answers sets
	// AGENT_DNS=forward in net.env.local. forward renders exactly the same
	// ruleset as before (vm/pi/testdata/nft.no-house.forward.golden).
	setDefault(&c.AgentDNS, AgentDNSFakeIP)
	if c.AgentDNS != AgentDNSForward && c.AgentDNS != AgentDNSFakeIP {
		return fmt.Errorf("AGENT_DNS='%s' is not %s or %s (%s)", c.AgentDNS, AgentDNSForward, AgentDNSFakeIP, c.EnvSrc)
	}
	setDefault(&c.FakeIPNet, DefaultFakeIPNet)
	if err := CheckFakeIPNet(c.FakeIPNet); err != nil {
		return fmt.Errorf("FAKEIP_NET='%s' %v (%s)", c.FakeIPNet, err, c.EnvSrc)
	}
	// This is the same grammar as for the interfaces in house.env and
	// segments.d. These two go into the ruleset inside quoted iifname
	// matches. Without --live, nothing else examines them.
	for _, x := range []declaredIF{{"INT_IF", o.IntIF}, {"WAN_IF", o.WanIF}} {
		if x.val != "" && !reIface.MatchString(x.val) {
			return fmt.Errorf("%s='%s' is not an interface name (%s)", x.key, x.val, c.EnvSrc)
		}
	}
	return nil
}

// checkForward reads the dnsmasq server= address form, which apply.sh
// documents at its GO_DNS_UPSTREAM rewrite: a bare IPv4 address, or an
// IPv4 address followed by #port.
func checkForward(v string) error {
	addr, port, ported := strings.Cut(v, "#")
	if !reIPv4.MatchString(addr) {
		return errors.New("is not an IPv4 address")
	}
	if !ported {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
		return fmt.Errorf("names port '%s', which is not a port", port)
	}
	return nil
}

// checkUplink refuses to close the uplink when no other path lets an
// operator in. That apply would lock the operator out of a headless Pi.
//
// A declared admin path is not a real path. UNTRUSTED_UPLINK=1 removes the
// WAN SSH accept (ruleset.go, fragments.uplink). If the interface behind
// the admin path is not on the box, the operator then has no way in. The
// Pi then needs a monitor and a keyboard for recovery. house.env.example
// ships HOUSE_IF=eth1, and the setup guide says to copy it. But a Pi 5
// USB NIC usually enumerates as enx<mac> (70-pi-fortress-rtl8153.rules)
// and can be disconnected. Thus a correct name is not certain. have is
// nil without --live. Then nothing about this box is known, and the code
// accepts the declaration as true.
func (c *Config) checkUplink(have map[string]bool, w io.Writer) error {
	switch c.UntrustedUplink {
	case "", "0":
		return nil
	case "1":
	default:
		return fmt.Errorf("UNTRUSTED_UPLINK='%s' is not 0 or 1 (%s)", c.UntrustedUplink, c.EnvSrc)
	}
	var paths []declaredIF
	if c.HouseIF != "" && c.HouseAdminIP != "" {
		paths = append(paths, declaredIF{"HOUSE_IF", c.HouseIF})
	}
	for _, s := range c.Segments {
		if s.Admin == "yes" {
			paths = append(paths, declaredIF{"segment " + s.Name + " IF", s.IF})
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("UNTRUSTED_UPLINK=1 closes SSH on WAN_IF=%s, and no house admin (HOUSE_IF and HOUSE_ADMIN_IP) or segment with ADMIN=yes is set, so the only way in would be a keyboard and screen on the Pi. Nothing was changed.", c.WanIF)
	}
	if have == nil {
		return nil
	}
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		if ifPresent(p.val, have) {
			// One working way in is sufficient. A cable that is disconnected today
			// gives a warning, not a refusal. It can go back in seconds, but
			// a wrong name never fixes itself.
			warnNoCarrier(w, p.key, p.val, have)
			return nil
		}
		names = append(names, p.key+"="+p.val)
	}
	return fmt.Errorf(`UNTRUSTED_UPLINK=1 is about to close SSH on WAN_IF=%s, and the only admin way in, %s, is not an interface on this box (check ip -br link).
  Applying this would leave nothing to reach the Pi on: a headless box would need a monitor and a keyboard to get back.
  Plug the adapter in, or set %s in %s to the name the kernel actually gave it (a Pi 5 USB NIC usually comes up as enx<mac>, not eth1), or set UNTRUSTED_UPLINK=0 in %s to leave SSH open on the uplink.
  Nothing was changed.`, c.WanIF, strings.Join(names, " and "), paths[0].key, houseSrc(paths[0].key), c.EnvSrc)
}

// declaredIF is an interface that a config asked for, with the key that
// asked for it. Thus a refusal points to the line to fix.
type declaredIF struct{ key, val string }

func houseSrc(key string) string {
	if strings.HasPrefix(key, "segment ") {
		return "segments.d"
	}
	return "house.env"
}

// ifaceStates is the interface table of the kernel as name to "has
// carrier". It is the one enumeration that each live existence check
// reads. A non-nil names replaces it for the tests.
func ifaceStates(names map[string]bool) (map[string]bool, error) {
	if names != nil {
		return names, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("the interfaces on this box cannot be listed (%v), so INT_IF, WAN_IF and the rest cannot be checked. Nothing was changed.", err)
	}
	have := make(map[string]bool, len(ifs))
	for _, i := range ifs {
		have[i.Name] = i.Flags&net.FlagRunning != 0
	}
	return have, nil
}

// ifPresent allows one thing that the name alone does not tell. A VLAN
// child (parent.id) does not exist until apply.sh builds it from
// VLAN_PARENTS, later in the same run than this render. Thus a render can
// only ask that the parent is present. All other interfaces are checked by name.
func ifPresent(name string, have map[string]bool) bool {
	if _, ok := have[name]; ok {
		return true
	}
	if i := strings.LastIndex(name, "."); i > 0 {
		_, ok := have[name[:i]]
		return ok
	}
	return false
}

func warnNoCarrier(w io.Writer, key, name string, have map[string]bool) {
	if w == nil {
		return
	}
	if carrier, ok := have[name]; ok && !carrier {
		fmt.Fprintf(w, "pi-fortress: %s=%s is there but has no carrier; nothing is plugged into it yet. The rules are rendered for it either way.\n", key, name)
	}
}

// checkDeclaredIFs looks for the house and plain-segment interfaces on a
// live apply. It reports loudly when one is absent, but it renders. Before,
// it refused, as INT_IF and WAN_IF still do. On 2026-09-22, this changed
// one USB adapter stuck in driver-CD mode into twelve hours of refused
// feed refreshes, for the agent segment too: each apply stopped at the
// house. A render for an absent interface is safe. The rules match it by
// name under input and forward chains whose policy is drop -- nothing
// arrives on it, and it is fenced when it appears. apply.sh then
// reports the missing address and exits "not settled" (3). The refresh
// timer counts this as done. Without --live, nothing is checked. WG_IF is
// never checked -- wg-quick creates that interface after this render, in
// the same apply.
func (c *Config) checkDeclaredIFs(have map[string]bool, w io.Writer) error {
	if have == nil {
		return nil
	}
	declared := []declaredIF{{"HOUSE_IF", c.HouseIF}}
	for _, s := range c.Segments {
		declared = append(declared, declaredIF{"segment " + s.Name + ": IF", s.IF})
	}
	for _, d := range declared {
		if d.val == "" {
			continue
		}
		if !ifPresent(d.val, have) {
			if w != nil {
				fmt.Fprintf(w, "pi-fortress: WARNING %s=%s: no such interface on this box (check ip -br link; pf doctor names a stuck USB adapter). Its rules are rendered and stay inert until it appears; everything else is applied.\n", d.key, d.val)
			}
			continue
		}
		warnNoCarrier(w, d.key, d.val, have)
	}
	return nil
}

func setDefault(s *string, v string) {
	if *s == "" {
		*s = v
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c *Config) segmentIFs() []string {
	out := make([]string, 0, len(c.Segments))
	for _, s := range c.Segments {
		out = append(out, s.IF)
	}
	return out
}

// EnvLines walks a KEY=VALUE file as the shell does. A line is blank, is
// a # comment, or must have an = sign. apply.sh reads the same files with
// `source`. Thus the value that the caller gets here must be the value
// that the shell got. base.EnvValue is that rule. The two readers share
// it, so they cannot become different again. Without it, a caller that
// compared a rendered value with the file compared 1 with "1".
func EnvLines(path string, fn func(n int, key, val string) error) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		n := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: not KEY=VALUE", path, n)
		}
		if err := fn(n, strings.TrimSpace(key), base.EnvValue(val)); err != nil {
			return err
		}
	}
	return nil
}

// envField is a KEY=VALUE line of house.env or segments.d that needs only a
// format check before the code keeps it. what completes the refusal
// "KEY is not <what>".
type envField struct {
	dst  *string
	ok   func(string) bool
	what string
}

type envFields map[string]envField

// set keeps val when key is in the table. It returns false for a key that
// is not in the table, which the caller then reads itself.
func (fs envFields) set(path string, n int, key, val string) (bool, error) {
	f, found := fs[key]
	if !found {
		return false, nil
	}
	if !f.ok(val) {
		return true, badValue(path, n, key, f.what)
	}
	*f.dst = val
	return true, nil
}

func badValue(path string, n int, key, what string) error {
	return fmt.Errorf("%s:%d: %s is not %s", path, n, key, what)
}

func oneOf(opts ...string) func(string) bool {
	return func(v string) bool { return slices.Contains(opts, v) }
}

func orEmpty(ok func(string) bool) func(string) bool {
	return func(v string) bool { return v == "" || ok(v) }
}

var (
	isOnOff  = oneOf("on", "off")
	isEgress = oneOf("strict", "audit", "open")
)

func (c *Config) loadHouse(path string) error {
	const (
		ifName = "an interface name"
		ipv4   = "an IPv4 address"
		onOff  = "on or off"
	)
	fields := envFields{
		"HOUSE_IF":                 {&c.HouseIF, reIface.MatchString, ifName},
		"HOUSE_NET":                {&c.HouseNet, reCIDR4.MatchString, "an IPv4 CIDR"},
		"HOUSE_IP":                 {&c.HouseIP, reIPv4.MatchString, ipv4},
		"HOUSE_DHCP_START":         {&c.HouseDHCPStart, reIPv4.MatchString, ipv4},
		"HOUSE_DHCP_END":           {&c.HouseDHCPEnd, reIPv4.MatchString, ipv4},
		"HOUSE_ADMIN_IP":           {&c.HouseAdminIP, orEmpty(reIPv4.MatchString), ipv4},
		"HOUSE_DNS_UPSTREAM":       {&c.HouseDNSUpstream, orEmpty(reIPv4.MatchString), ipv4},
		"HOUSE_SSH_TO":             {&c.HouseSSHTo, orEmpty(reRange4.MatchString), "an IPv4 address or a-b range"},
		"HOUSE_BLOCK_DIRECT_IP":    {&c.HouseBlockDirectIP, orEmpty(isOnOff), onOff},
		"HOUSE_BLOCK_HTTP":         {&c.HouseBlockHTTP, orEmpty(isOnOff), onOff},
		"HOUSE_BLOCK_VPN":          {&c.HouseBlockVPN, orEmpty(isOnOff), onOff},
		"HOUSE_PRIVATE_DNS":        {&c.HousePrivateDNS, orEmpty(isOnOff), onOff},
		"HOUSE_EGRESS":             {&c.HouseEgress, orEmpty(isEgress), "strict, audit or open"},
		"HOUSE_ALLOW_WIFI_CALLING": {&c.HouseAllowWiFiCalling, orEmpty(isOnOff), onOff},
		"HOUSE_ALLOW_CALL_UDP":     {&c.HouseAllowCallUDP, orEmpty(isOnOff), onOff},
		"HOUSE_ALLOW_WHATSAPP":     {&c.HouseAllowWhatsApp, orEmpty(isOnOff), onOff},
		"WG_IF":                    {&c.WGIF, orEmpty(reIface.MatchString), ifName},
	}
	return EnvLines(path, func(n int, key, val string) error {
		if done, err := fields.set(path, n, key, val); done {
			return err
		}
		var dst *string
		switch key {
		case "HOUSE_DOT_AUTH_NAME", "HOUSE_DOT_IPS":
			// This is the only house.env value that holds a list. Thus it is the
			// only value with a space in it. pf render parses this file and does not
			// source it. But it is a shell-format file, and other tools do
			// source it -- vm/itest does. Without quotes, the shell reads the second
			// address as a command to run with the first in its
			// environment. Thus the code allows the quotes and removes them here,
			// and the example writes them. A quote at a position other than the ends
			// is not quoting. It is an injection attempt, and the IPv4
			// and DNS-name checks in checkDoT refuse it.
			val = trimQuotes(val)
			// checkDoT checks the format together with the net.env pair. It
			// sees the two providers and can tell which one is wrong.
			dst = &c.HouseDoTAuthName
			if key == "HOUSE_DOT_IPS" {
				dst = &c.HouseDoTIPs
			}
		case "HOUSE_ALLOW_PORTS":
			val = trimQuotes(val)
			tcp, udp, err := ParsePorts(val)
			if err != nil {
				return badValue(path, n, key, "tcp:N or udp:N-M tokens ("+err.Error()+")")
			}
			c.HouseAllowTCP, c.HouseAllowUDP = tcp, udp
			dst = &c.HouseAllowPorts
		case "HOUSE_DEV_MODE":
			// The old name of HOUSE_PRIVATE_DNS. It was removed 2026-09-18 and
			// came back under the new name 2026-09-23. The code refuses it
			// and does not read it as an alias. The default branch would say
			// "unknown key". A silent alias would keep a stale "on", although
			// the operator did not examine it again.
			return fmt.Errorf("%s:%d: HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS; rename the line (see docs/user_guide/home_network.md)", path, n)
		case "WG_BYPASS_MARK":
			if err := CheckWGBypassMark(val); err != nil {
				return fmt.Errorf("%s:%d: WG_BYPASS_MARK is %v", path, n, err)
			}
			dst = &c.WGBypassMark
		default:
			return fmt.Errorf("%s:%d: unknown key '%s'", path, n, key)
		}
		*dst = val
		return nil
	})
}

// trimQuotes removes one layer of matching quotes around a value. A shell
// that sources the file also removes these quotes. Thus pf render and the
// shell read the same string from a quoted value. trimQuotes does not
// change other values, so the validators can refuse them.
func trimQuotes(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// allDigitLabel is true when the last label has only digits. No real DNS
// name has such a label, and each dotted-quad address has one.
func allDigitLabel(name string) bool {
	last := name[strings.LastIndex(name, ".")+1:]
	if last == "" {
		return false
	}
	return strings.TrimLeft(last, "0123456789") == ""
}

// checkDoTPair validates one provider: a name for authentication and the
// addresses to connect to. The two segments use the same rules. Thus the
// key names are arguments, and only the error text is different.
func checkDoTPair(nameKey, name, ipsKey, ips string) error {
	if name == "" && ips == "" {
		return nil
	}
	if name == "" || ips == "" {
		return fmt.Errorf("%s and %s are set together or not at all; a name with nothing to dial is dead, and addresses with no name is an unauthenticated tunnel", nameKey, ipsKey)
	}
	if !reDNSName.MatchString(name) || allDigitLabel(name) {
		// An address passes reDNSName -- "9.9.9.9" is four labels of
		// digits. TLS would then get it as a ServerName that
		// no certificate carries. The stub would then fail each connection with
		// a verification error, and not tell what was actually
		// wrong. The two keys are a name and a list of addresses. It is
		// easy to swap them by mistake.
		return fmt.Errorf("%s='%s' is not a DNS name; it is the name the upstream's certificate carries, not an address (those go in %s)", nameKey, name, ipsKey)
	}
	seen := map[string]bool{}
	for _, d := range strings.Fields(ips) {
		if !reIPv4.MatchString(d) {
			return fmt.Errorf("%s entry '%s' is not an IPv4 address", ipsKey, d)
		}
		if seen[d] {
			return fmt.Errorf("%s lists an address twice", ipsKey)
		}
		seen[d] = true
	}
	return nil
}

func (c *Config) checkDoT(live bool) error {
	if err := checkDoTPair("DOT_AUTH_NAME", c.DoTAuthName, "DOT_IPS", c.DoTIPs); err != nil {
		return err
	}
	if err := checkDoTPair("HOUSE_DOT_AUTH_NAME", c.HouseDoTAuthName, "HOUSE_DOT_IPS", c.HouseDoTIPs); err != nil {
		return err
	}
	// A house provider is a second stub in front of the house dnsmasq. It is
	// not a way to enable DoT for the house only. Without DOT_IPS, there
	// is no output pin, no box pin and no stub infrastructure at all. Thus
	// the keys would render nothing, and resolution would silently occur in clear.
	if c.HouseDoTIPs != "" && c.DoTIPs == "" {
		return errors.New("HOUSE_DOT_IPS is set but DOT_IPS is not; the house provider is a second stub alongside the box's own, so set DOT_IPS too")
	}
	if c.HouseDoTIPs != "" && c.HouseDNSExplicit {
		return errors.New("HOUSE_DOT_IPS and HOUSE_DNS_UPSTREAM are both set; the house forwards to one resolver, so pick the DoT provider or the plaintext address, not both")
	}
	if c.DoTIPs != "" && live {
		// The stub is now pf itself, so no package can be
		// missing. The ruleset still needs the account that it pins
		// by uid. apply creates it with the other system users, long
		// before this runs.
		if _, err := user.Lookup("pf-dns"); err != nil {
			return errors.New("DOT_IPS is set but there is no pf-dns user; the output chain pins the DoT stub by uid and nft would refuse the ruleset")
		}
	}
	return nil
}

// loadSegments reads segments.d. Absence is the usual case -- most
// boxes have no plain segments. But it is the only accepted excuse.
// These cases all rendered as "no segments" before: an unreadable
// directory, a usual file in its place, an enumeration that fails part
// way, or a declared *.env that is not a regular file. apply then
// removed the firewall and admin paths of segments that are still
// configured. Glob made that worse, because it discarded traversal errors
// completely. Thus os.ReadDir does the enumeration, and loadSegments
// returns its error.
func (c *Config) loadSegments(dir string) error {
	files, err := segmentFiles(dir)
	if err != nil {
		return err
	}
	nftNames := map[string]string{}
	for _, file := range files {
		s, err := c.loadSegment(dir, file, nftNames)
		if err != nil {
			return err
		}
		c.Segments = append(c.Segments, s)
	}
	return nil
}

// segmentFiles is the sorted list of the *.env files in segments.d. An
// absent directory gives no files and no error.
func segmentFiles(dir string) ([]string, error) {
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%s cannot be read (%v), and an unreadable segments.d is not an empty one. Nothing was changed.", dir, err)
	case !st.IsDir():
		return nil, fmt.Errorf("%s is not a directory; segments.d holds one <name>.env per segment. Nothing was changed.", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be listed (%v), so the segments in it cannot be rendered. Nothing was changed.", dir, err)
	}
	var files []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".env") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// loadSegment reads and checks one file of segments.d. nftNames maps the
// nftables name of each segment read before this one to its segment name.
func (c *Config) loadSegment(dir, file string, nftNames map[string]string) (Segment, error) {
	st, err := os.Stat(file)
	if err != nil {
		return Segment{}, fmt.Errorf("%s cannot be read (%v). Nothing was changed.", file, err)
	}
	if !st.Mode().IsRegular() {
		return Segment{}, fmt.Errorf("%s is not a regular file, so the segment it names cannot be read. Nothing was changed.", file)
	}
	name := strings.TrimSuffix(filepath.Base(file), ".env")
	if !reSegName.MatchString(name) {
		return Segment{}, fmt.Errorf("%s: '%s' is not a segment name", file, name)
	}
	if slices.Contains(reservedSegNames, nftName(name)) {
		return Segment{}, fmt.Errorf("%s: '%s' is reserved; the agent network, the house, the Pi and the broker already own its sets, meters, logs and resolver entry. Rename the file. Nothing was changed.", file, name)
	}
	if other, ok := nftNames[nftName(name)]; ok {
		return Segment{}, fmt.Errorf("%s: segments %s and %s name the same nftables sets, meters and chains (a dash is written as an underscore there); rename one. Nothing was changed.", file, other, name)
	}
	nftNames[nftName(name)] = name
	s := Segment{Name: name, Admin: "no"}
	if err := s.readEnv(file); err != nil {
		return Segment{}, err
	}
	if s.IF == "" || s.Net == "" || s.IP == "" {
		return Segment{}, fmt.Errorf("%s: IF, NET and IP are all required", file)
	}
	if err := c.checkSSHFrom(s, file); err != nil {
		return Segment{}, err
	}
	if err := c.segConnBudget(&s, file); err != nil {
		return Segment{}, err
	}
	if err := segParanoid(&s, dir, file); err != nil {
		return Segment{}, err
	}
	if err := segInspect(&s, file); err != nil {
		return Segment{}, err
	}
	if err := loadSegHosts(&s, dir); err != nil {
		return Segment{}, err
	}
	return s, nil
}

// readEnv reads the KEY=VALUE lines of one segments.d file into s.
func (s *Segment) readEnv(file string) error {
	const onOff = "on or off"
	fields := envFields{
		"IF":              {&s.IF, reIface.MatchString, "an interface name"},
		"NET":             {&s.Net, reCIDR4.MatchString, "an IPv4 CIDR"},
		"IP":              {&s.IP, reIPv4.MatchString, "an IPv4 address"},
		"ADMIN":           {&s.Admin, oneOf("yes", "no"), "yes or no"},
		"SSH_TO":          {&s.SSHTo, orEmpty(reRange4.MatchString), "an IPv4 address or a-b range"},
		"BLOCK_DIRECT_IP": {&s.BlockDirectIP, isOnOff, onOff},
		"EGRESS":          {&s.Egress, isEgress, "strict, audit or open"},
		"SSH_FROM":        {&s.SSHFrom, orEmpty(reIPv4.MatchString), "an IPv4 address"},
		"PARANOID":        {&s.Paranoid, isOnOff, onOff},
		"INSPECT":         {&s.Inspect, isOnOff, onOff},
	}
	return EnvLines(file, func(n int, key, val string) error {
		if done, err := fields.set(file, n, key, val); done {
			return err
		}
		switch key {
		case "ALLOW_PORTS":
			val = trimQuotes(val)
			tcp, udp, err := ParsePorts(val)
			if err != nil {
				return badValue(file, n, key, "tcp:N or udp:N-M tokens ("+err.Error()+")")
			}
			s.AllowPorts, s.AllowTCP, s.AllowUDP = val, tcp, udp
		case "DNS_TYPES":
			val = trimQuotes(val)
			for _, tok := range strings.Fields(val) {
				if !ValidDNSType(tok) {
					return badValue(file, n, key, "record types such as \"SRV TXT MX\" ("+tok+")")
				}
			}
			s.DNSTypes = strings.Join(strings.Fields(strings.ToUpper(val)), " ")
		case "DHCP":
			if !isOnOff(val) {
				return fmt.Errorf("%s:%d: DHCP='%s' is not on or off. Nothing was changed.", file, n, val)
			}
			s.DHCP = val
			if val == "off" {
				s.DHCP = ""
			}
		case "DHCP_START", "DHCP_END":
			if !reIPv4.MatchString(val) {
				return fmt.Errorf("%s:%d: %s='%s' is not an IPv4 address. Nothing was changed.", file, n, key, val)
			}
			if key == "DHCP_START" {
				s.DHCPStart = val
			} else {
				s.DHCPEnd = val
			}
		case "CONN_PER_IP", "NEW_PER_IP", "CONN_TOTAL", "NEW_TOTAL":
			if s.ConnLimits == nil {
				s.ConnLimits = map[string]string{}
			}
			s.ConnLimits[key] = val
		default:
			return fmt.Errorf("%s:%d: unknown key '%s'", file, n, key)
		}
		return nil
	})
}

// checkSSHFrom refuses an SSH_FROM inside AGENT_NET or inside the NET of
// the segment. SSH_FROM is an admin machine on a different network. An
// agent address there would give the agents SSH into the desk, which is
// the one thing that the desk fence stops. An address of the segment itself
// is no hole.
func (c *Config) checkSSHFrom(s Segment, file string) error {
	if s.SSHFrom == "" {
		return nil
	}
	from := netip.MustParseAddr(s.SSHFrom)
	for _, n := range []struct{ key, cidr string }{{"AGENT_NET", c.AgentNet}, {"NET", s.Net}} {
		if p, err := netip.ParsePrefix(n.cidr); err == nil && p.Contains(from) {
			return fmt.Errorf("%s: SSH_FROM=%s is inside %s %s; it must be an admin machine on another network (the house, for example)", file, s.SSHFrom, n.key, n.cidr)
		}
	}
	return nil
}

// reservedSegNames are the names, as nftName writes them, that a plain
// segment cannot take. Each is already the prefix of a set, meter, log
// prefix or dns-<name>.jsonl that the agent network, the house, the
// resolver of the Pi or the output rules of the broker use. A segment
// with that name would share them (resolved_house_v4 would let an address
// that the desk resolved through the gate of the house, and the reverse).
var reservedSegNames = []string{"agent", "house", "pi", "broker"}

// segInspect checks an INSPECT=on segment. The engine trusts that a flow
// it gets goes to an address that the resolver of the segment gave: the
// gate keeps 443 to those addresses, as on the agent network. Thus
// INSPECT=on with BLOCK_DIRECT_IP=off asks for two things that cannot both
// be true. off becomes "", so it renders what an absent line does.
func segInspect(s *Segment, file string) error {
	if s.Inspect != "on" {
		s.Inspect = ""
		return nil
	}
	if s.BlockDirectIP == "off" {
		return fmt.Errorf("%s: INSPECT=on needs the resolved-address gate, and BLOCK_DIRECT_IP=off turns it off; remove one of the two lines. Nothing was changed.", file)
	}
	return nil
}

// warnInspectAdmin warns about a segment that has the fence and also SSH
// to the Pi. The fence keeps the real keys off that segment. An agent that
// escapes to it and finds an SSH key for the Pi gets them all the same.
func (c *Config) warnInspectAdmin(w io.Writer) {
	if w == nil {
		return
	}
	for _, s := range c.Segments {
		if s.Inspect == "on" && s.Admin == "yes" {
			fmt.Fprintf(w, "pi-fortress: WARNING segment %s has INSPECT=on and ADMIN=yes. The SSH key that this segment uses for the Pi opens all the real keys on the Pi. Protect it with a hardware key (ssh-keygen -t ed25519-sk) or a passphrase, or set ADMIN=no.\n", s.Name)
		}
	}
}

// segParanoid checks a PARANOID=on segment before the render. Paranoid
// depends on the resolved-address gate. A resolver that answers only the
// allowlist limits nothing if the segment can connect to any address that
// it learned elsewhere. A segment that also disabled that gate asks for
// two things that cannot both be true. Thus segParanoid refuses it, and
// does not let one of them win silently. off becomes "", so an explicit
// off renders exactly what an absent line does.
func segParanoid(s *Segment, dir, file string) error {
	if s.Paranoid != "on" {
		s.Paranoid = ""
		return nil
	}
	if s.BlockDirectIP == "off" {
		return fmt.Errorf("%s: PARANOID=on needs the resolved-address gate, and BLOCK_DIRECT_IP=off turns it off; remove one of the two lines. Nothing was changed.", file)
	}
	s.AllowPath = SegmentAllowPath(dir, s.Name)
	if _, err := CheckSegmentAllow(s.AllowPath); err != nil {
		return fmt.Errorf("%s: PARANOID=on, but %v. A paranoid segment reaches only the names in that file; fill it or set PARANOID=off. Nothing was changed.", file, err)
	}
	return nil
}

func (c *Config) interfaces(o Options, have map[string]bool) error {
	c.IntIF, c.WanIF = o.IntIF, o.WanIF
	switch {
	case o.Live:
		if c.IntIF == "" {
			c.IntIF = ifaceWithAddr(c.PiIP)
		}
		if c.WanIF == "" {
			wan, err := defaultRouteIF()
			if err != nil {
				return err
			}
			c.WanIF = wan
		}
	default:
		setDefault(&c.IntIF, "eth0")
		setDefault(&c.WanIF, "wlan0")
	}
	// A name that was asked for and does not exist is a refusal. It is not a
	// config to render against an absent interface. HOUSE_IF, the
	// segments and the lockout guard read the same table, in
	// checkDeclaredIFs and checkUplink.
	// These two stay exact, while checkDeclaredIFs accepts the parent of a
	// VLAN child. The agent network and the uplink must be up and have
	// addresses before the fence is built. Thus their names cannot be
	// names that apply will create later.
	for _, x := range []declaredIF{{"INT_IF", c.IntIF}, {"WAN_IF", c.WanIF}} {
		if have == nil || x.val == "" {
			continue
		}
		if _, ok := have[x.val]; !ok {
			return fmt.Errorf("%s=%s: no such interface on this box (check ip -br link). Nothing was changed.", x.key, x.val)
		}
	}
	if c.IntIF == "" || c.WanIF == "" {
		c.explainNoIF(o.Stderr)
		return errSilent
	}
	if c.IntIF == c.WanIF {
		return fmt.Errorf("INT_IF and WAN_IF are both %s: %s sits on the uplink, so the agent rules would open DNS, enroll and the engine to the WAN and shadow SSH. Move %s to the agent cable first.", c.IntIF, c.PiIP, c.PiIP)
	}
	if c.HouseIF != "" && (c.HouseIF == c.IntIF || c.HouseIF == c.WanIF) {
		return fmt.Errorf("HOUSE_IF=%s collides with INT_IF=%s or WAN_IF=%s", c.HouseIF, c.IntIF, c.WanIF)
	}
	if c.WGIF != "" && c.HouseIF == "" {
		return fmt.Errorf("WG_IF=%s requires HOUSE_IF; the tunnel is a property of the house segment", c.WGIF)
	}
	if c.WGIF != "" && (c.WGIF == c.WanIF || c.WGIF == c.IntIF || c.WGIF == c.HouseIF) {
		return fmt.Errorf("WG_IF=%s collides with WAN_IF=%s, INT_IF=%s or HOUSE_IF=%s", c.WGIF, c.WanIF, c.IntIF, c.HouseIF)
	}
	return nil
}

// explainNoIF writes to w why INT_IF or WAN_IF is empty, followed by the
// addresses and routes of the box. A nil w gets nothing.
func (c *Config) explainNoIF(w io.Writer) {
	if w == nil {
		return
	}
	if c.IntIF == "" {
		fmt.Fprintf(w, "pi-fortress: no interface holds PI_IP=%s, so INT_IF is empty. INT_IF is found by address, not by name: give that address to the agent interface (nmcli con up agent-net) or point PI_IP in net.env at one of the addresses below. Nothing was changed.\n", c.PiIP)
	}
	if c.WanIF == "" {
		fmt.Fprintln(w, "pi-fortress: no default route, so WAN_IF is empty. The uplink has to be up before the fence can be built. Nothing was changed.")
	}
	for _, args := range [][]string{{"-br", "addr"}, {"route"}} {
		out, _ := exec.Command("ip", args...).CombinedOutput()
		w.Write(out)
	}
}

// ErrSilent is the error when the message and its diagnostics are
// already in Options.Stderr. The caller prints nothing.
var errSilent = errors.New("silent")

func IsSilent(err error) bool { return errors.Is(err, errSilent) }

// ifaceWithAddr is `ip -4 -o addr show to ADDR`: the first interface,
// by index, that has exactly that address.
func ifaceWithAddr(addr string) string {
	want, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == want {
				return ifc.Name
			}
		}
	}
	return ""
}

const procNetRoute = "/proc/net/route"

// defaultRouteIF is `ip -4 route show default` reduced to one device:
// the 0.0.0.0/0 entry with the lowest metric. The kernel will actually
// route through that entry.
//
// /proc/net/route is in FIB-hash order, not metric order. Thus the first
// 00000000 row is arbitrary. Before, a Pi 5 with a default route on
// Ethernet and on Wi-Fi got the row that the hash put first. The real
// uplink then matched no chain, and its input got the policy drop. After a
// reboot, the headless box was then unreachable.
//
// A read error or a table with no default route gives "" and no error: the
// caller already has a diagnostic for an absent uplink. Only an
// ambiguity that the caller must resolve comes back as an error.
func defaultRouteIF() (string, error) {
	data, err := os.ReadFile(procNetRoute)
	if err != nil {
		return "", nil
	}
	return defaultRouteIFFrom(strings.NewReader(string(data)))
}

// defaultRouteIFFrom is defaultRouteIF over an open route table. It finds
// the Destination and Metric columns from the header line, and does not
// hardcode them. Thus, if a kernel adds a column before them, the metric
// does not silently move to a different field.
func defaultRouteIFFrom(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	dstCol, metricCol := -1, -1
	best, bestMetric, tie := "", 0, ""
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if dstCol < 0 {
			for i, name := range f {
				switch name {
				case "Destination":
					dstCol = i
				case "Metric":
					metricCol = i
				}
			}
			if dstCol < 0 || metricCol < 0 {
				return "", fmt.Errorf("%s has no Destination and Metric columns; WAN_IF cannot be detected, set it in net.env. Nothing was changed.", procNetRoute)
			}
			continue
		}
		// A row that is too short for a metric is unusable. It is not a default
		// route with metric 0. Each parse of it would be a guess.
		if len(f) <= dstCol || len(f) <= metricCol || f[dstCol] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(f[metricCol])
		if err != nil {
			continue
		}
		switch {
		case best == "" || metric < bestMetric:
			best, bestMetric, tie = f[0], metric, ""
		case metric == bestMetric && f[0] != best:
			tie = f[0]
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	// The code refuses an exact tie between two devices. It does not select
	// one. The wrong selection fences the wrong uplink and bricks a headless
	// Pi. Unlike a missing route, the operator cannot see what went wrong.
	// To break the tie, the operator adds one line of config. This cannot
	// prevent access by the operator.
	if tie != "" {
		return "", fmt.Errorf("%s and %s both hold a default route with metric %d, so WAN_IF would be a coin toss and the wrong one fences the real uplink. Set WAN_IF in net.env, or give one route a lower metric. Nothing was changed.", best, tie, bestMetric)
	}
	return best, nil
}

func netHas(cidr, ip string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Masked().Contains(a)
}

func netsOverlap(a, b string) bool {
	return netHas(a, strings.SplitN(b, "/", 2)[0]) || netHas(b, strings.SplitN(a, "/", 2)[0])
}

// sshRangeOrder refuses an a-b SSH_TO/HOUSE_SSH_TO range whose low end is
// above its high end. nft reads "b-a" as an interval from b to a. No
// address is both >= b and <= a. Thus the rule loads without error and
// matches no packet. Before, only nft -c found the reversed range, if
// anything found it. val has already passed reRange4. Thus a single address
// (no "-") is correct, and two addresses parse without error.
func sshRangeOrder(val string) error {
	lo, hi, ok := strings.Cut(val, "-")
	if !ok {
		return nil
	}
	a, erra := netip.ParseAddr(lo)
	b, errb := netip.ParseAddr(hi)
	if erra != nil || errb != nil {
		return nil
	}
	if a.Compare(b) > 0 {
		return fmt.Errorf("%s is above %s, so the range is empty and no packet would match it", lo, hi)
	}
	return nil
}

// checkSSHTo checks an SSH_TO or HOUSE_SSH_TO value: each end inside
// AGENT_NET, and a range in the correct order. who names the owner of
// the key in the refusal. An empty value is not set and passes.
func (c *Config) checkSSHTo(who, key, val string) error {
	if val == "" {
		return nil
	}
	for _, e := range strings.Split(val, "-") {
		if !netHas(c.AgentNet, e) {
			return fmt.Errorf("%s: %s=%s is outside AGENT_NET=%s", who, key, val, c.AgentNet)
		}
	}
	if err := sshRangeOrder(val); err != nil {
		return fmt.Errorf("%s: %s=%s: %v", who, key, val, err)
	}
	return nil
}

// The code checks the format of the house keys when it reads house.env.
// This checks what they mean together. A HOUSE_NET that overlaps AGENT_NET
// merges two trust tiers, as a duplicate segment NET would. A DHCP range
// that covers the address of the Pi or the admin reservation gives a
// device an address that the Pi already answers on. The device takes the
// lease, the duplicate is silent, and the admin loses the one way in. Only
// the configured house is checked, as checkSegments does with HOUSE_IF.
func (c *Config) checkHouse() error {
	if c.HouseIF == "" {
		return nil
	}
	if !netHas(c.HouseNet, c.HouseIP) {
		return fmt.Errorf("house: HOUSE_IP=%s is not inside HOUSE_NET=%s", c.HouseIP, c.HouseNet)
	}
	if netsOverlap(c.HouseNet, c.AgentNet) {
		return fmt.Errorf("house: HOUSE_NET=%s overlaps AGENT_NET=%s", c.HouseNet, c.AgentNet)
	}
	if c.HouseAdminIP != "" && !netHas(c.HouseNet, c.HouseAdminIP) {
		return fmt.Errorf("house: HOUSE_ADMIN_IP=%s is not inside HOUSE_NET=%s", c.HouseAdminIP, c.HouseNet)
	}
	// HOUSE_SSH_TO widens the destination of the one house->agent ssh
	// hole past AgentIP. The check uses AGENT_NET, not HOUSE_NET,
	// because its addresses are actually inside that fence.
	if err := c.checkSSHTo("house", "HOUSE_SSH_TO", c.HouseSSHTo); err != nil {
		return err
	}
	for _, x := range []struct{ key, val string }{{"HOUSE_DHCP_START", c.HouseDHCPStart}, {"HOUSE_DHCP_END", c.HouseDHCPEnd}} {
		if !netHas(c.HouseNet, x.val) {
			return fmt.Errorf("house: %s=%s is not inside HOUSE_NET=%s", x.key, x.val, c.HouseNet)
		}
	}
	// The order is by address, not by string. As text, "10.78.0.9" sorts
	// above "10.78.0.100". On the wire, it sorts below it.
	start, err := netip.ParseAddr(c.HouseDHCPStart)
	if err != nil {
		return fmt.Errorf("house: HOUSE_DHCP_START=%s is not an IPv4 address", c.HouseDHCPStart)
	}
	end, err := netip.ParseAddr(c.HouseDHCPEnd)
	if err != nil {
		return fmt.Errorf("house: HOUSE_DHCP_END=%s is not an IPv4 address", c.HouseDHCPEnd)
	}
	if start.Compare(end) > 0 {
		return fmt.Errorf("house: HOUSE_DHCP_START=%s is above HOUSE_DHCP_END=%s, so the range is empty and no house device would get a lease", c.HouseDHCPStart, c.HouseDHCPEnd)
	}
	for _, x := range []struct{ key, val string }{{"HOUSE_IP", c.HouseIP}, {"HOUSE_ADMIN_IP", c.HouseAdminIP}} {
		if x.val == "" {
			continue
		}
		a, err := netip.ParseAddr(x.val)
		if err != nil || a.Compare(start) < 0 || a.Compare(end) > 0 {
			continue
		}
		return fmt.Errorf("house: the DHCP range HOUSE_DHCP_START=%s to HOUSE_DHCP_END=%s covers %s=%s, so a house device would be leased an address the Pi already holds", c.HouseDHCPStart, c.HouseDHCPEnd, x.key, x.val)
	}
	return nil
}

// A segment that shares an interface or an address range with a different
// segment isolates nothing. The isolation rules use iifname as the key,
// and the NAT rules use saddr. Thus a duplicate silently merges
// two trust tiers into one. Refuse it.
func (c *Config) checkSegments() error {
	for i, s := range c.Segments {
		// WG_IF must be in this list, as the other three are. Each
		// generated rule uses the interface name as the key. Thus a segment that
		// claims the tunnel does more than shadow it. Tunnel traffic
		// becomes the traffic of that segment and gets the ADMIN and
		// SSH_TO that it declared. CIDRs that do not overlap prove nothing,
		// because nothing here matches on them.
		if s.IF == c.WGIF && c.WGIF != "" {
			return fmt.Errorf("segment %s: IF=%s collides with WG_IF=%s; the tunnel is the house's, and a segment on that name would fence it as %s", s.Name, s.IF, c.WGIF, s.Name)
		}
		if s.IF == c.IntIF || s.IF == c.WanIF || (c.HouseIF != "" && s.IF == c.HouseIF) {
			house := c.HouseIF
			if house == "" {
				house = "none"
			}
			return fmt.Errorf("segment %s: IF=%s collides with INT_IF=%s, WAN_IF=%s or HOUSE_IF=%s", s.Name, s.IF, c.IntIF, c.WanIF, house)
		}
		if !netHas(s.Net, s.IP) {
			return fmt.Errorf("segment %s: IP=%s is not inside NET=%s", s.Name, s.IP, s.Net)
		}
		if netsOverlap(s.Net, c.AgentNet) {
			return fmt.Errorf("segment %s: NET=%s overlaps AGENT_NET=%s", s.Name, s.Net, c.AgentNet)
		}
		if c.HouseIF != "" && netsOverlap(s.Net, c.HouseNet) {
			return fmt.Errorf("segment %s: NET=%s overlaps HOUSE_NET=%s", s.Name, s.Net, c.HouseNet)
		}
		if err := c.checkSSHTo("segment "+s.Name, "SSH_TO", s.SSHTo); err != nil {
			return err
		}
		for _, t := range c.Segments[:i] {
			if s.IF == t.IF {
				return fmt.Errorf("segments %s and %s share IF=%s", s.Name, t.Name, s.IF)
			}
			if netsOverlap(s.Net, t.Net) {
				return fmt.Errorf("segments %s and %s overlap on %s", s.Name, t.Name, s.Net)
			}
		}
		if err := checkSegDHCP(s); err != nil {
			return err
		}
		if err := checkSegHosts(s); err != nil {
			return err
		}
	}
	return nil
}

// checkSegDHCP checks what DHCP_START and DHCP_END mean on one segment:
// a range of addresses that a device can hold, inside NET. The range never
// gives out the address of the Pi or the two addresses that are not host
// addresses. No range-against-range check is necessary. Each range is
// inside its own NET, and checkSegments and checkHouse already refused a
// NET that overlaps the NET of a different segment or HOUSE_NET. The code
// also checks a range in the file when DHCP is off. Thus a typo is found
// on the day it is written, not on the day DHCP is enabled.
func checkSegDHCP(s Segment) error {
	if s.DHCPStart == "" || s.DHCPEnd == "" {
		switch {
		case s.DHCP == "on":
			return fmt.Errorf("segment %s: DHCP=on needs DHCP_START and DHCP_END, the first and last address to lease inside NET=%s. Nothing was changed.", s.Name, s.Net)
		case s.DHCPStart != "" || s.DHCPEnd != "":
			return fmt.Errorf("segment %s: DHCP_START and DHCP_END go together; set both or neither. Nothing was changed.", s.Name)
		}
		return nil
	}
	for _, x := range []struct{ key, val string }{{"DHCP_START", s.DHCPStart}, {"DHCP_END", s.DHCPEnd}} {
		if !netHas(s.Net, x.val) {
			return fmt.Errorf("segment %s: %s=%s is not inside NET=%s. Nothing was changed.", s.Name, x.key, x.val, s.Net)
		}
	}
	start, end := netip.MustParseAddr(s.DHCPStart), netip.MustParseAddr(s.DHCPEnd)
	if start.Compare(end) > 0 {
		return fmt.Errorf("segment %s: DHCP_START=%s is above DHCP_END=%s, so the range is empty and no device would get a lease. Nothing was changed.", s.Name, s.DHCPStart, s.DHCPEnd)
	}
	covers := func(a netip.Addr) bool { return a.Compare(start) >= 0 && a.Compare(end) <= 0 }
	rng := fmt.Sprintf("the DHCP range DHCP_START=%s to DHCP_END=%s", s.DHCPStart, s.DHCPEnd)
	if covers(netip.MustParseAddr(s.IP)) {
		return fmt.Errorf("segment %s: %s covers IP=%s, so a device would be leased the address the Pi answers on. Nothing was changed.", s.Name, rng, s.IP)
	}
	p := netip.MustParsePrefix(s.Net).Masked()
	network := p.Addr()
	bcast := lastAddr(p)
	if covers(network) {
		return fmt.Errorf("segment %s: %s covers %s, the network address of NET=%s, which no device can hold. Nothing was changed.", s.Name, rng, network, s.Net)
	}
	if covers(bcast) {
		return fmt.Errorf("segment %s: %s covers %s, the broadcast address of NET=%s, which no device can hold. Nothing was changed.", s.Name, rng, bcast, s.Net)
	}
	return nil
}

// lastAddr is the highest address in an IPv4 prefix, its broadcast.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// CheckWGBypassMark validates WG_BYPASS_MARK for its use in the ruleset and
// wg-routes.sh. The kill switch in forward accepts the uplink only for a
// packet whose full mark equals it. `ip rule fwmark` routes the same
// packets around the tunnel. Thus it must be a 32-bit hex value and not
// zero. Zero is the mark of each packet that nobody marked. It would route
// all of the house out the uplink, and the kill switch would accept all of
// it. It must also not use the bits of the SNI check (sniBits). pf dns and
// forward rewrite these bits on each checked flow.
// Empty is the default, 0x1.
func CheckWGBypassMark(v string) error {
	if v == "" {
		return nil
	}
	if !reFwmark.MatchString(v) || len(v) > 10 {
		return errors.New("not a hex fwmark of at most 32 bits (e.g. 0x1)")
	}
	m, err := strconv.ParseUint(v[2:], 16, 32)
	if err != nil {
		return errors.New("not a hex fwmark of at most 32 bits (e.g. 0x1)")
	}
	if m == 0 {
		return errors.New("0, the mark every unmarked packet carries, so the whole house would bypass the tunnel and the kill switch")
	}
	bits, _ := strconv.ParseUint(sniBits[2:], 16, 32)
	if m&bits != 0 {
		return fmt.Errorf("%s, which overlaps the SNI check's mark bits %s", v, sniBits)
	}
	return nil
}

// CheckFakeIPNet checks what FAKEIP_NET must be on its own: an IPv4
// network, written as the network, between /16 and /24, inside one of
// fakeIPHomes. It is exported for the validator of the admin seat, so the
// two cannot become different, as a copied rule would. The code names
// 127/8 and 169.254/16, and does not leave them to the home rule, so that
// the refusal tells why. Loopback is the resolvers of the Pi. Link-local is
// where a cloud or a USB gadget puts its metadata service. A pool there
// answers a lookup with an address that already has a meaning for the Pi.
func CheckFakeIPNet(v string) error {
	if !reCIDR4.MatchString(v) {
		return errors.New("is not an IPv4 CIDR")
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return errors.New("is not an IPv4 CIDR")
	}
	if masked := p.Masked(); masked != p {
		return fmt.Errorf("carries a host address; write the network itself, %s", masked)
	}
	if p.Bits() < minFakeIPBits || p.Bits() > maxFakeIPBits {
		return fmt.Errorf("is a /%d; the pool is /%d to /%d", p.Bits(), minFakeIPBits, maxFakeIPBits)
	}
	for _, r := range []struct{ net, what string }{{"127.0.0.0/8", "loopback, where the Pi's own resolvers listen"}, {"169.254.0.0/16", "link-local"}} {
		if netsOverlap(v, r.net) {
			return fmt.Errorf("overlaps %s, %s", r.net, r.what)
		}
	}
	for _, h := range fakeIPHomes {
		hp := netip.MustParsePrefix(h)
		if hp.Bits() <= p.Bits() && hp.Contains(p.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("is not inside %s; the pool must sit in ranges the broker is already refused from, so a synthetic address can never be dialled for real", strings.Join(fakeIPHomes, ", "))
}

// checkFakeIP checks what FAKEIP_NET means next to all else that the Pi
// routes. A pool address is a name that the agent got. The gate lets each
// pool address through to the TLS engine. Thus, if a pool overlaps a
// network that the Pi is on, the real hosts of that network look the same
// as synthetic ones. An agent that connects to a house device on 443 would
// pass the gate as a resolved name. The broker would then look for a name
// that no one asked for. The check also occurs in forward mode, as for
// DNS_UPSTREAM under DoT. A later change to fakeip must not be the moment
// when an old overlap is found. The desk seat is a segments.d segment, so
// the segment loop covers it. DESK_NET in net.env is the VirtualBox side
// of the lab, and render
// never sees it.
func (c *Config) checkFakeIP() error {
	nets := []struct{ key, val string }{{"AGENT_NET", c.AgentNet}}
	if c.HouseIF != "" {
		nets = append(nets, struct{ key, val string }{"HOUSE_NET", c.HouseNet})
	}
	for _, s := range c.Segments {
		nets = append(nets, struct{ key, val string }{"segment " + s.Name + " NET", s.Net})
	}
	for _, n := range nets {
		if netsOverlap(c.FakeIPNet, n.val) {
			return fmt.Errorf("FAKEIP_NET=%s overlaps %s=%s; the pool must not share addresses with a network the Pi is on (%s)", c.FakeIPNet, n.key, n.val, c.EnvSrc)
		}
	}
	return nil
}

// ParsePorts reads HOUSE_ALLOW_PORTS: space-separated "tcp:N" or
// "udp:N-M" tokens. It returns the ports of each protocol as an nft set
// body ("27015, 27020-27030"), or empty when there are none. Each number
// is plain decimal, and ParsePorts writes it from the parsed value. nft
// reads a leading zero as octal, so a "0443" passed through would open port 291.
func ParsePorts(v string) (tcp, udp string, err error) {
	var t, u []string
	for _, tok := range strings.Fields(v) {
		proto, rng, ok := strings.Cut(tok, ":")
		if !ok || (proto != "tcp" && proto != "udp") {
			return "", "", fmt.Errorf("%q: want tcp:N or udp:N", tok)
		}
		lo, hi, isRange := strings.Cut(rng, "-")
		a, okA := atoiStrict(lo)
		b, okB := a, true
		if isRange {
			b, okB = atoiStrict(hi)
		}
		if !okA || !okB || a < 1 || b > 65535 || a > b {
			return "", "", fmt.Errorf("%q: a port is 1-65535 in plain decimal, a range low-high", tok)
		}
		out := strconv.Itoa(a)
		if isRange {
			out += "-" + strconv.Itoa(b)
		}
		if proto == "tcp" {
			t = append(t, out)
		} else {
			u = append(u, out)
		}
	}
	return strings.Join(t, ", "), strings.Join(u, ", "), nil
}

// DNSTypeNames are the record types that pf dns has a name for
// (internal/dnsd, namedTypes). All other types are written TYPE<n>. A
// test there keeps the two lists the same.
var DNSTypeNames = []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "SOA", "HTTPS", "SVCB"}

// ValidDNSType reports whether pf dns will take tok as a DNS_TYPES entry.
func ValidDNSType(tok string) bool {
	tok = strings.ToUpper(tok)
	if slices.Contains(DNSTypeNames, tok) {
		return true
	}
	n, ok := strings.CutPrefix(tok, "TYPE")
	if !ok || n == "" {
		return false
	}
	v, err := strconv.ParseUint(n, 10, 16)
	return err == nil && v > 0
}
