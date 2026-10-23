// Package policycompile changes the policy files into the artifacts that the
// resolver and nftables load: merged domain and IP lists without the
// never-block sets. pf compile, internal/fetch and internal/admin call it.
package policycompile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"pi-fortress/internal/base"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/fence"
)

var (
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	// TEST-NET-1 is not in this list on purpose. 192.0.2.1 is the lab canary in
	// blacklist.ips and the echo net of the fence.
	Reserved = base.MustPrefixes(
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
	)
)

const minBits = 8

// FeedMinBits is the widest prefix that a fetched IP feed can add to the
// blocklist, when sources.json does not set min_ip_prefix. One feed line
// with a /8 drops 16M addresses. The widest entries of the shipped feeds
// are /12, in Spamhaus DROP (2026-09-21: three /12, and /14 and /15
// ranges). Thus /12 keeps each real entry, and one line drops at most 1M
// addresses. blacklist.ips of the operator keeps the /8 floor (minBits).
const FeedMinBits = 12

// FeedMinBitsIn gives the min_ip_prefix of sources.json in policyDir, or
// FeedMinBits. A value that is not in minBits..32, or a file that does not
// parse, gives FeedMinBits: pf fetch reports a bad sources.json, and the
// compile must not open the floor because of it.
func FeedMinBitsIn(policyDir string) int {
	raw, err := os.ReadFile(filepath.Join(policyDir, "sources.json"))
	if err != nil {
		return FeedMinBits
	}
	var spec struct {
		MinIPPrefix int `json:"min_ip_prefix"`
	}
	if json.Unmarshal(raw, &spec) != nil || spec.MinIPPrefix < minBits || spec.MinIPPrefix > 32 {
		return FeedMinBits
	}
	return spec.MinIPPrefix
}

// widerThan says if an IPv4 item is a prefix wider than /bits.
func widerThan(item string, bits int) bool {
	p, ok := parsePrefix4(item)
	return ok && p.Bits() < bits
}

// An allow list cancels a drop. Thus a wide prefix there is a hole, not a
// typo that fails closed. /24 is sufficient for the seeded ControlD anycast
// and for any single resolver or pinned service.
const allowMinBits = 24

// ssh_allow.ips opens TCP 22, a path past the fence. Thus it uses the rule
// of an allow list, not the /8 floor of the blocklist. The cap is /16, not
// /24 as for direct_ip.allow, because a forge publishes its SSH front door
// as ranges wider than /24 (GitHub: 140.82.112.0/20).
const sshMinBits = 16

// allowWhat and sshWhat tell what an "allow_ips" line and an "ssh_ips" line
// must be. The warning for a skipped line uses them. A feed line that is
// skipped gets no warning: it is feed noise.
var (
	allowWhat = fmt.Sprintf("a public IPv4 address or range (/%d or narrower)", allowMinBits)
	sshWhat   = fmt.Sprintf("a public IPv4 address or network (/%d or narrower, no host bits)", sshMinBits)
)

type Out struct {
	NFT    string
	DNS    string
	DoHNFT string
	DoHDNS string
	// HouseDNS, when set, receives the house-only sinkhole: the shipped
	// house_default.domains, the feeds with segment "house", and the
	// house.domains of the operator, without house_never_block.
	HouseDNS string
	// HouseVPNDNS receives the house VPN/proxy feed (HouseVPNFile), without
	// house_never_block and without the names that HouseDNS already holds. It
	// is a separate file because apply serves it only while HOUSE_BLOCK_VPN is on.
	HouseVPNDNS string
	// HouseDoHDNS receives the DoH sinkhole without the house_private_dns.domains
	// of the operator (suffix match). HousePrivateDNSNFT receives the coalesced
	// house_private_dns.ips. apply.sh serves and accepts them only with
	// HOUSE_PRIVATE_DNS=on. The compiler writes them each time a caller asks.
	// Thus a change of the flag needs an apply, not a recompile.
	HouseDoHDNS        string
	HousePrivateDNSNFT string
	// DirectIPNFT receives the coalesced direct_ip.allow: the addresses that a
	// client can reach without a resolver answer for them.
	DirectIPNFT string
	// HouseDirectIPNFT is the same for house_direct_ip.allow. Only the house
	// gate reads that file. direct_ip.allow is only for the agent.
	HouseDirectIPNFT string
	// HouseWhatsAppNFT receives the coalesced house_whatsapp.ips (the shipped
	// ranges of Meta). HOUSE_ALLOW_WHATSAPP lets the non-TLS chat protocol of
	// WhatsApp go to these ranges.
	HouseWhatsAppNFT string
	// SSHAllowNFT receives the coalesced ssh_allow.ips: the public addresses
	// that an agent segment can reach on TCP 22. It is empty by default. For
	// an empty list, pf render emits no set and no accept.
	SSHAllowNFT string
	// DomainMap and IPMap receive one "<item>\t<feed>" line for each compiled
	// sinkhole name (agent, then house) and for each blacklist prefix before
	// coalescence. The feed comes from generated/feeds.map. It is "local" when
	// the map does not name the item. pf observe
	// reads them to label a blocked event.
	DomainMap string
	IPMap     string
}

type Summary struct {
	IPs             int
	Domains         int
	DoHIPs          int
	DoHDomains      int
	HouseDomains    int
	HousePrivateDNS int
	DirectIPs       int
	HouseDirectIPs  int
	SSHAllows       int
	GitPushes       int
	// Warnings are lines that the operator wrote into a hand-kept address list
	// (ssh_allow.ips, direct_ip.allow, the direct_ip.allow of the house). Each
	// line was not an address that the list accepts, and the compiler skipped
	// it. Line prints each one after the counts.
	Warnings []string
	// SharedParents are the feed entries that did not compile because each
	// is at a shared parent (AtSharedParent), in order. Line prints them.
	SharedParents []string
	// WidePrefixes are the feed prefixes that did not compile because each
	// is wider than FeedFloor, in order. Line prints them.
	WidePrefixes []string
	FeedFloor    int
}

// skipLine tells the operator which feed entries did not compile, and why.
// It names the first few. A feed that goes wrong can carry many of them.
func skipLine(items []string, why string) string {
	const show = 5
	names := strings.Join(items[:min(len(items), show)], ", ")
	if len(items) > show {
		names += ", ..."
	}
	return fmt.Sprintf("\ncompile: skipped %d feed entries %s: %s", len(items), why, names)
}

func (s Summary) Line() string {
	line := fmt.Sprintf("compile: %d ips, %d domains, %d doh_ips, %d doh_domains", s.IPs, s.Domains, s.DoHIPs, s.DoHDomains)
	if s.HouseDomains > 0 {
		line += fmt.Sprintf(", %d house_domains", s.HouseDomains)
	}
	if s.HousePrivateDNS > 0 {
		line += fmt.Sprintf(", %d house_private_dns", s.HousePrivateDNS)
	}
	if s.DirectIPs > 0 {
		line += fmt.Sprintf(", %d direct_ips", s.DirectIPs)
	}
	if s.HouseDirectIPs > 0 {
		line += fmt.Sprintf(", %d house_direct_ips", s.HouseDirectIPs)
	}
	if s.SSHAllows > 0 {
		line += fmt.Sprintf(", %d ssh_allows", s.SSHAllows)
	}
	if s.GitPushes > 0 {
		line += fmt.Sprintf(", %d git_pushes", s.GitPushes)
	}
	for _, w := range s.Warnings {
		line += "\ncompile: warning: " + w
	}
	if len(s.SharedParents) > 0 {
		line += skipLine(s.SharedParents, "at a shared parent ("+SharedParentsFile+")")
	}
	if len(s.WidePrefixes) > 0 {
		line += skipLine(s.WidePrefixes, fmt.Sprintf("wider than /%d (min_ip_prefix)", s.FeedFloor))
	}
	return line
}

func StripLine(raw string) string {
	line := raw
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	if i := strings.Index(line, ";"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

func parsePrefix4(token string) (netip.Prefix, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(token, "/") {
		p, err := netip.ParsePrefix(token)
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	addr, err := netip.ParseAddr(token)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, 32), true
}

func prefixContains(outer, inner netip.Prefix) bool {
	if !outer.IsValid() || !inner.IsValid() {
		return false
	}
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Addr())
}

func ParseIPv4(token string) (string, bool) { return parseIPv4(token, minBits) }

// ParseAllowIPv4 is ParseIPv4 for a list that opens something
// (direct_ip.allow, house_direct_ip.allow): it accepts nothing wider than /24.
func ParseAllowIPv4(token string) (string, bool) { return parseIPv4(token, allowMinBits) }

// ParseSSHIPv4 parses the token of ssh_allow.ips: /16 or narrower, with a
// prefix written as its network. Before, the code masked 140.82.114.4/20 to
// 140.82.112.0/20 without a warning. This opened a /20 for an operator who
// possibly meant the one host.
func ParseSSHIPv4(token string) (string, bool) {
	if p, err := netip.ParsePrefix(strings.TrimSpace(token)); err == nil && p.Masked() != p {
		return "", false
	}
	return parseIPv4(token, sshMinBits)
}

// ParseHostIPv4 accepts one address, not a range. house_private_dns.ips pins
// an endpoint, and the range of a provider also holds its public resolvers.
func ParseHostIPv4(token string) (string, bool) {
	got, ok := parseIPv4(token, 32)
	return strings.TrimSuffix(got, "/32"), ok
}

// ParseEndpoint parses a resolver name for one profile,
// <profile>.dns.<provider>.<tld>. It must have a minimum of four labels,
// because privateDNSEndpoints sinkholes its parent zone.
func ParseEndpoint(token string) (string, bool) {
	got, ok := ParseDomain(token)
	if !ok || strings.Count(got, ".") < 3 {
		return "", false
	}
	return got, true
}

func parseIPv4(token string, min int) (string, bool) {
	p, ok := parsePrefix4(token)
	if !ok {
		return "", false
	}
	if p.Bits() < min {
		return "", false
	}
	for _, block := range Reserved {
		if p.Overlaps(block) {
			return "", false
		}
	}
	if p.Bits() < 32 {
		return p.String(), true
	}
	return p.Addr().String(), true
}

func ParseDomain(token string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(token))
	name = strings.TrimRight(name, ".")
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if len(name) > 253 || !domainRe.MatchString(name) {
		return "", false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 {
			return "", false
		}
	}
	return name, true
}

func IsNeverDomain(name string, never map[string]struct{}) bool {
	return corepolicy.HostIn(name, never)
}

// BlocksCoreHost says if a block entry would block a host that core.hosts
// binds credentials to: the entry is that host or a parent of it, or it is
// under a "*." entry. never_block is a coarse shield on purpose
// (docs/fence.md): a shield below a listed parent leaves the parent entry
// in place. A core host is not a curation choice. A feed line for
// anthropic.com blocked api.anthropic.com, and the agent lost the service
// that holds its credentials. So for these hosts the parent entry goes.
// An entry under an exact host stays: it does not block the host itself.
func BlocksCoreHost(entry string, core *corepolicy.Policy) bool {
	if core == nil {
		return false
	}
	if corepolicy.HostIn(entry, core.Suffix) {
		return true
	}
	if _, ok := core.Hosts[entry]; ok {
		return true
	}
	under := "." + entry
	for h := range core.Hosts {
		if strings.HasSuffix(h, under) {
			return true
		}
	}
	return false
}

// SharedParentsFile lists the shared parents: names under which many
// unrelated owners have their own sites (github.io, herokuapp.com), and
// public suffixes with two labels (co.uk). It ships, and each ship
// replaces it.
const SharedParentsFile = "shared_parents.domains"

// SharedParents gives the set that AtSharedParent reads: each name of
// the list and each parent of it.
func SharedParents(names []string) map[string]struct{} {
	m := make(map[string]struct{}, 2*len(names))
	for _, name := range names {
		for {
			m[name] = struct{}{}
			_, rest, ok := strings.Cut(name, ".")
			if !ok {
				break
			}
			name = rest
		}
	}
	return m
}

// AtSharedParent says if a feed entry is a shared parent or a parent of
// one. A feed line for github.io blocks the sites of all owners under it,
// not only the one bad site that the feed meant. So the entry does not
// compile. An entry under a shared parent (x.github.io) stays. The rule
// applies only to the feeds: a name that the operator writes in a block
// list compiles as written.
func AtSharedParent(entry string, shared map[string]struct{}) bool {
	_, ok := shared[entry]
	return ok
}

// dropFeed removes from items each entry that refuse matches, and adds it
// to dropped.
func dropFeed(items []string, refuse func(string) bool, dropped map[string]struct{}) []string {
	var kept []string
	for _, item := range items {
		if refuse(item) {
			dropped[item] = struct{}{}
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

// sorted gives the items of a set in order.
func sorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for item := range m {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// set is the membership set of items.
func set(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

// keepNew appends to dst the items of src that are new to seen and not
// refused, in source order.
func keepNew(dst, src []string, seen map[string]struct{}, refuse func(string) bool) []string {
	for _, item := range src {
		if _, ok := seen[item]; ok || refuse(item) {
			continue
		}
		seen[item] = struct{}{}
		dst = append(dst, item)
	}
	return dst
}

func IsNeverIP(item string, never []netip.Prefix) bool {
	p, ok := parsePrefix4(item)
	if !ok {
		return false
	}
	for _, n := range never {
		if p.Overlaps(n) {
			return true
		}
	}
	return false
}

func mergeAdjacent(a, b netip.Prefix) (netip.Prefix, bool) {
	if !a.IsValid() || !b.IsValid() || a.Bits() != b.Bits() || a.Bits() == 0 {
		return netip.Prefix{}, false
	}
	parentBits := a.Bits() - 1
	parent, err := a.Addr().Prefix(parentBits)
	if err != nil {
		return netip.Prefix{}, false
	}
	parentB, err := b.Addr().Prefix(parentBits)
	if err != nil {
		return netip.Prefix{}, false
	}
	if parent != parentB {
		return netip.Prefix{}, false
	}
	return parent, true
}

func collapsePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		c := in[i].Addr().Compare(in[j].Addr())
		if c != 0 {
			return c < 0
		}
		return in[i].Bits() < in[j].Bits()
	})
	changed := true
	cur := append([]netip.Prefix(nil), in...)
	for changed {
		changed = false
		var out []netip.Prefix
		for _, p := range cur {
			if len(out) == 0 {
				out = append(out, p)
				continue
			}
			last := out[len(out)-1]
			if prefixContains(last, p) {
				changed = true
				continue
			}
			if prefixContains(p, last) {
				out[len(out)-1] = p
				changed = true
				continue
			}
			if m, ok := mergeAdjacent(last, p); ok {
				out[len(out)-1] = m
				changed = true
				continue
			}
			out = append(out, p)
		}
		cur = out
	}
	return cur
}

func CoalesceIPv4(items []string) []string {
	var nets []netip.Prefix
	for _, item := range items {
		p, ok := parsePrefix4(item)
		if !ok {
			continue
		}
		nets = append(nets, p)
	}
	sort.Slice(nets, func(i, j int) bool {
		if nets[i].Bits() != nets[j].Bits() {
			return nets[i].Bits() < nets[j].Bits()
		}
		return nets[i].Addr().Compare(nets[j].Addr()) < 0
	})
	var kept []netip.Prefix
	for _, n := range nets {
		covered := false
		for _, prev := range kept {
			if prefixContains(prev, n) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, n)
		}
	}
	collapsed := collapsePrefixes(kept)
	out := make([]string, 0, len(collapsed))
	for _, p := range collapsed {
		if p.Bits() == 32 {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out
}

func LoadTokens(path, kind string) ([]string, error) {
	out, _, err := loadTokens(path, kind)
	return out, err
}

// loadWithLocal is LoadTokens of path and then of path.local: the shipped
// list plus the lines of the operator. An upgrade or a provision replaces
// the shipped list and keeps the local one. A token in both files counts
// one time.
func loadWithLocal(path, kind string) ([]string, error) {
	shipped, err := LoadTokens(path, kind)
	if err != nil {
		return nil, err
	}
	local, err := LoadTokens(path+".local", kind)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(shipped)+len(local))
	out := make([]string, 0, len(shipped)+len(local))
	for _, t := range append(shipped, local...) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// checkKeyRulesLocal loads key_prefixes.rules.local as the broker loads
// its rules. apply appends this file to the shipped key_prefixes.rules,
// and the broker, the engine, pf dns and pf observe read the result. Thus
// a rule that does not compile, or that has no literal prefix, stops the
// apply here, before anything installs. It does not stop the broker at
// its start. A missing file, or a file with only comments, adds nothing.
func checkKeyRulesLocal(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	tr, err := fence.LoadTokenRules(path)
	if errors.Is(err, fence.ErrNoRules) {
		return nil
	}
	if err == nil {
		err = tr.Streamable()
	}
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

// badLine is a line loadTokens skipped: its 1-based number and token.
type badLine struct {
	n     int
	token string
}

// loadOperatorIPs is LoadTokens for an address list that the operator keeps
// by hand. In such a list, a skipped line is a mistake to report, not feed
// noise. Before, a hostname in ssh_allow.ips disappeared without a warning.
// The operator who wrote github.com there got nothing and no reason.
//
// It gives a warning, not an error. A file that already holds a name
// compiled without errors before. If the compiler refused it now, pf apply
// would stop on a Pi that worked, for a line that never did anything.
func loadOperatorIPs(path, kind, what string, warn *[]string) ([]string, error) {
	out, bad, err := loadTokens(path, kind)
	for _, b := range bad {
		hint := ""
		if _, ok := parsePrefix4(b.token); !ok {
			hint = " (a name is not accepted: list the host's address)"
		} else if p, err := netip.ParsePrefix(b.token); err == nil && p.Masked() != p {
			hint = fmt.Sprintf(" (it carries host bits: write the network, %s, or the one address)", p.Masked())
		}
		*warn = append(*warn, fmt.Sprintf("%s line %d: %q is not %s; skipped%s",
			filepath.Base(path), b.n, b.token, what, hint))
	}
	return out, err
}

func loadTokens(path, kind string) ([]string, []badLine, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var out []string
	var bad []badLine
	n := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		n++
		token := StripLine(line)
		if token == "" {
			continue
		}
		var parsed string
		var ok bool
		switch kind {
		case "ips":
			parsed, ok = ParseIPv4(token)
		case "allow_ips":
			parsed, ok = ParseAllowIPv4(token)
		case "ssh_ips":
			parsed, ok = ParseSSHIPv4(token)
		case "host_ips":
			parsed, ok = ParseHostIPv4(token)
		case "endpoints":
			parsed, ok = ParseEndpoint(token)
		default:
			parsed, ok = ParseDomain(token)
		}
		if ok {
			out = append(out, parsed)
		} else {
			bad = append(bad, badLine{n: n, token: token})
		}
	}
	return out, bad, nil
}

// collect loads the block list of a segment in two halves: feed, which pf
// fetch writes, and local, which the operator writes.
func collect(policyDir string, seg SegmentPolicy, kind string) (feed, local, never []string, err error) {
	never, err = LoadTokens(filepath.Join(policyDir, seg.File("never_block."+kind)), kind)
	if err != nil {
		return nil, nil, nil, err
	}
	feed, err = LoadTokens(filepath.Join(policyDir, seg.Generated(kind)), kind)
	if err != nil {
		return nil, nil, nil, err
	}
	local, err = LoadTokens(filepath.Join(policyDir, seg.Sinkhole(kind)), kind)
	if err != nil {
		return nil, nil, nil, err
	}
	return feed, local, never, nil
}

func nftElements(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return "elements = {\n      " + strings.Join(items, ",\n      ") + "\n    }"
}

// privateDNSEndpoints changes house_private_dns.domains (the secure-DNS
// endpoints of the operator, for example abc123.dns.controld.com) and
// house_private_dns.ips (the addresses that they are pinned to) into
// resolver lines and the allowed addresses of the firewall.
//
// A provider serves the profiles of all customers, and its free public
// resolvers, from the same anycast addresses. It identifies each one by the
// name inside TLS, and the firewall cannot read that name. Thus the control
// is the name, at the house resolver. The house resolver answers each
// endpoint from here with its first pinned address. It sinkholes the parent
// zone (dns.controld.com), so no other profile of that provider resolves in
// the house. The address list holds only single addresses. Thus the
// firewall opens the pins of the endpoint, not the ranges of the provider.
// Those ranges also hold its public resolvers (2026-09-23: the first
// version opened 76.76.2.0/24 and 76.76.10.0/24, that is, any ControlD resolver).
//
// The pin is per address. The firewall does not check the SNI of a
// connection to a pinned address; the house resolver is what answers by
// name. Each usual device resolves the name first.
func privateDNSEndpoints(names, ips []string) (string, []string, error) {
	var pins []string
	for _, ip := range ips {
		addr, bits, ok := strings.Cut(ip, "/")
		if ok && bits != "32" {
			return "", nil, fmt.Errorf("house_private_dns.ips: %s is a range; list the endpoint's own addresses, one per line (a provider's range also holds its public resolvers)", ip)
		}
		pins = append(pins, addr)
	}
	if len(names) > 0 && len(pins) == 0 {
		return "", nil, fmt.Errorf("house_private_dns.domains lists %s but house_private_dns.ips has no address to pin it to", names[0])
	}
	var b strings.Builder
	parents := map[string]bool{}
	for _, name := range names {
		labels := strings.Split(name, ".")
		// The code sinkholes the parent zone. Thus it must be the profile zone
		// of a provider and never a registrable domain. If not, an endpoint of
		// dns.example.com would sinkhole all of example.com.
		if len(labels) < 4 {
			return "", nil, fmt.Errorf("house_private_dns.domains: %s is not a per-profile endpoint (<profile>.dns.<provider>.<tld>); its parent zone %s would be sinkholed whole", name, strings.Join(labels[1:], "."))
		}
		parent := strings.Join(labels[1:], ".")
		if !parents[parent] {
			parents[parent] = true
			b.WriteString("address=/" + parent + "/0.0.0.0\n")
		}
	}
	for _, name := range names {
		b.WriteString("address=/" + name + "/" + pins[0] + "\n")
	}
	return b.String(), pins, nil
}

func dnsLines(names []string) string {
	if len(names) == 0 {
		return ""
	}
	lines := make([]string, 0, len(names))
	for _, name := range names {
		lines = append(lines, "address=/"+name+"/0.0.0.0")
	}
	return strings.Join(lines, "\n") + "\n"
}

// ParseMap reads "<item>\t<feed>" lines. This is the format of
// generated/feeds.map and of the compiled DomainMap and IPMap. It skips
// blank and malformed lines. The first feed named for an item wins.
func ParseMap(text string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		item, feed, ok := strings.Cut(strings.TrimSpace(line), "\t")
		item, feed = strings.TrimSpace(item), strings.TrimSpace(feed)
		if !ok || item == "" || feed == "" {
			continue
		}
		if _, dup := m[item]; !dup {
			m[item] = feed
		}
	}
	return m
}

func mapLines(items []string, feeds map[string]string) string {
	var b strings.Builder
	for _, item := range items {
		feed := feeds[item]
		if feed == "" {
			feed = "local"
		}
		b.WriteString(item + "\t" + feed + "\n")
	}
	return b.String()
}

func writeFile(path, text string) error {
	if path == "" {
		return nil
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return os.WriteFile(path, []byte(text), 0644)
}

// compileOperatorIPs loads one list of operator addresses and writes it to
// path as nft elements.
func compileOperatorIPs(src, kind, what string, warn *[]string, path string) ([]string, error) {
	ips, err := loadOperatorIPs(src, kind, what, warn)
	if err != nil {
		return nil, err
	}
	final := CoalesceIPv4(ips)
	if err := writeFile(path, nftElements(final)); err != nil {
		return nil, err
	}
	return final, nil
}

// compileHouse removes the entries of the two house feeds that refuseFeed
// matches. The shipped defaults and house.domains of the operator compile
// as written.
func compileHouse(policyDir string, house SegmentPolicy, out Out, refuseFeed func([]string) []string) (houseFinal, houseVPNFinal []string, err error) {
	if out.HouseDNS == "" {
		return nil, nil, nil
	}
	// The shared never_block keeps registries and Google APIs reachable for
	// agents. On the house side, it would protect ad hosts under google.com.
	// The house list obeys only its own file.
	houseNeverList, err := LoadTokens(filepath.Join(policyDir, house.File("never_block.domains")), "domains")
	if err != nil {
		return nil, nil, err
	}
	houseNever := set(houseNeverList)
	isNever := func(d string) bool { return IsNeverDomain(d, houseNever) }
	seenHouse := map[string]struct{}{}
	// The defaults go first. Thus the head of the compiled file is the shipped
	// baseline, and the volatile feed is in the middle of each diff.
	for _, f := range []struct {
		name string
		feed bool
	}{
		{house.File("default.domains"), false},
		{house.Generated("domains"), true},
		{house.Sinkhole("domains"), false},
	} {
		got, err := LoadTokens(filepath.Join(policyDir, f.name), "domains")
		if err != nil {
			return nil, nil, err
		}
		if f.feed {
			got = refuseFeed(got)
		}
		houseFinal = keepNew(houseFinal, got, seenHouse, isNever)
	}
	if err := writeFile(out.HouseDNS, dnsLines(houseFinal)); err != nil {
		return nil, nil, err
	}
	if out.HouseVPNDNS == "" {
		return houseFinal, nil, nil
	}
	got, err := LoadTokens(filepath.Join(policyDir, HouseVPNFile), "domains")
	if err != nil {
		return nil, nil, err
	}
	houseVPNFinal = keepNew(nil, refuseFeed(got), seenHouse, isNever)
	if err := writeFile(out.HouseVPNDNS, dnsLines(houseVPNFinal)); err != nil {
		return nil, nil, err
	}
	return houseFinal, houseVPNFinal, nil
}

func compilePrivateDNS(policyDir string, house SegmentPolicy, out Out, dohDomains []string) ([]string, error) {
	if out.HouseDoHDNS == "" && out.HousePrivateDNSNFT == "" {
		return nil, nil
	}
	privateNames, err := LoadTokens(filepath.Join(policyDir, house.File("private_dns.domains")), "domains")
	if err != nil {
		return nil, err
	}
	privateIPs, err := LoadTokens(filepath.Join(policyDir, house.File("private_dns.ips")), "allow_ips")
	if err != nil {
		return nil, err
	}
	endpoints, pins, err := privateDNSEndpoints(privateNames, privateIPs)
	if err != nil {
		return nil, err
	}
	if err := writeFile(out.HouseDoHDNS, dnsLines(dohDomains)+endpoints); err != nil {
		return nil, err
	}
	if err := writeFile(out.HousePrivateDNSNFT, nftElements(pins)); err != nil {
		return nil, err
	}
	return pins, nil
}

func Compile(policyDir string, out Out) (Summary, error) {
	agent := SegmentFor(DenyByDefault)
	feedIPs, localIPs, neverIPTokens, err := collect(policyDir, agent, "ips")
	if err != nil {
		return Summary{}, err
	}
	feedDomains, localDomains, neverDomainsList, err := collect(policyDir, agent, "domains")
	if err != nil {
		return Summary{}, err
	}
	sharedList, err := LoadTokens(filepath.Join(policyDir, SharedParentsFile), "domains")
	if err != nil {
		return Summary{}, err
	}
	shared := SharedParents(sharedList)
	sharedDropped := map[string]struct{}{}
	refuseFeed := func(items []string) []string {
		return dropFeed(items, func(d string) bool { return AtSharedParent(d, shared) }, sharedDropped)
	}
	floor := FeedMinBitsIn(policyDir)
	wideDropped := map[string]struct{}{}
	feedIPs = dropFeed(feedIPs, func(ip string) bool { return widerThan(ip, floor) }, wideDropped)
	// The feed half goes first, as before the split.
	ips := append(feedIPs, localIPs...)
	domains := append(refuseFeed(feedDomains), localDomains...)
	neverNets := make([]netip.Prefix, 0, len(neverIPTokens))
	for _, token := range neverIPTokens {
		p, ok := parsePrefix4(token)
		if ok {
			neverNets = append(neverNets, p)
		}
	}
	neverDomains := set(neverDomainsList)
	// core.hosts and core.hosts.local, which apply installs as one file, also
	// compile to nothing. Their load here makes a header that can never carry
	// a credential stop the apply, with the file and line, before anything
	// installs. It does not stop the broker at its start. Its hosts also
	// shield the domain list (BlocksCoreHost).
	core, err := corepolicy.LoadFiles(filepath.Join(policyDir, "core.hosts"), filepath.Join(policyDir, "core.hosts.local"))
	if err != nil {
		return Summary{}, err
	}

	ipKept := keepNew(nil, ips, map[string]struct{}{}, func(ip string) bool { return IsNeverIP(ip, neverNets) })
	ipFinal := CoalesceIPv4(ipKept)

	domainFinal := keepNew(nil, domains, map[string]struct{}{}, func(d string) bool {
		return IsNeverDomain(d, neverDomains) || BlocksCoreHost(d, core)
	})

	if err := writeFile(out.NFT, nftElements(ipFinal)); err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DNS, dnsLines(domainFinal)); err != nil {
		return Summary{}, err
	}
	// The map is absent until pf fetch writes it for the first time. Until
	// then, all items read as local.
	feeds := map[string]string{}
	if raw, err := os.ReadFile(filepath.Join(policyDir, "generated", "feeds.map")); err == nil {
		feeds = ParseMap(string(raw))
	}
	if err := writeFile(out.IPMap, mapLines(ipKept, feeds)); err != nil {
		return Summary{}, err
	}

	// doh.ips and doh.domains ship, and each upgrade replaces them. The
	// operator adds resolvers in doh.ips.local and doh.domains.local.
	dohIPs, err := loadWithLocal(filepath.Join(policyDir, "doh.ips"), "ips")
	if err != nil {
		return Summary{}, err
	}
	dohIPFinal := CoalesceIPv4(dohIPs)
	dohDomains, err := loadWithLocal(filepath.Join(policyDir, "doh.domains"), "domains")
	if err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DoHNFT, nftElements(dohIPFinal)); err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DoHDNS, dnsLines(dohDomains)); err != nil {
		return Summary{}, err
	}
	var warnings []string
	directFinal, err := compileOperatorIPs(filepath.Join(policyDir, agent.File("direct_ip.allow")), "allow_ips", allowWhat, &warnings, out.DirectIPNFT)
	if err != nil {
		return Summary{}, err
	}
	sshFinal, err := compileOperatorIPs(filepath.Join(policyDir, agent.File("ssh_allow.ips")), "ssh_ips", sshWhat, &warnings, out.SSHAllowNFT)
	if err != nil {
		return Summary{}, err
	}
	// git_push.allow is for the broker and compiles to nothing. Its load here
	// makes a malformed line stop an apply before anything installs.
	gitPush, err := corepolicy.LoadGitPush(filepath.Join(policyDir, "git_push.allow"))
	if err != nil {
		return Summary{}, err
	}
	if err := checkKeyRulesLocal(filepath.Join(policyDir, "key_prefixes.rules.local")); err != nil {
		return Summary{}, err
	}

	house := SegmentFor(AllowByDefault)
	houseFinal, houseVPNFinal, err := compileHouse(policyDir, house, out, refuseFeed)
	if err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DomainMap, mapLines(domainFinal, feeds)+mapLines(houseFinal, feeds)+mapLines(houseVPNFinal, feeds)); err != nil {
		return Summary{}, err
	}

	privateIPFinal, err := compilePrivateDNS(policyDir, house, out, dohDomains)
	if err != nil {
		return Summary{}, err
	}
	// The direct-IP list of the house compiles the same way as the list of the
	// agent. Thus the house gate never reads an address opened for the agents.
	houseDirectFinal, err := compileOperatorIPs(filepath.Join(policyDir, house.File("direct_ip.allow")), "allow_ips", allowWhat, &warnings, out.HouseDirectIPNFT)
	if err != nil {
		return Summary{}, err
	}
	if out.HouseWhatsAppNFT != "" {
		wa, err := LoadTokens(filepath.Join(policyDir, HouseWhatsAppFile), "ips")
		if err != nil {
			return Summary{}, err
		}
		if err := writeFile(out.HouseWhatsAppNFT, nftElements(CoalesceIPv4(wa))); err != nil {
			return Summary{}, err
		}
	}
	return Summary{
		IPs:             len(ipFinal),
		Domains:         len(domainFinal),
		DoHIPs:          len(dohIPFinal),
		DoHDomains:      len(dohDomains),
		HouseDomains:    len(houseFinal),
		HousePrivateDNS: len(privateIPFinal),
		DirectIPs:       len(directFinal),
		HouseDirectIPs:  len(houseDirectFinal),
		SSHAllows:       len(sshFinal),
		GitPushes:       gitPush.Len(),
		Warnings:        warnings,
		SharedParents:   sorted(sharedDropped),
		WidePrefixes:    sorted(wideDropped),
		FeedFloor:       floor,
	}, nil
}
