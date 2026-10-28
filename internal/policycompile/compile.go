// Package policycompile changes the policy files into the artifacts that the
// resolver and nftables load: merged domain and IP lists without the
// never-block sets. pf compile, internal/fetch and internal/admin call it.
package policycompile

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	allowWhat = fmt.Sprintf("a public IPv4 address or range (/%d or narrower, no host bits)", allowMinBits)
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
	// NTPPassNFT receives the coalesced ntp_pass.ips (NTPPassFile): the NTP
	// and NTS servers that a plain segment with NTP=pass can reach. pf
	// render emits the set only when a segment has NTP=pass.
	NTPPassNFT string
	// DomainMap and IPMap receive one "<item>\t<feed>" line for each compiled
	// sinkhole name (agent, then house) and for each blacklist prefix before
	// coalescence. The feed comes from generated/feeds.map. It is "local" when
	// the map does not name the item, or when a list of the operator
	// (blacklist.*, house.domains) has the item. pf observe
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
	NTPPass         int
	GitPushes       int
	// Warnings are the lines of the operator's lists that did not compile:
	// each line that the parser of the list skipped (loadOperator), and each
	// line of a block list that a shield removed (shieldWarnings,
	// ipShieldWarnings). Line prints each one after the counts.
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
	if s.NTPPass > 0 {
		line += fmt.Sprintf(", %d ntp_pass", s.NTPPass)
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
// (direct_ip.allow, house_direct_ip.allow): it accepts nothing wider than /24,
// and it refuses host bits as ParseSSHIPv4 does.
func ParseAllowIPv4(token string) (string, bool) { return parseOpenIPv4(token, allowMinBits) }

// ParseSSHIPv4 parses the token of ssh_allow.ips: /16 or narrower, with a
// prefix written as its network. Before, the code masked 140.82.114.4/20 to
// 140.82.112.0/20 without a warning. This opened a /20 for an operator who
// possibly meant the one host.
func ParseSSHIPv4(token string) (string, bool) { return parseOpenIPv4(token, sshMinBits) }

// parseOpenIPv4 is parseIPv4 for a list that opens something. It refuses a
// prefix with host bits. It does not mask it into a range wider than the
// operator possibly meant. loadOperatorIPs gives the network in the warning.
func parseOpenIPv4(token string, min int) (string, bool) {
	if p, err := netip.ParsePrefix(strings.TrimSpace(token)); err == nil && p.Masked() != p {
		return "", false
	}
	return parseIPv4(token, min)
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

// ParseDomain gives the name that a list line blocks or shields. A dnsmasq
// line and a suffix match cover the name and all names below it. Thus
// "*.example.com" and ".example.com" are the same as "example.com". Only one
// "*." or one dot goes.
func ParseDomain(token string) (string, bool) {
	name := domainForm(token)
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

// ParseName is ParseDomain for a list of the house. The house blocks names
// only: it has no IP drop. As a name, an address there matched no query
// and blocked nothing. Thus ParseName refuses an IPv4 address.
func ParseName(token string) (string, bool) {
	name, ok := ParseDomain(token)
	if _, err := netip.ParseAddr(name); !ok || err == nil {
		return "", false
	}
	return name, true
}

// domainForm is the name of token that ParseDomain checks: lower case, with
// no dot at the end, and with one "*." or one dot at the start removed.
func domainForm(token string) string {
	name := strings.ToLower(strings.TrimSpace(token))
	name = strings.TrimRight(name, ".")
	if strings.HasPrefix(name, "*.") {
		return name[2:]
	}
	return strings.TrimPrefix(name, ".")
}

// DomainProblem says why ParseDomain refuses token, or it gives "".
func DomainProblem(token string) string {
	if _, ok := ParseDomain(token); ok {
		return ""
	}
	name := domainForm(token)
	switch {
	case !corepolicy.IsASCII(name):
		return corepolicy.ASCIIHint(strings.TrimSpace(token))
	case len(name) > 253:
		return "the name is over 253 bytes"
	case !strings.Contains(name, "."):
		return "a name needs two labels or more"
	}
	for label := range strings.SplitSeq(name, ".") {
		switch {
		case label == "":
			return "the name has an empty label (two dots)"
		case len(label) > 63:
			return "a label is over 63 bytes"
		case strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "":
			return "a label has a character that is not a-z, 0-9 or a hyphen"
		case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
			return "a label starts or ends with a hyphen"
		}
	}
	return "it is not a name"
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

// shieldWarnings gives one warning for each line of the operator's block
// list (local) that never_block.domains or core.hosts removes. The shield
// is a suffix match (IsNeverDomain). Thus a line for www.example.com goes
// when never_block has example.com. The operator wrote that line to block
// the name, so the compiler tells why it did not. A feed entry that a
// shield removes gets no warning: the shield is there for the feeds.
func shieldWarnings(seg SegmentPolicy, local []string, never map[string]struct{}, core *corepolicy.Policy) []string {
	var warn []string
	seen := map[string]struct{}{}
	for _, d := range local {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		var why string
		switch {
		case IsNeverDomain(d, never):
			why = seg.File("never_block.domains") + " shields it (the name or a parent of it is there)"
		case BlocksCoreHost(d, core):
			why = `core.hosts shields it (a credential host there is the name, is below it, or is under a "*." line that covers it)`
		default:
			continue
		}
		warn = append(warn, fmt.Sprintf("%s: %q is not blocked: %s", seg.Sinkhole("domains"), d, why))
	}
	return warn
}

// addrNets gives each IPv4 address in names as a /32. never_block.domains
// and core.hosts accept "192.0.2.1": four labels of digits obey the grammar
// of a name. The compiler blocks such an item as an address (splitAddrs).
// Thus these two shields must also apply to the IP half.
func addrNets(names iter.Seq[string]) []netip.Prefix {
	var out []netip.Prefix
	for name := range names {
		if a, err := netip.ParseAddr(name); err == nil && a.Is4() {
			out = append(out, netip.PrefixFrom(a, 32))
		}
	}
	return out
}

// ipShields are the shields of the IP half: never_block.ips, and the
// addresses of never_block.domains and core.hosts. Each one removes an
// entry that overlaps it.
type ipShields struct {
	ips, domains, core []netip.Prefix
}

// why gives the reason that a shield removes item, or "".
func (s ipShields) why(seg SegmentPolicy, item string) string {
	switch {
	case IsNeverIP(item, s.ips):
		return seg.File("never_block.ips") + " shields it (an address or range there overlaps it)"
	case IsNeverIP(item, s.domains):
		return seg.File("never_block.domains") + " shields it (an address there is in it)"
	case IsNeverIP(item, s.core):
		return "core.hosts shields it (a credential host there is an address in it)"
	}
	return ""
}

// ipShieldWarnings is shieldWarnings for the lines of the IP half that the
// operator wrote in file.
func ipShieldWarnings(seg SegmentPolicy, file string, local []string, s ipShields) []string {
	var warn []string
	for _, item := range local {
		if why := s.why(seg, item); why != "" {
			warn = append(warn, fmt.Sprintf("%s: %q is not blocked: %s", file, item, why))
		}
	}
	return warn
}

// asciiWarnings gives one warning for each line that is not ASCII in a
// domain list that the operator edits: the lists of each segment and
// doh.domains.local. LoadTokens skips such a line, because a query, an SNI
// and a feed carry the xn-- form. The warning gives that form. A feed line
// that is not ASCII gets no warning: it is feed noise.
func asciiWarnings(policyDir string) ([]string, error) {
	files := []string{"doh.domains.local"}
	for _, seg := range Segments {
		for _, l := range seg.Lists() {
			if IsNameKind(l.Kind) {
				files = append(files, l.Name)
			}
		}
	}
	var warn []string
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(policyDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if token := base.StripLine(line); !corepolicy.IsASCII(token) {
				warn = append(warn, fmt.Sprintf("%s line %d: %q is skipped (%s)", name, i+1, token, corepolicy.ASCIIHint(token)))
			}
		}
	}
	return warn, nil
}

// allowWarnings gives one warning for each "*.name" line of allow.domains.
// The line allows name and all names below it (corepolicy.AllowEntry),
// the same as the line "name". The warning tells the operator to write
// that. It also gives one warning for each one-label line ("com",
// "*.com"), for each line with an empty label or over the DNS length
// limits (corepolicy.AllowProblem), and for each other line that allows
// nothing ("*.*.name"). It reads the line as LoadDomains does:
// the first token before a "#". The block lists need no "*." warning:
// ParseDomain reads "*.name" there as "name", and a sinkhole line also
// covers the names below it.
func allowWarnings(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var warn []string
	for i, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		bits := strings.Fields(line)
		if len(bits) == 0 {
			continue
		}
		name, star, oneLabel := corepolicy.AllowEntry(bits[0])
		switch {
		case oneLabel:
			warn = append(warn, fmt.Sprintf("%s line %d: %q is one label; it would allow every name below it; write the full name", filepath.Base(path), i+1, bits[0]))
		case star && name != "":
			warn = append(warn, fmt.Sprintf("%s line %d: %q means %s and every name below it; write %s", filepath.Base(path), i+1, bits[0], name, name))
		case name == "" && corepolicy.AllowProblem(bits[0]) != "":
			warn = append(warn, fmt.Sprintf("%s line %d: %q allows nothing (%s)", filepath.Base(path), i+1, bits[0], corepolicy.AllowProblem(bits[0])))
		case name == "" && corepolicy.IsASCII(bits[0]):
			warn = append(warn, fmt.Sprintf("%s line %d: %q allows no name; skipped", filepath.Base(path), i+1, bits[0]))
		}
	}
	return warn, nil
}

// parseBlockDomain parses a line of a domain block list. ParseDomain
// accepts "192.0.2.1": four labels of digits obey the grammar of a name. As
// a name, the address got only a sinkhole line, and no nft drop. Thus an
// IPv4 address or range there gets the rule of an "ips" list (ParseIPv4),
// and splitAddrs sends it to the IP half.
func parseBlockDomain(token string) (string, bool) {
	if name, ok := ParseDomain(token); ok {
		if _, err := netip.ParseAddr(name); err != nil {
			return name, true
		}
		token = name
	}
	return ParseIPv4(token)
}

// splitAddrs takes the IPv4 addresses and ranges out of the items of a
// domain block list (parseBlockDomain).
func splitAddrs(items []string) (names, addrs []string) {
	for _, item := range items {
		if _, ok := parsePrefix4(item); ok {
			addrs = append(addrs, item)
		} else {
			names = append(names, item)
		}
	}
	return names, addrs
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
// one time. A skipped line of the local file gives a warning.
func loadWithLocal(path, kind string, warn *[]string) ([]string, error) {
	shipped, err := LoadTokens(path, kind)
	if err != nil {
		return nil, err
	}
	local, err := loadOperator(path+".local", kind, warn)
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

// kindWhat tells what a line of each kind must be, and kindMin gives the
// widest prefix that the kind accepts. The warning for a skipped line of
// the operator uses them.
var (
	kindWhat = map[string]string{
		"ips":           fmt.Sprintf("a public IPv4 address or range (/%d or narrower)", minBits),
		"block_domains": fmt.Sprintf("a name or a public IPv4 address or range (/%d or narrower)", minBits),
		"allow_ips":     allowWhat,
		"ssh_ips":       sshWhat,
		"host_ips":      "a public IPv4 address",
		"domains":       "a domain name",
		"names":         "a domain name (the house blocks names only, not addresses)",
		"endpoints":     "a resolver endpoint (<profile>.dns.<provider>.<tld>)",
	}
	kindMin = map[string]int{"ips": minBits, "block_domains": minBits, "allow_ips": allowMinBits, "ssh_ips": sshMinBits, "host_ips": 32}
)

// skipHint tells why a token that is an IPv4 address or range, or that
// looks like a name, is not a line of the kind.
func skipHint(token, kind string) string {
	p, ok := parsePrefix4(token)
	if !ok {
		if name, isName := ParseDomain(token); isName {
			p, ok = parsePrefix4(name)
		}
	}
	min, ipKind := kindMin[kind]
	switch {
	case !ok && ipKind && kind != "block_domains":
		return " (a name is not accepted: list the host's address)"
	case !ok:
		if why := DomainProblem(token); why != "" {
			return " (" + why + ")"
		}
		return ""
	case !ipKind && p.Bits() == 32:
		return " (an address is not a name)"
	case !ipKind:
		return " (an address range is not a name)"
	}
	if q, err := netip.ParsePrefix(token); err == nil && q.Masked() != q && (kind == "allow_ips" || kind == "ssh_ips") {
		return fmt.Sprintf(" (it carries host bits: write the network, %s, or the one address)", q.Masked())
	}
	if p.Bits() < min {
		return fmt.Sprintf(" (it is wider than /%d)", min)
	}
	return " (it is in private or reserved space)"
}

// loadOperator is LoadTokens for a list that the operator keeps by hand. In
// such a list, a skipped line is a mistake to report, not feed noise.
// Before, a hostname in ssh_allow.ips disappeared without a warning. The
// operator who wrote github.com there got nothing and no reason. A line
// that is not ASCII gets its warning from asciiWarnings.
//
// It gives a warning, not an error. A file that already holds a name
// compiled without errors before. If the compiler refused it now, pf apply
// would stop on a Pi that worked, for a line that never did anything.
func loadOperator(path, kind string, warn *[]string) ([]string, error) {
	out, bad, err := loadTokens(path, kind)
	*warn = append(*warn, skipWarnings(path, kind, bad)...)
	return out, err
}

// skipWarnings gives one warning for each line of path that loadTokens
// skipped.
func skipWarnings(path, kind string, bad []badLine) []string {
	var warn []string
	for _, b := range bad {
		if IsNameKind(kind) && !corepolicy.IsASCII(b.token) {
			continue
		}
		warn = append(warn, fmt.Sprintf("%s line %d: %q is not %s; skipped%s",
			filepath.Base(path), b.n, b.token, kindWhat[kind], skipHint(b.token, kind)))
	}
	return warn
}

// ParseToken parses one line of a list of the kind (ListType.Kind). It is
// the one rule for a line: pf compile reads each list with it, and the
// seat (internal/admin) adds a value with it. Thus a value that the seat
// adds compiles, and a line that compiles can be added at the seat.
func ParseToken(kind, token string) (string, bool) {
	switch kind {
	case "ips":
		return ParseIPv4(token)
	case "allow_ips":
		return ParseAllowIPv4(token)
	case "ssh_ips":
		return ParseSSHIPv4(token)
	case "host_ips":
		return ParseHostIPv4(token)
	case "endpoints":
		return ParseEndpoint(token)
	case "block_domains":
		return parseBlockDomain(token)
	case "names":
		return ParseName(token)
	case "allow":
		// allow.domains: corepolicy.LoadDomains reads it, and allowWarnings
		// tells why a line allows nothing.
		name, _, _ := corepolicy.AllowEntry(token)
		return name, name != ""
	}
	return ParseDomain(token)
}

// TokenProblem says why ParseToken refuses token for the kind, in the words
// of the warning of pf compile. The seat gives it with its refusal.
func TokenProblem(kind, token string) string {
	if kind != "allow" {
		return "it is not " + kindWhat[kind] + skipHint(token, kind)
	}
	_, _, oneLabel := corepolicy.AllowEntry(token)
	switch {
	case oneLabel:
		return "it is one label; it would allow every name below it"
	case corepolicy.AllowProblem(token) != "":
		return corepolicy.AllowProblem(token)
	}
	return "it allows no name"
}

// IsNameKind says if a list of the kind holds names, not addresses. A name
// that is not ASCII gets its own warning there (asciiWarnings).
func IsNameKind(kind string) bool {
	return kind != "ips" && !strings.HasSuffix(kind, "_ips")
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
		token := base.StripLine(line)
		if token == "" {
			continue
		}
		if parsed, ok := ParseToken(kind, token); ok {
			out = append(out, parsed)
		} else {
			bad = append(bad, badLine{n: n, token: token})
		}
	}
	return out, bad, nil
}

// collect loads the block list of a segment in two halves: feed, which pf
// fetch writes, and local, which the operator writes. An address or range
// on a domain block list is an item of the list (parseBlockDomain).
func collect(policyDir string, seg SegmentPolicy, kind string, warn *[]string) (feed, local, never []string, err error) {
	never, err = loadOperator(filepath.Join(policyDir, seg.File("never_block."+kind)), kind, warn)
	if err != nil {
		return nil, nil, nil, err
	}
	block := kind
	if kind == "domains" {
		block = "block_domains"
	}
	feed, err = LoadTokens(filepath.Join(policyDir, seg.Generated(kind)), block)
	if err != nil {
		return nil, nil, nil, err
	}
	local, err = loadOperator(filepath.Join(policyDir, seg.Sinkhole(kind)), block, warn)
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
// privateRangeErr is the error for a range in house_private_dns.ips.
const privateRangeErr = "house_private_dns.ips: %s is a range; list the endpoint's own addresses, one per line (a provider's range also holds its public resolvers)"

func privateDNSEndpoints(names, ips []string) (string, []string, error) {
	var pins []string
	for _, ip := range ips {
		addr, bits, ok := strings.Cut(ip, "/")
		if ok && bits != "32" {
			return "", nil, fmt.Errorf(privateRangeErr, ip)
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

// MapHouseMark is the line in the DomainMap between the names that all
// segments get (blacklist.domains and its feeds) and the names of the
// house lists only. The line has no tab, so ParseMap skips it. pf observe
// reads it to tell a house feed or house.domains from a shared feed or
// blacklist.domains, because both halves label an operator entry "local".
const MapHouseMark = "# house"

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

// mapLines gives one "<item>\t<feed>" line for each item. An item in local
// (the operator half of the list) is "local", also when a feed lists it
// too: the operator line is the reason for the block.
func mapLines(items []string, feeds map[string]string, local map[string]struct{}) string {
	var b strings.Builder
	for _, item := range items {
		feed := feeds[item]
		if _, ok := local[item]; ok || feed == "" {
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
func compileOperatorIPs(src, kind string, warn *[]string, path string) ([]string, error) {
	ips, err := loadOperator(src, kind, warn)
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
// as written. houseLocal is the set of house.domains, for the domain map.
// A skipped or shielded line of the operator gives a warning.
func compileHouse(policyDir string, house SegmentPolicy, out Out, refuseFeed func([]string) []string, warn *[]string) (houseFinal, houseVPNFinal []string, houseLocal map[string]struct{}, err error) {
	if out.HouseDNS == "" {
		return nil, nil, nil, nil
	}
	// The shared never_block keeps registries and Google APIs reachable for
	// agents. On the house side, it would protect ad hosts under google.com.
	// The house list obeys only its own file.
	houseNeverList, err := loadOperator(filepath.Join(policyDir, house.File("never_block.domains")), "names", warn)
	if err != nil {
		return nil, nil, nil, err
	}
	houseNever := set(houseNeverList)
	isNever := func(d string) bool { return IsNeverDomain(d, houseNever) }
	seenHouse := map[string]struct{}{}
	// The defaults go first. Thus the head of the compiled file is the shipped
	// baseline, and the volatile feed is in the middle of each diff.
	for _, f := range []struct {
		name  string
		feed  bool
		local bool
	}{
		{house.File("default.domains"), false, false},
		{house.Generated("domains"), true, false},
		{house.Sinkhole("domains"), false, true},
	} {
		load := LoadTokens
		if f.local {
			load = func(path, kind string) ([]string, error) { return loadOperator(path, kind, warn) }
		}
		got, err := load(filepath.Join(policyDir, f.name), "names")
		if err != nil {
			return nil, nil, nil, err
		}
		if f.feed {
			got = refuseFeed(got)
		}
		if f.local {
			houseLocal = set(got)
			*warn = append(*warn, shieldWarnings(house, got, houseNever, nil)...)
		}
		houseFinal = keepNew(houseFinal, got, seenHouse, isNever)
	}
	if err := writeFile(out.HouseDNS, dnsLines(houseFinal)); err != nil {
		return nil, nil, nil, err
	}
	if out.HouseVPNDNS == "" {
		return houseFinal, nil, houseLocal, nil
	}
	got, err := LoadTokens(filepath.Join(policyDir, HouseVPNFile), "names")
	if err != nil {
		return nil, nil, nil, err
	}
	houseVPNFinal = keepNew(nil, refuseFeed(got), seenHouse, isNever)
	if err := writeFile(out.HouseVPNDNS, dnsLines(houseVPNFinal)); err != nil {
		return nil, nil, nil, err
	}
	return houseFinal, houseVPNFinal, houseLocal, nil
}

func compilePrivateDNS(policyDir string, house SegmentPolicy, out Out, dohDomains []string, warn *[]string) ([]string, error) {
	if out.HouseDoHDNS == "" && out.HousePrivateDNSNFT == "" {
		return nil, nil
	}
	// The kind is domains, not endpoints: privateDNSEndpoints stops the
	// compile on a name that is not an endpoint, with the reason.
	privateNames, err := loadOperator(filepath.Join(policyDir, house.File("private_dns.domains")), "domains", warn)
	if err != nil {
		return nil, err
	}
	// The kind is host_ips, as in Lists. That parser refuses a range, and
	// loadTokens skips a refused line. Thus a line that is a range stops the
	// compile here, with or without host bits, and at any width. The file
	// pins exact addresses: a skip would hide the mistake. Each other
	// skipped line gives a warning.
	ipsPath := filepath.Join(policyDir, house.File("private_dns.ips"))
	privateIPs, bad, err := loadTokens(ipsPath, "host_ips")
	if err != nil {
		return nil, err
	}
	for _, b := range bad {
		if p, ok := parsePrefix4(b.token); ok && p.Bits() < 32 {
			return nil, fmt.Errorf(privateRangeErr, b.token)
		}
	}
	*warn = append(*warn, skipWarnings(ipsPath, "host_ips", bad)...)
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
	var skipped []string
	feedIPs, localIPs, neverIPTokens, err := collect(policyDir, agent, "ips", &skipped)
	if err != nil {
		return Summary{}, err
	}
	feedDomains, localDomains, neverDomainsList, err := collect(policyDir, agent, "domains", &skipped)
	if err != nil {
		return Summary{}, err
	}
	// An address on a domain list blocks as an address. It keeps its half:
	// the IP map labels a feed address with its feed and an operator line
	// "local". never_block.ips, never_block.domains and core.hosts shield it
	// (ipShields).
	feedDomains, feedAddrs := splitAddrs(feedDomains)
	localDomains, localAddrs := splitAddrs(localDomains)
	listIPs := localIPs
	feedIPs = append(feedIPs, feedAddrs...)
	localIPs = append(slices.Clip(localIPs), localAddrs...)
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
	// shield the domain list (BlocksCoreHost), and a host that is an address
	// shields the IP half.
	core, err := corepolicy.LoadFiles(filepath.Join(policyDir, "core.hosts"), filepath.Join(policyDir, "core.hosts.local"))
	if err != nil {
		return Summary{}, err
	}
	shields := ipShields{ips: neverNets, domains: addrNets(slices.Values(neverDomainsList)), core: addrNets(maps.Keys(core.Hosts))}

	ipKept := keepNew(nil, ips, map[string]struct{}{}, func(ip string) bool { return shields.why(agent, ip) != "" })
	ipFinal := CoalesceIPv4(ipKept)

	domainFinal := keepNew(nil, domains, map[string]struct{}{}, func(d string) bool {
		return IsNeverDomain(d, neverDomains) || BlocksCoreHost(d, core)
	})
	warnings := append(skipped, shieldWarnings(agent, localDomains, neverDomains, core)...)
	warnings = append(warnings, ipShieldWarnings(agent, agent.Sinkhole("domains"), localAddrs, shields)...)
	warnings = append(warnings, ipShieldWarnings(agent, agent.Sinkhole("ips"), listIPs, shields)...)

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
	if err := writeFile(out.IPMap, mapLines(ipKept, feeds, set(localIPs))); err != nil {
		return Summary{}, err
	}

	// doh.ips and doh.domains ship, and each upgrade replaces them. The
	// operator adds resolvers in doh.ips.local and doh.domains.local.
	dohIPs, err := loadWithLocal(filepath.Join(policyDir, "doh.ips"), "ips", &warnings)
	if err != nil {
		return Summary{}, err
	}
	dohIPFinal := CoalesceIPv4(dohIPs)
	dohDomains, err := loadWithLocal(filepath.Join(policyDir, "doh.domains"), "domains", &warnings)
	if err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DoHNFT, nftElements(dohIPFinal)); err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DoHDNS, dnsLines(dohDomains)); err != nil {
		return Summary{}, err
	}
	directFinal, err := compileOperatorIPs(filepath.Join(policyDir, agent.File("direct_ip.allow")), "allow_ips", &warnings, out.DirectIPNFT)
	if err != nil {
		return Summary{}, err
	}
	sshFinal, err := compileOperatorIPs(filepath.Join(policyDir, agent.File("ssh_allow.ips")), "ssh_ips", &warnings, out.SSHAllowNFT)
	if err != nil {
		return Summary{}, err
	}
	// ntp_pass.ips opens time ports past the gate of an NTP=pass segment.
	// Thus it uses the rule of an allow list: public, /24 or narrower.
	ntpPassFinal, err := compileOperatorIPs(filepath.Join(policyDir, NTPPassFile), "allow_ips", &warnings, out.NTPPassNFT)
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
	houseFinal, houseVPNFinal, houseLocal, err := compileHouse(policyDir, house, out, refuseFeed, &warnings)
	if err != nil {
		return Summary{}, err
	}
	if err := writeFile(out.DomainMap, mapLines(domainFinal, feeds, set(localDomains))+MapHouseMark+"\n"+mapLines(houseFinal, feeds, houseLocal)+mapLines(houseVPNFinal, feeds, nil)); err != nil {
		return Summary{}, err
	}

	privateIPFinal, err := compilePrivateDNS(policyDir, house, out, dohDomains, &warnings)
	if err != nil {
		return Summary{}, err
	}
	// The direct-IP list of the house compiles the same way as the list of the
	// agent. Thus the house gate never reads an address opened for the agents.
	houseDirectFinal, err := compileOperatorIPs(filepath.Join(policyDir, house.File("direct_ip.allow")), "allow_ips", &warnings, out.HouseDirectIPNFT)
	if err != nil {
		return Summary{}, err
	}
	ascii, err := asciiWarnings(policyDir)
	if err != nil {
		return Summary{}, err
	}
	allowWarn, err := allowWarnings(filepath.Join(policyDir, agent.File("allow.domains")))
	if err != nil {
		return Summary{}, err
	}
	warnings = append(append(append(warnings, ascii...), allowWarn...), core.Warnings...)
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
		NTPPass:         len(ntpPassFinal),
		GitPushes:       gitPush.Len(),
		Warnings:        warnings,
		SharedParents:   sorted(sharedDropped),
		WidePrefixes:    sorted(wideDropped),
		FeedFloor:       floor,
	}, nil
}
