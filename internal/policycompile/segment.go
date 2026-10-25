package policycompile

import "path/filepath"

// Posture is what a policed segment does with a name that none of its lists
// carry. It is the full difference between the two segments. Before it was
// a field, a third segment was a copy of an existing one.
type Posture int

const (
	// DenyByDefault: under PARANOID=1, allow.domains plus the host column of
	// core.hosts is the full reachable set. The block lists then remove names
	// from that set.
	DenyByDefault Posture = iota
	// AllowByDefault: the domain lists are sinkholes. Thus a device can reach
	// all names that nobody named.
	AllowByDefault
)

// ListType is one operator-editable policy file: its name in the policy
// directory, and how LoadTokens and the TUI read its tokens.
type ListType struct {
	Name string
	Kind string
}

// SegmentPolicy is one policed segment. Prefix and Sink are the flat
// naming that keeps the files of the two segments in one directory. The
// plan moves them to one directory for each segment. Thus callers ask for
// a file by its type, not by its name.
type SegmentPolicy struct {
	Name    string
	Prefix  string
	Sink    string
	Posture Posture
}

// Segments is the policed tier, in the order the TUI tabs it.
var Segments = []SegmentPolicy{
	{Name: "agent", Prefix: "", Sink: "blacklist", Posture: DenyByDefault},
	{Name: "house", Prefix: "house_", Sink: "house", Posture: AllowByDefault},
}

// SegmentFor returns the segment that holds a posture. Today there is one
// segment for each posture. A second segment of a posture needs Phase 2 and 3 first.
func SegmentFor(p Posture) SegmentPolicy {
	for _, s := range Segments {
		if s.Posture == p {
			return s
		}
	}
	return SegmentPolicy{}
}

// File names one of the segment's policy files by its type.
func (s SegmentPolicy) File(kind string) string { return s.Prefix + kind }

// Sinkhole names the block list of the segment: the half from the operator.
func (s SegmentPolicy) Sinkhole(kind string) string { return s.Sink + "." + kind }

// HouseVPNFile is the VPN/proxy feed list of the house, relative to the
// policy dir. pf fetch writes it separately from the house sinkhole. Thus
// the house resolver can serve it only while HOUSE_BLOCK_VPN is on.
const HouseVPNFile = "generated/house_vpn.domains"

// HouseWhatsAppFile is Meta's ranges for HOUSE_ALLOW_WHATSAPP, shipped.
const HouseWhatsAppFile = "house_whatsapp.ips"

// Generated names the half of the block list that internal/fetch writes.
func (s SegmentPolicy) Generated(kind string) string {
	return filepath.Join("generated", s.Sinkhole(kind))
}

// Lists are the editable files of the segment. Posture decides the set. An
// allowlist has no effect where all unnamed names already resolve. A
// sinkhole segment takes no IP feed.
func (s SegmentPolicy) Lists() []ListType {
	if s.Posture == AllowByDefault {
		return []ListType{
			{s.Sinkhole("domains"), "domains"},
			{s.File("never_block.domains"), "domains"},
			{s.File("private_dns.domains"), "endpoints"},
			{s.File("private_dns.ips"), "host_ips"},
			{s.File("direct_ip.allow"), "allow_ips"},
		}
	}
	return []ListType{
		{s.Sinkhole("domains"), "domains"},
		{s.Sinkhole("ips"), "ips"},
		{s.File("never_block.domains"), "domains"},
		{s.File("never_block.ips"), "ips"},
		{s.File("direct_ip.allow"), "allow_ips"},
		{s.File("ssh_allow.ips"), "ssh_ips"},
		{s.File("allow.domains"), "domains"},
	}
}

// DNSInputs are the operator lists, relative to the policy dir, that
// decide the compiled DNS block lists of pf dns: the block list and the
// never_block list of each segment, the house defaults and private DNS
// names, the shared parents, core.hosts and the DoH names, each with its
// .local file where compile reads one. generated/ is not here: pf fetch
// writes it. pf nftsets policy flushes the resolved sets when one of these
// files changes, and not when only a feed changes. Keep this list the same
// as what Compile reads for its DNS outputs.
func DNSInputs() []string {
	var out []string
	for _, s := range Segments {
		out = append(out, s.Sinkhole("domains"), s.File("never_block.domains"))
	}
	house := SegmentFor(AllowByDefault)
	return append(out,
		house.File("default.domains"),
		house.File("private_dns.domains"),
		SharedParentsFile,
		"core.hosts", "core.hosts.local",
		"doh.domains", "doh.domains.local")
}
