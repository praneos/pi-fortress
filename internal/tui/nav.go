package tui

import (
	"slices"
	"strings"

	"pi-fortress/internal/admin"
)

// The seat is organised by network, because that is how an operator
// thinks about the box: "my home network", "the agents", "the Pi". All
// networks have the same four sections. Thus a difference between two of
// them is real (only the agent network has Keys and extra Activity views,
// because it is the only network whose TLS the Pi reads).
//
//	Overview
//	Agent network   Devices  Filtering  Activity  Settings  Keys
//	Home network    Devices  Filtering  Activity  Settings
//	<Desk>          Devices  Filtering  Activity  Settings   (one per segments.d file)
//	System          Health  Settings  Feeds  Admin log  Actions
type section int

const (
	secOverview section = iota
	secDevices
	secFiltering
	secActivity
	secSettings
	secKeys
	secHealth
	secFeeds
	secAdminLog
	secActions
)

var sectionNames = map[section]string{
	secOverview:  "Overview",
	secDevices:   "Devices",
	secFiltering: "Filtering",
	secActivity:  "Activity",
	secSettings:  "Settings",
	secKeys:      "Keys",
	secHealth:    "Health",
	secFeeds:     "Feeds",
	secAdminLog:  "Admin log",
	secActions:   "Actions",
}

// Network ids. A plain segment's id is its segments.d name.
const (
	netOverview = "overview"
	netAgent    = "agent"
	netHouse    = "house"
	netSystem   = "system"
)

// view is one page: a network and one of its sections. The code keeps the
// cursor, scroll and tab positions for each view. Thus when the operator
// moves away and back, the view returns to where the operator was.
type view struct {
	net string
	sec section
}

type netEntry struct {
	id, label string
	secs      []section
}

var networkSections = []section{secDevices, secFiltering, secActivity, secSettings}

// buildNets is the menu: fixed entries around one entry for each plain
// segment. A segment appears when an operator applies one. Thus the code
// reads it again on each reload, and does not cache it for the life of
// the seat.
func buildNets(plain []admin.Segment) []netEntry {
	out := []netEntry{
		{netOverview, "Overview", []section{secOverview}},
		{netAgent, "Agent network", append(append([]section{}, networkSections...), secKeys)},
		{netHouse, "Home network", networkSections},
	}
	for _, s := range plain {
		out = append(out, netEntry{s.Name, titleCase(s.Name), networkSections})
	}
	return append(out, netEntry{netSystem, "System", []section{secHealth, secSettings, secFeeds, secAdminLog, secActions}})
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// plainNet says the view's network is a segments.d segment.
func (v view) plainNet() bool {
	switch v.net {
	case netOverview, netAgent, netHouse, netSystem:
		return false
	}
	return true
}

// Friendly names for the policy lists, in the order of the admin package.
// The header of the list still shows the file name, for people who edit
// the files by hand.
var listLabels = map[string]string{
	"house.domains":             "Blocked sites",
	"house_never_block.domains": "Never block",
	"house_private_dns.domains": "Private DNS name",
	"house_private_dns.ips":     "Private DNS addresses",
	"house_direct_ip.allow":     "Direct-IP exceptions",
	"blacklist.domains":         "Blocked sites",
	"blacklist.ips":             "Blocked addresses",
	"never_block.domains":       "Never block",
	"never_block.ips":           "Never-block addresses",
	"direct_ip.allow":           "Direct-IP exceptions",
	"ssh_allow.ips":             "SSH destinations",
	"allow.domains":             "Paranoid allowlist",
	admin.DNSTypesList:          "DNS record types",
}

func listLabel(name string) string {
	if l, ok := listLabels[name]; ok {
		return l
	}
	return name
}

// activityTab is one view under Activity: the blocked-events table, or a
// log. Only the agent network has the three views that the Pi learns when
// it reads TLS: new destinations, stripped keys and their alerts.
type activityTab struct {
	name string
	log  admin.LogKind
	// blocked is the events table and chart, not a log.
	blocked bool
	// seg narrows log to the rows of one plain segment.
	seg string
}

func (a *App) activityTabs(v view) []activityTab {
	blocked := activityTab{name: "Blocked", blocked: true}
	switch v.net {
	case netAgent:
		return []activityTab{blocked,
			{name: "DNS log", log: admin.LogAgentDNS},
			{name: "New destinations", log: admin.LogFirstSeen},
			{name: "Keys stripped", log: admin.LogStrips},
			{name: "Alerts", log: admin.LogAlerts}}
	case netHouse:
		return []activityTab{blocked,
			{name: "DNS log", log: admin.LogHouseDNS},
			{name: "Firewall log", log: admin.LogHouseDrops}}
	}
	tabs := []activityTab{blocked}
	for i, n := range a.logTabs() {
		if n == "dns "+v.net {
			tabs = append(tabs, activityTab{name: "DNS log", log: admin.LogKind(i)})
		}
	}
	// There is no TLS to read here. Thus the destinations come from conntrack,
	// and the resolver of the segment names them (internal/observe
	// segdest.go).
	if v.plainNet() {
		tabs = append(tabs, activityTab{name: "New destinations", log: admin.LogFirstSeen, seg: v.net})
	}
	return tabs
}

// filterLists is the lists that the Filtering section of a network shows.
// A plain segment resolves with the lists of the agent network and has no
// lists of its own. Thus it shows those lists, read-only.
func filterLists(v view) []string {
	if v.net == netHouse {
		return admin.HouseLists
	}
	// dns_types.allow belongs to the agent resolver. A plain segment is not
	// address-only, so the list has no meaning there.
	if v.plainNet() {
		return slices.DeleteFunc(slices.Clone(admin.AgentLists), func(n string) bool { return n == admin.DNSTypesList })
	}
	return admin.AgentLists
}

func (v view) readOnlyLists() bool { return v.plainNet() }
