package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Link is the subset of `ip -j link` that an interface wizard needs. The
// real command prints much more. json.Unmarshal discards unknown fields.
// Thus new fields in a future ip never break this.
type Link struct {
	IfName    string `json:"ifname"`
	LinkType  string `json:"link_type"`
	OperState string `json:"operstate"`
}

// Route is the subset of `ip -j route show default` this needs.
type Route struct {
	Dev string `json:"dev"`
}

// ParseLinks parses `ip -j link` output.
func ParseLinks(raw []byte) ([]Link, error) {
	var links []Link
	if err := json.Unmarshal(raw, &links); err != nil {
		return nil, fmt.Errorf("ip -j link: %w", err)
	}
	return links, nil
}

// ParseRoutes parses `ip -j route show default` output.
func ParseRoutes(raw []byte) ([]Route, error) {
	var routes []Route
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("ip -j route show default: %w", err)
	}
	return routes, nil
}

// Proposal is what the wizard suggests before it asks the operator to
// confirm or override: WAN from the default route (the uplink is
// a role, not a port), Agent as the first candidate that is not
// WAN, and all other physical interfaces as house candidates.
type Proposal struct {
	WAN        string
	Agent      string
	Candidates []string // every non-loopback interface, sorted, WAN and Agent included
}

// Propose is ProposeFor with nothing pinned and every ether interface
// taken as hardware.
func Propose(linkRaw, routeRaw []byte) (Proposal, error) {
	return ProposeFor(linkRaw, routeRaw, "", nil)
}

// ProposeFor is the pure decision that the interactive and -yes paths
// both call: no exec, no stdin, only the two command outputs in and a
// proposal out. Candidates excludes loopback, all that is not link_type
// "ether", and, when hw is given, all that hw says has no hardware
// behind it. docker0, br-*, virbr*, VLAN children, vnet and macvtap all
// report "ether". If the fence gets one of those, the box fences a
// bridge, not a cable. wan is the uplink when the caller pinned one
// (-wan), so the agent proposal is never that same port. An empty wan
// proposes it from the default route.
func ProposeFor(linkRaw, routeRaw []byte, wan string, hw func(string) bool) (Proposal, error) {
	links, err := ParseLinks(linkRaw)
	if err != nil {
		return Proposal{}, err
	}
	routes, err := ParseRoutes(routeRaw)
	if err != nil {
		return Proposal{}, err
	}
	var candidates []string
	for _, l := range links {
		if l.LinkType != "ether" || (hw != nil && !hw(l.IfName)) {
			continue
		}
		candidates = append(candidates, l.IfName)
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return Proposal{}, fmt.Errorf("pf install: no hardware ethernet interface found (ip -j link); a USB-only agent NIC that has not enumerated yet would look like this")
	}
	p := Proposal{Candidates: candidates, WAN: wan}
	if p.WAN == "" && len(routes) > 0 {
		p.WAN = routes[0].Dev
	}
	if p.WAN == "" {
		// No default route yet (the uplink cable is not connected). Guess the
		// other way: the first candidate is WAN, the second is agent. This is
		// still only a proposal. -yes without explicit -wan/-agent refuses below.
		p.WAN = candidates[0]
	}
	for _, c := range candidates {
		if c != p.WAN {
			p.Agent = c
			break
		}
	}
	return p, nil
}

// SysfsHardware is the hardware test of the wizard against sysClassNet
// (/sys/class/net). A port has a device link, and is not a bridge, a
// tun/tap, or already enslaved to a bridge or bond (master). The device
// link alone excludes veth, VLAN children, macvlan and most bridges.
// The other three checks find what a driver backs with a device anyway,
// and a physical port that a bridge of a different owner already owns.
func SysfsHardware(sysClassNet string) func(string) bool {
	return func(ifname string) bool {
		if ifname == "" || ifname == "." || ifname == ".." || strings.ContainsRune(ifname, '/') {
			return false
		}
		dir := filepath.Join(sysClassNet, ifname)
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			return false
		}
		for _, virtual := range []string{"bridge", "tun_flags", "master"} {
			if _, err := os.Lstat(filepath.Join(dir, virtual)); err == nil {
				return false
			}
		}
		return true
	}
}

// HouseCandidates is every candidate that is neither wan nor agent, for
// the optional third prompt.
func HouseCandidates(p Proposal, wan, agent string) []string {
	var out []string
	for _, c := range p.Candidates {
		if c != wan && c != agent {
			out = append(out, c)
		}
	}
	return out
}
