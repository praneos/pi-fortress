package observe

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pi-fortress/internal/base"
)

// Seg is one L2 that this box terminates: the tag that its rows carry, the
// network that its neighbours are in, and the address that the Pi answers
// on there.
//
// It is exported because the screens need the same list as the watch. A
// front end that hardcoded "house" and "agent" showed the clients of a
// plain segment nowhere -- the rows were in the ledger, under a tag that
// nothing on the screen asked for.
type Seg struct{ Name, Net, IP string }

// Segments lists the segments that these files describe, in the order
// that a screen shows them: agent, house when one is configured, then
// segments.d by name. net is net.env with the overlay already applied.
// houseEnv is the candidate paths for house.env. dir is the segments.d directory.
func Segments(net map[string]string, houseEnv []string, dir string) []Seg {
	agent := Seg{Name: "agent", Net: net["AGENT_NET"], IP: net["PI_IP"]}
	if agent.Net == "" {
		agent.Net = "10.77.0.0/24"
	}
	if agent.IP == "" {
		agent.IP = "10.77.0.1"
	}
	segs := []Seg{agent}
	if house := base.LoadEnvFirst(houseEnv); house["HOUSE_IF"] != "" {
		h := Seg{Name: "house", Net: house["HOUSE_NET"], IP: house["HOUSE_IP"]}
		if h.Net == "" {
			h.Net = "10.78.0.0/24"
		}
		if h.IP == "" {
			h.IP = "10.78.0.1"
		}
		segs = append(segs, h)
	}
	return append(segs, PlainSegments(dir)...)
}

// segments lists all segments that the Pi terminates. Two of them read
// their own DNS log. All of them share a broadcast domain with the Pi, so
// a neighbour on any of them can claim an address. A watch that examined
// only agent and house would be silent about exactly the segments that
// nothing else watches either.
func (o *Observer) segments() []Seg {
	return Segments(base.LoadEnvOverlay(o.NetEnvPath, o.NetEnvLocal), o.HouseEnvPath, o.SegmentsDir)
}

// PlainSegments reads dir, one segment per <name>.env. The file name is
// the segment name. IF is not read: nothing here needs the interface that
// an address arrives on, only the network that it belongs to. Attribution
// by network keeps this working on a box where two segments share a VLAN
// parent.
//
// The parse is forgiving on purpose, where pf render is strict. render
// refuses a malformed segments.d and changes nothing. That is correct for
// a box that will install a ruleset. Here, a file that cannot be read is
// one segment that is not watched, and a drop of the full ledger for it
// would be the worse trade. The name is checked nevertheless, because it
// becomes a file path in segDNSLog and segOffset.
func PlainSegments(dir string) []Seg {
	if dir == "" {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".env") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	out := make([]Seg, 0, len(files))
	for _, f := range files {
		name := strings.TrimSuffix(f, ".env")
		if name == "" || strings.ContainsAny(name, `/\.`) {
			continue
		}
		env := base.LoadEnvFirst([]string{filepath.Join(dir, f)})
		s := Seg{Name: name, Net: env["NET"], IP: env["IP"]}
		// pf render requires both. Thus a file without one of them was
		// never applied and names no live segment.
		if s.Net == "" || s.IP == "" {
			continue
		}
		if _, err := netip.ParsePrefix(s.Net); err != nil {
			continue
		}
		if _, err := netip.ParseAddr(s.IP); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

// segmentOf names the segment that an address belongs to. It is not ok
// for an address on no segment of this box -- a WAN neighbour, the
// upstream gateway.
func segmentOf(segs []Seg, ip string) (Seg, bool) {
	for _, s := range segs {
		if InNet(ip, s.Net) {
			return s, true
		}
	}
	return Seg{}, false
}

// segDNSLog and segOffset name the resolver log of a plain segment and the
// checkpoint into it. apply.sh writes them under the same names.
func (o *Observer) segDNSLog(name string) string {
	return filepath.Join(filepath.Dir(o.HouseDNSLog), "dns-"+name+".jsonl")
}

func (o *Observer) segOffset(name string) string {
	return filepath.Join(filepath.Dir(o.HouseOffsetPath), "dns-"+name+".offset")
}
