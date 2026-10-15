package observe

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/keyshape"
)

const (
	// maxSegDests is the limit on the first-seen destination table of one
	// plain segment. A desk that reaches more distinct (name, port) pairs
	// than this in a month evicts its own coldest pairs. The cost is a
	// second row for a destination that it returns to.
	maxSegDests = 1024
	// segDestEvict is the batch of one eviction. Thus a segment that
	// continues to find new destinations sorts its table one time per
	// batch, not one time per destination.
	segDestEvict = maxSegDests / 8
)

// DestRec is the first time that a plain segment reached one destination.
// The agent has the broker for this, which sees each request. The traffic
// of a plain segment is never terminated, so conntrack and the resolver
// log of the segment are all that the Pi has to say where it went.
type DestRec struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	// Name is the name for which the resolver of the segment last answered
	// with Dst. It is empty when that never occurred: an address reached
	// without a lookup that the Pi saw. On a seat, that is worth a look.
	Name  string `json:"name,omitempty"`
	Dport int    `json:"dport"`
	Proto string `json:"proto"`
}

// plainSegment says whether a row's segment tag is a segments.d one.
// The agent is "" in the ledger and "agent" once clientSegment has run.
func plainSegment(segment string) bool {
	return segment != "" && segment != "agent" && segment != "house"
}

// touchDest records the first contact that a plain segment makes with a
// destination. The key is the name that its resolver gave the address,
// when there is one. Thus a CDN that rotates addresses under one name is
// one row, not one per address. It is called only for a fresh conntrack
// tuple: an open connection seen again on the next poll has nothing new to say.
func (o *Observer) touchDest(st *State, segment, src, dst string, dport int, proto string) {
	name := o.segNames[segment][dst]
	id := dst
	if name != "" {
		id = name
	}
	key := id + ":" + strconv.Itoa(dport) + "/" + proto
	if st.Dests == nil {
		st.Dests = map[string]map[string]*DestRec{}
	}
	tab := st.Dests[segment]
	if tab == nil {
		tab = map[string]*DestRec{}
		st.Dests[segment] = tab
	}
	ts := o.nowISO()
	if rec := tab[key]; rec != nil {
		if ts > rec.LastSeen {
			rec.LastSeen = ts
		}
		return
	}
	if len(tab) >= maxSegDests {
		prune(tab, maxSegDests-segDestEvict, func(r *DestRec) string { return r.LastSeen })
	}
	tab[key] = &DestRec{FirstSeen: ts, LastSeen: ts, Src: src, Dst: dst, Name: name, Dport: dport, Proto: proto}
	ev := map[string]any{"t": ts, "kind": "dest", "segment": segment, "src": src, "dst": dst, "dport": dport, "proto": proto}
	if name != "" {
		ev["name"] = name
	}
	o.appendJSONL(ev)
}

// expireDests drops destinations not reached for clientIdle, and with
// them the table of a removed segment.
func expireDests(st *State, now time.Time) {
	cutoff := now.Add(-clientIdle).UTC().Format(base.ISO)
	for seg, tab := range st.Dests {
		for k, r := range tab {
			if r == nil || r.LastSeen < cutoff {
				delete(tab, k)
			}
		}
		if len(tab) == 0 {
			delete(st.Dests, seg)
		}
	}
}

// noteSegAnswer is noteAnswer for the resolver of one plain segment. It is
// separate from dstNames, so a desk row gets a name only from what the
// desk asked for. An address that the house resolved is not evidence of
// what the desk wanted to reach.
func (o *Observer) noteSegAnswer(segment, name, answer string) {
	if name == "" || answer == "" {
		return
	}
	if o.segNames == nil {
		o.segNames = map[string]map[string]string{}
	}
	m := o.segNames[segment]
	if m == nil || len(m) >= maxDstNames {
		m = map[string]string{}
		o.segNames[segment] = m
	}
	m[answer] = strings.ToLower(strings.TrimRight(cleanName(name), "."))
}

// segKeys is the key-shape check of dnsd (internal/keyshape). It
// runs here on what the resolver of a plain segment answered. apply gives
// that resolver the key rules of the agent, so the resolver refuses such a
// name itself. This check is the backstop for a resolver started without
// them. There, a seat with a compromised host could send a key out in a
// query name, and no row would say so. Here it is an alert, not a
// refusal: the name already went out.
type segKeys struct {
	all      *regexp.Regexp
	prefixes []string
}

func loadSegKeys(path string) (*segKeys, error) {
	tr, err := fence.LoadTokenRules(path)
	if err != nil {
		return nil, err
	}
	heads, _ := keyshape.Heads(tr.Rules)
	return &segKeys{all: tr.All(), prefixes: heads}, nil
}

func (k *segKeys) match(name string) string {
	if k == nil || k.all == nil {
		return ""
	}
	return keyshape.Match(k.all, k.prefixes, name)
}

// zone is what an alert can say about a name that carried a key: the
// last two labels, or nothing when the key goes into those labels.
func (k *segKeys) zone(name string) string {
	tail := keyshape.Tail(strings.TrimSuffix(name, "."))
	if k.match(tail) != "" {
		return ""
	}
	return tail
}

// loadKeyRules reads KeyRulesPath again when its mtime changes. If the
// file does not load, the check stays off and says why one time on
// Stderr. The fence refuses to start without it, so on a live box this is
// a lab or a box in the middle of an apply.
func (o *Observer) loadKeyRules() {
	if o.KeyRulesPath == "" {
		o.segKeys = nil
		return
	}
	fi, err := os.Stat(o.KeyRulesPath)
	if err != nil {
		o.segKeys, o.keyStamp = nil, time.Time{}
		return
	}
	if o.segKeys != nil && fi.ModTime().Equal(o.keyStamp) {
		return
	}
	k, err := loadSegKeys(o.KeyRulesPath)
	if err != nil {
		if msg := err.Error(); msg != o.keyErr && o.Stderr != nil {
			fmt.Fprintf(o.Stderr, "pf observe: key rules: %v; plain segments get no dns_key alert\n", err)
			o.keyErr = msg
		}
		o.segKeys = nil
		return
	}
	o.segKeys, o.keyStamp, o.keyErr = k, fi.ModTime(), ""
}

// checkSegKey runs the key check on one plain-segment row that the
// resolver did not refuse. It returns the name that the ledger can keep:
// the zone in place of a name that carried a key. Thus the state file, the
// first-seen log and the screens do not hold a second copy of it.
func (o *Observer) checkSegKey(st *State, segment string, ev dnslog.Event) string {
	rule := o.segKeys.match(ev.Name)
	if rule == "" {
		return ev.Name
	}
	zone := o.segKeys.zone(ev.Name)
	act := ev.Act
	if act == "" {
		act = "seen"
	}
	o.keyAlert(st, segment, ev.Src, zone, rule, act+", rule "+rule)
	if zone == "" {
		return "(redacted)"
	}
	return zone
}

// DestRows is the first-seen destinations of one plain segment, or of all
// segments for "", oldest first. pf observe and internal/admin print
// them.
func DestRows(st *State, segment string) []DestRow {
	var out []DestRow
	for seg, tab := range st.Dests {
		if segment != "" && seg != segment {
			continue
		}
		for _, r := range tab {
			if r != nil {
				out = append(out, DestRow{Segment: seg, DestRec: *r})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen < out[j].FirstSeen
		}
		return out[i].Segment+out[i].Dst < out[j].Segment+out[j].Dst
	})
	return out
}

// DestRow is one DestRec with the segment it belongs to.
type DestRow struct {
	Segment string
	DestRec
}

// Line is the row as the screens print it. First come the time, the
// segment and the source. Then comes the destination as the client named
// it: the name with the address in brackets, or the address alone.
func (r DestRow) Line() string {
	what := r.Dst
	if r.Name != "" {
		what = r.Name + " (" + r.Dst + ")"
	}
	return fmt.Sprintf("%s %-8s %-15s %s:%d/%s", r.FirstSeen, r.Segment, r.Src, what, r.Dport, r.Proto)
}

func showDests(w io.Writer, st *State) {
	rows := DestRows(st, "")
	fmt.Fprintf(w, "DESTS first-seen, plain segments (%d)\n", len(rows))
	if len(rows) > 40 {
		rows = rows[len(rows)-40:]
	}
	for _, r := range rows {
		fmt.Fprintf(w, "  %s\n", r.Line())
	}
}
