package observe

import (
	"fmt"
	"strings"
	"time"
)

const (
	// tunnelDebounce is how long one (client, domain) pair stays quiet
	// after it reported something. A tunnel runs as long as its operator
	// needs. The operator here needs one message only.
	tunnelDebounce = 10 * time.Minute
	// tunnelMinNames is the minimum that the label-length and TXT rules
	// share. Under twenty queries in a minute, nothing is different from a
	// page load, whatever its shape.
	tunnelMinNames = 20
	// tunnelLabelLen is the average payload label, in characters, that
	// the label rule needs: the longest label to the left of the
	// registrable domain, in any position (payload). Base32 of any useful
	// payload is longer than thirty. A hostname that a person typed is not,
	// and the machine-generated CDN shards that look most similar
	// (r3---sn-abc123.googlevideo.com) are also not.
	tunnelLabelLen = 30
	// tunnelTotalLen is the same rule on the bytes of all labels to the
	// left of the domain. It is for a payload cut into labels just under
	// the limit above: two of 29 are 58. The longest machine names of
	// ordinary traffic there (an ELB's my-lb-1234567890.us-west-2.elb, an
	// EC2 host's ec2-54-12-34-56.us-west-2.compute) stay near forty.
	tunnelTotalLen = 50
	// tunnelTXTPercent is the TXT/NULL share of a window that is a sign
	// by itself. TXT is the largest record that a tunnel can ask for, and
	// ordinary traffic rarely asks for it.
	tunnelTXTPercent = 50
	// agentTXTLabel is the left label that a TXT or NULL question on the
	// agent segment needs to be a sign by itself, the first time. The tools
	// of the agent ask for addresses. A TXT with a sentence in front of the
	// zone is a question to something that answers in TXT (an LLM over DNS
	// does). _acme-challenge is 15. A question cut into short labels counts
	// by its bytes against twice this.
	agentTXTLabel = 16
	// agentLongNames is the number of distinct long-label names in a minute
	// that the agent segment needs, against tunnelMinNames for the house:
	// the agent has no page loads to hide behind.
	agentLongNames = 3
	// maxTunnelDomains bounds the table of open windows.
	maxTunnelDomains = 512
	// tunnelEvict is the number of windows that one eviction drops. It
	// uses batches for the same reason as the volume table.
	tunnelEvict = maxTunnelDomains / 8
	// maxTunnelNames is the limit on the distinct-name set of one window.
	// It is above all the thresholds above. Thus a window that reaches it
	// already said what it had to say, and the count stops there.
	maxTunnelNames = 256
	// maxTunnelSupp bounds the per-client suppression counters.
	maxTunnelSupp = 256
)

// twoLevelSuffixes is an approximation of the public suffix list: the
// second-level suffixes under which the name of the registrant is the
// third label, not the second. The real list is a feed, and this daemon
// reads no feed for it. Thus this is a short table of the suffixes that
// ordinary traffic actually reaches. A suffix that the table misses folds
// all registrants under it into one domain. This makes the counts too
// high, not too low -- the failure is a false alert, never a missed alert.
var twoLevelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.nz": true, "co.za": true, "co.in": true, "net.in": true,
	"co.jp": true, "ne.jp": true, "or.jp": true,
	"com.br": true, "com.cn": true, "com.mx": true, "com.sg": true,
	"com.tr": true, "co.kr": true, "com.hk": true, "com.tw": true,
}

// registrableDomain is the domain that the operator of a tunnel would have
// had to register: the last two labels, or the last three under one of
// the suffixes above. It allocates nothing -- the result is a slice of the
// given name -- because it runs one time per query log row.
func registrableDomain(name string) string {
	name = strings.TrimSuffix(name, ".")
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		// A single label is not a domain anybody registered.
		return ""
	}
	j := strings.LastIndexByte(name[:i], '.')
	if j < 0 {
		return name
	}
	if twoLevelSuffixes[name[j+1:]] {
		k := strings.LastIndexByte(name[:j], '.')
		if k < 0 {
			return name
		}
		return name[k+1:]
	}
	return name[j+1:]
}

// payload measures what a name carries to its zone: the longest label to
// the left of the registrable domain, and the bytes of all of them. Not
// the leftmost label alone, which a.<52>.<52>.evil.example keeps at one
// character. domain is registrableDomain(name), a suffix of it.
func payload(name, domain string) (longest, total int) {
	sub := strings.TrimSuffix(strings.TrimSuffix(name, domain), ".")
	if sub == "" || len(sub) == len(name) {
		return 0, 0
	}
	for l := range strings.SplitSeq(sub, ".") {
		longest = max(longest, len(l))
		total += len(l)
	}
	return longest, total
}

// isTunnelQType says whether a query asked for a record large enough to
// be useful for a tunnel. The resolver writes TXT by name. NULL, the
// other classic carrier, has no name in the message package and comes
// through as its number.
func isTunnelQType(qtype string) bool {
	return qtype == "TXT" || qtype == "NULL" || qtype == "TYPE10"
}

// tunWindow is the minute of one client against one registrable domain.
// The counters reset when the minute changes. fired does not reset,
// because it is the debounce and must outlive the window it was set in.
type tunWindow struct {
	seg, src, domain string
	minute           int64
	names            map[string]struct{}
	labelSum         int
	labelMax         int
	totalSum         int
	totalMax         int
	queries          int
	txt              int
	// long is the number of distinct names whose payload reaches
	// tunnelLabelLen in one label, or tunnelTotalLen in all of them.
	long int
	// last is the newest minute that this window saw. The eviction sorts
	// on it.
	last  int64
	fired time.Time
}

// tunSuppress counts, per client and minute, the queries that the rate
// limiter of the resolver itself answered with nothing. It is not evidence
// of a tunnel, and nothing fires on it. But a client that gets throttled
// while it floods one domain is worth a mention in the same line.
type tunSuppress struct {
	minute int64
	n      int
}

// reset starts the minute of the window again, and keeps the debounce.
func (w *tunWindow) reset(minute int64) {
	w.minute, w.labelSum, w.labelMax, w.queries, w.txt, w.long = minute, 0, 0, 0, 0, 0
	w.totalSum, w.totalMax = 0, 0
	clear(w.names)
}

// trackTunnel folds one query-log row into its (client, domain) minute. It
// raises a dns_tunnel event when the shape of that minute is one of the
// three shapes that a tunnel makes. With the resolver pin and the DoH and
// DoT drops in place, the subdomain labels of a zone that the attacker
// owns are the remaining channel in the default mode. All names resolve,
// so nothing here blocks, and nothing here touches the resolver. It is a
// sign, and the operator decides what it is worth.
//
// The minute is the minute of the row (at), not of the clock. If not, rows
// read again after a restart, or a backlog read late, would all land in
// the minute of the read, and make a tunnel out of the names of an hour.
func (o *Observer) trackTunnel(st *State, segment, name, src, qtype string) {
	o.trackTunnelAt(st, segment, name, src, qtype, o.now())
}

func (o *Observer) trackTunnelAt(st *State, segment, name, src, qtype string, at time.Time) {
	if o.TunnelNames <= 0 || name == "" || src == "" {
		return
	}
	name = strings.ToLower(strings.TrimRight(cleanName(name), "."))
	// Reverse lookups are one name per address by construction. Thus a box
	// that walks a subnet trips the distinct-name rule without being a
	// tunnel. This heuristic does not separate those cases, so .arpa is out
	// of scope, and this line says so here, not in a special case further
	// down.
	if strings.HasSuffix(name, ".arpa") {
		return
	}
	domain := registrableDomain(name)
	if domain == "" {
		return
	}
	seg := clientSegment(segment)
	now := at
	minute := now.Unix() / 60
	w := o.tunnelWindow(seg, src, domain, minute)
	l, total := payload(name, domain)
	tunnelQ := isTunnelQType(qtype)
	w.count(minute, name, l, total, tunnelQ)
	distinct, avg, avgTotal, txtPct := w.stats()
	byTXT := txtPct >= tunnelTXTPercent && w.queries >= tunnelMinNames
	// The agent segment gets two more, because one question at a time
	// never reaches the minimums of the minute above. A plain segment also
	// gets them: the house is the one network of people who browse, and a
	// seat whose host an agent escaped into is the agent at a different address.
	agent := seg != "house"
	agentTXT := agent && tunnelQ && (l >= agentTXTLabel || total >= 2*agentTXTLabel)
	agentLong := agent && w.long >= agentLongNames
	hit := distinct >= o.TunnelNames ||
		(distinct >= tunnelMinNames && (avg >= tunnelLabelLen || avgTotal >= tunnelTotalLen)) ||
		byTXT || agentTXT || agentLong
	if !hit || now.Sub(w.fired) < tunnelDebounce {
		return
	}
	w.fired = now
	detail := fmt.Sprintf("%d names/min, labels avg %d max %d", distinct, avg, w.labelMax)
	// Only when the payload went over more than one label. The label
	// figures alone understate that shape.
	if w.totalMax > w.labelMax {
		detail += fmt.Sprintf(", payload avg %d max %d", avgTotal, w.totalMax)
	}
	if byTXT {
		detail += fmt.Sprintf(", txt %d%%", txtPct)
	}
	if agentTXT {
		detail += fmt.Sprintf(", %s with a %d-character label", qtype, l)
	}
	if n := o.suppressedIn(seg, src, minute); n > 0 {
		detail += fmt.Sprintf(", %d suppressed", n)
	}
	o.alert(st, Event{T: now.UTC(), Segment: seg, Src: src, Dst: domain, Threat: "dns_tunnel", Detail: detail})
}

// tunnelWindow is the window of one client against one domain. It opens
// the window when there is none.
func (o *Observer) tunnelWindow(seg, src, domain string, minute int64) *tunWindow {
	key := seg + "/" + src + "/" + domain
	w := o.tun[key]
	if w == nil {
		if o.tun == nil {
			o.tun = map[string]*tunWindow{}
		}
		if len(o.tun) >= maxTunnelDomains {
			o.evictTunnel()
		}
		w = &tunWindow{seg: seg, src: src, domain: domain, minute: minute, names: map[string]struct{}{}}
		o.tun[key] = w
	}
	return w
}

// count adds one row of minute to the window. l and total are the
// payload of the name.
func (w *tunWindow) count(minute int64, name string, l, total int, tunnelQ bool) {
	// A row older than the minute of the window, from a log read out of
	// order, counts in the window and does not start it again: the failure
	// is then one alert too many, never a missed alert.
	if minute > w.minute {
		w.reset(minute)
	}
	w.last = max(w.last, minute)
	if _, dup := w.names[name]; !dup && len(w.names) < maxTunnelNames {
		w.names[name] = struct{}{}
		// The average of the label lengths is over distinct names, not
		// over queries: one long name asked for a hundred times is a cache
		// miss loop, not a hundred labels of payload.
		w.labelSum += l
		w.labelMax = max(w.labelMax, l)
		w.totalSum += total
		w.totalMax = max(w.totalMax, total)
		if l >= tunnelLabelLen || total >= tunnelTotalLen {
			w.long++
		}
	}
	w.queries++
	if tunnelQ {
		w.txt++
	}
}

// stats is the minute of the window so far: the distinct names, the
// average payload per distinct name, and the TXT share of the queries.
func (w *tunWindow) stats() (distinct, avg, avgTotal, txtPct int) {
	distinct = len(w.names)
	if distinct > 0 {
		avg, avgTotal = w.labelSum/distinct, w.totalSum/distinct
	}
	if w.queries > 0 {
		txtPct = w.txt * 100 / w.queries
	}
	return distinct, avg, avgTotal, txtPct
}

// trackSuppressedAt counts a resolver rate-limit summary against the client
// that it names. The summary carries no name, so it belongs to no domain
// and fires nothing. It only goes into a detail line.
func (o *Observer) trackSuppressedAt(segment, src string, n int, at time.Time) {
	if o.TunnelNames <= 0 || src == "" || n <= 0 {
		return
	}
	key := clientSegment(segment) + "/" + src
	minute := at.Unix() / 60
	if o.tunSupp == nil {
		o.tunSupp = map[string]*tunSuppress{}
	}
	s := o.tunSupp[key]
	if s == nil {
		// Each entry stays for one minute. Thus the full table goes when it
		// fills, without a sort: the loss is one line of context on an
		// event that fires for other reasons anyway.
		if len(o.tunSupp) >= maxTunnelSupp {
			clear(o.tunSupp)
		}
		s = &tunSuppress{}
		o.tunSupp[key] = s
	}
	if s.minute != minute {
		s.minute, s.n = minute, 0
	}
	s.n += n
}

func (o *Observer) suppressedIn(seg, src string, minute int64) int {
	s := o.tunSupp[seg+"/"+src]
	if s == nil || s.minute != minute {
		return 0
	}
	return s.n
}

// evictTunnel drops the least recently active windows. A window that is
// the coldest of five hundred had no query this minute, so it loses only
// a count that had already reset.
func (o *Observer) evictTunnel() {
	for _, k := range coldest(o.tun, func(w *tunWindow) int64 { return w.last }, tunnelEvict) {
		delete(o.tun, k)
	}
}
