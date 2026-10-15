package observe

import (
	"cmp"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	// volumeSlots is the window, one minute per slot. An hour is what the
	// operator can keep in mind ("612 MB in the last hour"). It is also
	// long enough that a dump paced to hide under a per-poll number still
	// has to land inside one hour.
	volumeSlots = 60
	// maxVolPairs is the limit on the table. A house with a dozen devices
	// that talk to a few dozen destinations each is well under this. The
	// limit is there so a client that sweeps addresses cannot grow the daemon.
	maxVolPairs = 512
	// volumeEvict is the number of pairs that one eviction drops. A batch
	// prevents a sort of the full table on each new destination, on a box
	// with more talkers than slots.
	volumeEvict = maxVolPairs / 8
	// volumeRefire is the longest a pair stays quiet after an event
	// while it is still over the threshold.
	volumeRefire = time.Hour
	// volumeUnit is what the MB in PF_OBSERVE_VOLUME_MB and in the event
	// detail counts: 2^20, the same MiB the flush cap is written in.
	volumeUnit = 1 << 20
	// maxDstNames bounds the address → name table the events read.
	maxDstNames = 2048
)

// volPair is the outbound byte window of one client towards one
// destination. slots is a ring of one minute per slot, and mins[i] is the
// minute that slots[i] counts. Thus a slot that the window already passed
// reads as stale, and no timer has to clear it.
type volPair struct {
	seg, src, dst string
	slots         [volumeSlots]int64
	mins          [volumeSlots]int64
	// last is the minute of the newest byte counted. The eviction sorts on
	// it.
	last int64
	// fired and over are the debounce: over says that the pair was above
	// the threshold at the last check. fired says when it last reported that.
	fired time.Time
	over  bool
}

func (p *volPair) add(minute, n int64) {
	i := minute % volumeSlots
	if p.mins[i] != minute {
		p.mins[i], p.slots[i] = minute, 0
	}
	p.slots[i] += n
	if minute > p.last {
		p.last = minute
	}
}

// sum totals the slots still inside the window that ends at minute. A slot
// stamped after minute is a clock that went backwards. It counts, because
// a drop would hide bytes that were really sent.
func (p *volPair) sum(minute int64) int64 {
	oldest := minute - volumeSlots + 1
	var total int64
	for i, m := range p.mins {
		if m >= oldest {
			total += p.slots[i]
		}
	}
	return total
}

// trackVolume counts sent bytes from src towards dst and raises one
// volume alert when the total of the hour crosses VolumeMB. It closes a
// gap: a bulk dump to a destination that nothing blocks, a gist, an
// object store behind a name that the allowlist carries. Nothing here
// stops the traffic -- when conntrack counted it, it was already gone.
// Thus it is an alert, not a block.
func (o *Observer) trackVolume(st *State, segment, src, dst string, sent int64) {
	if o.VolumeMB <= 0 || sent <= 0 {
		return
	}
	seg := clientSegment(segment)
	key := seg + "/" + src + ">" + dst
	p := o.vol[key]
	if p == nil {
		if o.vol == nil {
			o.vol = map[string]*volPair{}
		}
		if len(o.vol) >= maxVolPairs {
			o.evictVolume()
		}
		p = &volPair{seg: seg, src: src, dst: dst}
		o.vol[key] = p
	}
	now := o.now()
	minute := now.Unix() / 60
	p.add(minute, sent)
	total := p.sum(minute)
	limit := int64(o.VolumeMB) * volumeUnit
	if total < limit {
		// Under the threshold again. Thus the next crossing is a new event,
		// not the tail of this one.
		p.over = false
		return
	}
	if p.over && now.Sub(p.fired) < volumeRefire {
		return
	}
	p.over, p.fired = true, now
	o.alert(st, Event{
		T: now.UTC(), Segment: seg, Src: src, Dst: o.destLabel(dst),
		Threat: "volume", Detail: fmt.Sprintf("%d MB in 1h", total/volumeUnit),
	})
}

// evictVolume makes room: it drops the least recently active pairs. An
// evicted pair loses its window. A slow upload that goes quiet long enough
// to be among the coldest of the table starts again from zero, and needs
// one more full threshold to alert. That is the cost of a fixed limit. The
// traffic that this signal looks for is, by definition, the traffic that
// keeps its pair warm.
func (o *Observer) evictVolume() {
	for _, k := range coldest(o.vol, func(p *volPair) int64 { return p.last }, volumeEvict) {
		delete(o.vol, k)
	}
}

// coldest names the n keys of table with the oldest last activity, ties
// by key, so an eviction is the same on each run. The tunnel table and
// prune evict the same way. This is why this code is not written twice.
func coldest[V any, T cmp.Ordered](table map[string]V, last func(V) T, n int) []string {
	type kv struct {
		k    string
		last T
	}
	rows := make([]kv, 0, len(table))
	for k, v := range table {
		rows = append(rows, kv{k, last(v)})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].last != rows[j].last {
			return rows[i].last < rows[j].last
		}
		return rows[i].k < rows[j].k
	})
	out := make([]string, 0, min(n, len(rows)))
	for _, r := range rows[:min(n, len(rows))] {
		out = append(out, r.k)
	}
	return out
}

// destLabel names an address by the last name that observe saw resolve to
// it. Thus a volume row reads as a bucket, not as a number that the
// operator must look up. An address that no query answered stands alone.
func (o *Observer) destLabel(ip string) string {
	if n := o.dstNames[ip]; n != "" {
		return n + " (" + ip + ")"
	}
	return ip
}

// noteAnswer remembers which name an address answered for. It is only a
// display aid. Thus it is in memory only, and the full table goes when it
// fills, with no stamp per entry: the addresses worth a name are the
// addresses that a busy client continues to resolve, and they come back
// within a poll or two.
func (o *Observer) noteAnswer(name, answer string) {
	if name == "" || answer == "" {
		return
	}
	a, err := netip.ParseAddr(answer)
	if err != nil || a.IsUnspecified() {
		return
	}
	if o.dstNames == nil {
		o.dstNames = map[string]string{}
	}
	if len(o.dstNames) >= maxDstNames {
		clear(o.dstNames)
	}
	o.dstNames[answer] = strings.ToLower(strings.TrimRight(cleanName(name), "."))
}
