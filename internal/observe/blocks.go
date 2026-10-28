package observe

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/jsonl"
)

const (
	// maxTallyHits bounds the destinations that one flush window keeps for
	// one segment. A block past it still counts in its class. Only its name
	// is not kept. An agent selects the names, so the table must not grow
	// with them. The bound is for each segment, so that the names of one
	// segment never take the place of the names of a different segment.
	// The segments come from the configuration, so their number is small.
	maxTallyHits = 512
	// maxRowHits is the number of destinations in one Blocks row.
	maxRowHits = 20
)

// blockKey is one destination of the tally.
type blockKey struct {
	seg, class, feed, src, dst string
}

// blockTally counts the blocks to listed destinations since the last
// flush, for the Blocks rows of notice (jsonl.BlocksThreat). It is working
// memory, not ledger. Flush writes it with the checkpoints of the logs that
// it counts, so a restart reads again exactly what it did not write.
type blockTally struct {
	counts map[string]map[string]int
	hits   map[blockKey]int
	// segHits is the number of keys in hits for each segment.
	segHits map[string]int
}

func (t *blockTally) add(seg, class, feed, src, dst string, n int) {
	if n <= 0 {
		return
	}
	if t.counts == nil {
		t.counts = map[string]map[string]int{}
		t.hits = map[blockKey]int{}
		t.segHits = map[string]int{}
	}
	if t.counts[seg] == nil {
		t.counts[seg] = map[string]int{}
	}
	t.counts[seg][class] += n
	// A house list block is noise for the digest. It is only a count.
	if class == jsonl.BlockHouse {
		return
	}
	k := blockKey{seg, class, feed, src, dst}
	if _, ok := t.hits[k]; ok {
		t.hits[k] += n
	} else if t.segHits[seg] < maxTallyHits {
		t.hits[k] = n
		t.segHits[seg]++
	}
}

// rows gives one Blocks row for each segment, in name order.
func (t *blockTally) rows(now time.Time) []jsonl.Blocks {
	segs := make([]string, 0, len(t.counts))
	for s := range t.counts {
		segs = append(segs, s)
	}
	sort.Strings(segs)
	out := make([]jsonl.Blocks, 0, len(segs))
	for _, s := range segs {
		row := jsonl.Blocks{T: now.UTC().Format(time.RFC3339Nano), Threat: jsonl.BlocksThreat, Rule: "observe", Where: s, Counts: t.counts[s]}
		for k, n := range t.hits {
			if k.seg == s {
				row.Top = append(row.Top, jsonl.BlockHit{Class: k.class, Feed: k.feed, Src: k.src, Dst: k.dst, N: n})
			}
		}
		sort.Slice(row.Top, func(i, j int) bool {
			a, b := row.Top[i], row.Top[j]
			if a.N != b.N {
				return a.N > b.N
			}
			if a.Dst != b.Dst {
				return a.Dst < b.Dst
			}
			return a.Src < b.Src
		})
		if len(row.Top) > maxRowHits {
			row.Top = row.Top[:maxRowHits]
		}
		out = append(out, row)
	}
	return out
}

// domainLists is the domain map of pf compile, split at
// base.MapHouseMark. feeds is the name → feed table of all names.
// houseLocal has the names that only the house half labels "local"
// (house.domains, the house defaults). houseFeeds has the feed ids that
// only the house half names (the ad, tracker and bypass feeds).
type domainLists struct {
	houseLocal map[string]struct{}
	houseFeeds map[string]struct{}
}

// parseDomainMap reads the domain map as ParseMap does, and also notes
// which half each label comes from. A map from before the mark has no
// house half: then each name reads as a shared one.
func parseDomainMap(text string) (map[string]string, domainLists) {
	feeds := map[string]string{}
	lists := domainLists{houseLocal: map[string]struct{}{}, houseFeeds: map[string]struct{}{}}
	shared := map[string]struct{}{}
	house := false
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == base.MapHouseMark {
			house = true
			continue
		}
		item, feed, ok := strings.Cut(line, "\t")
		item, feed = strings.TrimSpace(item), strings.TrimSpace(feed)
		if !ok || item == "" || feed == "" {
			continue
		}
		if _, dup := feeds[item]; dup {
			continue
		}
		feeds[item] = feed
		switch {
		case !house:
			shared[feed] = struct{}{}
		case feed == "local":
			lists.houseLocal[item] = struct{}{}
		default:
			lists.houseFeeds[feed] = struct{}{}
		}
	}
	for f := range shared {
		delete(lists.houseFeeds, f)
	}
	return feeds, lists
}

// nameClass gives the class and the feed of a blocked name. It walks from
// the name through its parents, as feedForName does. A name in no list is
// BlockOther: a DoH name, or a name that paranoid mode does not allow.
func (o *Observer) nameClass(name string) (class, feed string) {
	for n := name; n != ""; {
		if f, ok := o.domainFeeds[n]; ok {
			if f == "local" {
				if _, h := o.domainLists.houseLocal[n]; h {
					return jsonl.BlockHouse, f
				}
				return jsonl.BlockOperator, f
			}
			if _, h := o.domainLists.houseFeeds[f]; h {
				return jsonl.BlockHouse, f
			}
			return jsonl.BlockSecurity, f
		}
		_, rest, ok := strings.Cut(n, ".")
		if !ok {
			break
		}
		n = rest
	}
	return jsonl.BlockOther, ""
}

// ipClass gives the class and the feed of an address that the blacklist
// set dropped. The IP feeds go to all segments, so a feed is
// BlockSecurity.
func (o *Observer) ipClass(ip string) (class, feed string) {
	f := feedForIP(o.ipFeeds, ip)
	if f == "local" {
		return jsonl.BlockOperator, f
	}
	return jsonl.BlockSecurity, f
}

// flushBlocks appends the Blocks rows of the tally to NoticePath, and
// empties the tally. On a write error, the tally stays for the next flush.
func (o *Observer) flushBlocks() error {
	if len(o.tally.counts) == 0 {
		return nil
	}
	if o.NoticePath == "" {
		o.tally = blockTally{}
		return nil
	}
	var buf []byte
	for _, row := range o.tally.rows(o.now()) {
		raw, err := json.Marshal(row)
		if err != nil {
			continue
		}
		buf = append(append(buf, raw...), '\n')
	}
	if err := appendRows(o.NoticePath, buf); err != nil {
		return err
	}
	o.tally = blockTally{}
	return nil
}
