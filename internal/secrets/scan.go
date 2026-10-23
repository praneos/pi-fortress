package secrets

import (
	"bytes"
	"sort"
	"strings"
)

const phPrefix = "pf_"

// IsPlaceholder reports whether v is one whole exact placeholder and
// nothing else. A prefix test would also accept a live value that only
// starts with "pf_" as a placeholder.
func IsPlaceholder(v string) bool {
	b := []byte(v)
	sp := FindPlaceholderSpans(b)
	return len(sp) == 1 && sp[0] == [2]int{0, len(v)} && PlaceholderExact(b, sp[0])
}

// FindPlaceholderSpans returns [start,end) of each placeholder in b, in
// any letter case. It matches pf_<16 hex>_<kind>: the prefix in any case,
// and the kind is a letter and then a maximal run of [A-Za-z0-9_]. The
// slot ID is the secret part. An origin can change the case back, or
// remove a letter that the agent added. Thus a span is also each such
// variant of a placeholder. The fence substitutes only an exact span
// (PlaceholderExact). It refuses each other span as it refuses a
// placeholder in a forbidden place. No regexp: one index for each
// candidate.
func FindPlaceholderSpans(b []byte) [][2]int {
	var out [][2]int
	for i := 0; i < len(b); {
		j := indexPrefix(b[i:])
		if j < 0 {
			break
		}
		s := i + j
		if e, ok := placeholderEnd(b, s); ok {
			out = append(out, [2]int{s, e})
			i = e
		} else {
			i = s + 1
		}
	}
	return out
}

// PlaceholderExact reports whether the span is a placeholder as the
// gateway writes it: the prefix "pf_" and a kind of [A-Z0-9_] only. The
// slot hex can be in either case. Only an exact span gets a live value.
func PlaceholderExact(b []byte, span [2]int) bool {
	if string(b[span[0]:span[0]+len(phPrefix)]) != phPrefix {
		return false
	}
	for _, c := range b[span[0]+len(phPrefix)+17 : span[1]] {
		if c >= 'a' && c <= 'z' {
			return false
		}
	}
	return true
}

// TrailingPlaceholders returns the start of the placeholder that ends
// exactly at len(b), or len(b) when no placeholder ends there. Each byte
// of a span is in [A-Za-z0-9_], and the kind run is maximal. Thus a span
// that ends at len(b) is in the last run of such bytes. It is the first
// span in that run, because it takes the run to its end. Two spans are
// never adjacent: a span ends before a byte outside the run, and a span
// starts with p or P.
func TrailingPlaceholders(b []byte) int {
	r := len(b)
	for r > 0 && isWord(b[r-1]) {
		r--
	}
	if sp := FindPlaceholderSpans(b[r:]); len(sp) > 0 && r+sp[0][1] == len(b) {
		return r + sp[0][0]
	}
	return len(b)
}

// PlaceholderHold reports how many trailing bytes of b may still belong
// to a placeholder whose end has not arrived: from the earliest pf_
// candidate (any case) that b cannot settle, or a partial prefix exactly
// at the end. A streamed scan may emit all bytes before them. What it
// emits can never be the head of a placeholder that the next read
// completes.
func PlaceholderHold(b []byte) int {
	for i := 0; i < len(b); {
		j := indexPrefix(b[i:])
		if j < 0 {
			break
		}
		s := i + j
		if placeholderOpen(b, s) {
			return len(b) - s
		}
		i = s + 1
	}
	for k := min(len(phPrefix)-1, len(b)); k > 0; k-- {
		if hasPrefixFold(b[len(b)-k:], phPrefix[:k]) {
			return k
		}
	}
	return 0
}

// placeholderOpen says whether the candidate at s is still undecided:
// each byte so far fits the shape, and b ends before the byte that
// would settle it. placeholderEnd is the closed form of the same rule.
func placeholderOpen(b []byte, s int) bool {
	p := s + len(phPrefix)
	for k := 0; k < 17; k++ {
		if p+k >= len(b) {
			return true
		}
		if k < 16 && !isHex(b[p+k]) || k == 16 && b[p+k] != '_' {
			return false
		}
	}
	k := p + 17
	if k >= len(b) {
		return true
	}
	if !isLetter(b[k]) {
		return false
	}
	e := k + 1
	for e < len(b) && isWord(b[e]) {
		e++
	}
	return e == len(b)
}

func placeholderEnd(b []byte, s int) (int, bool) {
	p := s + len(phPrefix)
	if p+18 > len(b) {
		return 0, false
	}
	for k := 0; k < 16; k++ {
		if !isHex(b[p+k]) {
			return 0, false
		}
	}
	if b[p+16] != '_' {
		return 0, false
	}
	k := p + 17
	if !isLetter(b[k]) {
		return 0, false
	}
	e := k + 1
	for e < len(b) && isWord(b[e]) {
		e++
	}
	return e, true
}

// indexPrefix returns the index of the first "pf_" in b, in any letter
// case, or -1.
func indexPrefix(b []byte) int {
	for i := 0; ; {
		j := bytes.IndexByte(b[i:], '_')
		if j < 0 {
			return -1
		}
		u := i + j
		if u >= 2 && hasPrefixFold(b[u-2:u], "pf") {
			return u - 2
		}
		i = u + 1
	}
}

// hasPrefixFold reports whether b starts with the lower-case ASCII
// string p, in any letter case.
func hasPrefixFold(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != p[i] {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func isWord(c byte) bool {
	return isLetter(c) || (c >= '0' && c <= '9') || c == '_'
}

// PlaceholderParts splits the placeholder at span into its slot ID,
// lowercased as the store holds it, and its kind as written.
func PlaceholderParts(b []byte, span [2]int) (slot, kind string) {
	slot = strings.ToLower(string(b[span[0]+len(phPrefix) : span[0]+len(phPrefix)+16]))
	kind = string(b[span[0]+len(phPrefix)+17 : span[1]])
	return slot, kind
}

// PlaceholderKey normalises the placeholder at span to the form stored
// in Slot.Dummy: lowercase slot hex, kind as written.
func PlaceholderKey(b []byte, span [2]int) string {
	return Placeholder(PlaceholderParts(b, span))
}

// Index is a per-request view of a slot snapshot: lookups by dummy and
// by live value, plus the live values as bytes for the scan. Lives also
// lists each disabled or expired slot with its Stale value as Live, for
// the scan to strip. Those entries keep Disabled or Expired set, and
// are in neither map. ByDummy still answers their placeholder with the
// blank Live that refuses it.
type Index struct {
	ByDummy map[string]Slot
	ByLive  map[string]Slot
	Lives   []Slot
}

func NewIndex(slots map[string]Slot) *Index {
	ix := &Index{ByDummy: make(map[string]Slot, len(slots)), ByLive: make(map[string]Slot, len(slots))}
	for _, sl := range slots {
		ix.ByDummy[sl.Dummy] = sl
		switch {
		case sl.Live != "" && !IsPlaceholder(sl.Live):
			ix.ByLive[sl.Live] = sl
			ix.Lives = append(ix.Lives, sl)
		case sl.Live == "" && (sl.Disabled || sl.Expired) && sl.Stale != "" && !IsPlaceholder(sl.Stale):
			st := sl
			st.Live = sl.Stale
			ix.Lives = append(ix.Lives, st)
		}
	}
	// Map order would make each scan over Lives (and the rules and
	// counts built from it) different from run to run. Longest first, then id.
	sort.Slice(ix.Lives, func(i, j int) bool {
		a, b := ix.Lives[i], ix.Lives[j]
		if len(a.Live) != len(b.Live) {
			return len(a.Live) > len(b.Live)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Kind < b.Kind
	})
	return ix
}
