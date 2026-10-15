package secrets

import (
	"bytes"
	"sort"
	"strings"
)

const phPrefix = "pf_"

// IsPlaceholder reports whether v is one whole placeholder and nothing
// else. A prefix test would also accept a live value that only starts
// with "pf_" as a placeholder.
func IsPlaceholder(v string) bool {
	sp := FindPlaceholderSpans([]byte(v))
	return len(sp) == 1 && sp[0] == [2]int{0, len(v)}
}

// FindPlaceholderSpans returns [start,end) of each placeholder in b. It
// matches pf_<16 hex>_<KIND> with the same boundary rule as the
// regexp: the kind is a maximal run of [A-Z0-9_], and a lowercase
// letter must not follow it. No regexp: one Index for each candidate.
func FindPlaceholderSpans(b []byte) [][2]int {
	var out [][2]int
	pre := []byte(phPrefix)
	for i := 0; i < len(b); {
		j := bytes.Index(b[i:], pre)
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

// TrailingPlaceholders returns the start of the run of placeholders that
// ends exactly at len(b). In the run, each one ends where the next
// begins. It returns len(b) when no placeholder ends there. It finds, in
// one backward pass, what FindPlaceholderSpans would find if repeated on
// shorter and shorter prefixes. A span holds no 'p' past its first byte.
// Thus the only candidate that ends at n is the last pf_ before n, and
// the code never examines the bytes of one candidate again.
func TrailingPlaceholders(b []byte) int {
	pre := []byte(phPrefix)
	n := len(b)
	for {
		s := bytes.LastIndex(b[:n], pre)
		if s < 0 {
			return n
		}
		if e, ok := placeholderEnd(b[:n], s); !ok || e != n {
			return n
		}
		n = s
	}
}

// PlaceholderHold reports how many trailing bytes of b may still belong
// to a placeholder whose end has not arrived: from the earliest pf_
// candidate that b cannot settle, or a partial prefix exactly at the
// end. A streamed scan may emit all bytes before them. What it emits can
// never be the head of a placeholder that the next read completes.
func PlaceholderHold(b []byte) int {
	pre := []byte(phPrefix)
	for i := 0; i < len(b); {
		j := bytes.Index(b[i:], pre)
		if j < 0 {
			break
		}
		s := i + j
		if placeholderOpen(b, s) {
			return len(b) - s
		}
		i = s + 1
	}
	for k := min(len(pre)-1, len(b)); k > 0; k-- {
		if bytes.HasSuffix(b, pre[:k]) {
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
	if !isUpper(b[k]) {
		return false
	}
	e := k + 1
	for e < len(b) && isKind(b[e]) {
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
	if !isUpper(b[k]) {
		return 0, false
	}
	e := k + 1
	for e < len(b) && isKind(b[e]) {
		e++
	}
	if e < len(b) && b[e] >= 'a' && b[e] <= 'z' {
		return 0, false
	}
	return e, true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func isKind(c byte) bool {
	return isUpper(c) || (c >= '0' && c <= '9') || c == '_'
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
