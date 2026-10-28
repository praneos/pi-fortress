package secrets

import (
	"sort"

	"pi-fortress/internal/placeholder"
)

// PlaceholderKey normalises the placeholder at span to the form stored
// in Slot.Dummy: lowercase slot hex, kind as written.
func PlaceholderKey(b []byte, span [2]int) string {
	return Placeholder(placeholder.PlaceholderParts(b, span))
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
		case sl.Live != "" && !placeholder.IsPlaceholder(sl.Live):
			ix.ByLive[sl.Live] = sl
			ix.Lives = append(ix.Lives, sl)
		case sl.Live == "" && (sl.Disabled || sl.Expired) && sl.Stale != "" && !placeholder.IsPlaceholder(sl.Stale):
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
