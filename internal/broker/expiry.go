package broker

import (
	"context"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
)

// threatSlotExpiry marks a row about the deadline of a slot
// (docs/fence.md §5.2e): a warning during its last week, and one row when
// the deadline passes. As with slot_budget, nothing was stripped or
// refused. pf alert posts it so that the operator renews before the agent
// gets the refusal mid-session.
const threatSlotExpiry = "slot_expiry"

// expiryWarn is how long before its deadline a slot starts to warn.
// expiryRepeat is how often it warns again until a person renews it.
const (
	expiryWarn   = 7 * 24 * time.Hour
	expiryRepeat = 24 * time.Hour
)

// expiryState is what the watcher already said, in memory. A restart
// forgets it, which costs at most one repeated row per slot. The watcher
// writes an expired row only within expiryRepeat of the deadline. Thus a
// restart long after does not announce old news again.
type expiryState struct {
	warned  map[string]time.Time
	expired map[string]time.Time
}

// WatchExpiry checks the deadline of each slot now, and then at each
// interval until ctx ends.
func (b *Broker) WatchExpiry(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		b.checkExpiry(b.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (b *Broker) checkExpiry(now time.Time) {
	if b.Store == nil || b.Logs == nil {
		return
	}
	snap, err := b.Store.Snapshot()
	if err != nil {
		return
	}
	// A Claude slot is two rows, oat and ort, under one deadline: one
	// warning names both kinds.
	type slotDue struct {
		at    time.Time
		kinds []string
	}
	due := map[string]*slotDue{}
	for _, sl := range snap {
		if sl.Expires.IsZero() {
			continue
		}
		d := due[sl.ID]
		if d == nil {
			d = &slotDue{at: sl.Expires}
			due[sl.ID] = d
		}
		d.kinds = append(d.kinds, sl.Kind)
	}
	st := &b.expiry
	if st.warned == nil {
		st.warned, st.expired = map[string]time.Time{}, map[string]time.Time{}
	}
	for id, d := range due {
		left := d.at.Sub(now)
		rule := ""
		switch {
		case left <= 0:
			if -left >= expiryRepeat || st.expired[id].Equal(d.at) {
				continue
			}
			st.expired[id] = d.at
			rule = "slot_expired"
		case left <= expiryWarn:
			if last, ok := st.warned[id]; ok && now.Sub(last) < expiryRepeat {
				continue
			}
			st.warned[id] = now
			rule = "slot_expiring"
		default:
			// Renewed past the window: the next approach warns again.
			delete(st.warned, id)
			continue
		}
		// Whole days left, rounded up, so the last day reads 1 and not 0. An
		// expired row carries none.
		var days int64
		if left > 0 {
			days = int64((left + 24*time.Hour - 1) / (24 * time.Hour))
		}
		sort.Strings(d.kinds)
		_ = b.Logs.Strip(jsonl.Strip{
			Host:   "-",
			Where:  strings.Join(d.kinds, ","),
			Rule:   rule + ":" + id,
			Threat: threatSlotExpiry,
			Slot:   id,
			Count:  days,
		})
	}
}
