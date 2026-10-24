package broker

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"pi-fortress/internal/jsonl"
)

// Nothing else in the fence limits the spend of one slot. The broker
// substitutes for each request that carries a placeholder and counts
// nothing per slot. Thus a prompt-injected agent, or an agent in a loop,
// drains the provider account at line rate. The first sign of it is the
// bill. The budget is that missing limit. It is a sliding hour per slot
// of substituted requests and of request-body bytes that reached the
// origin. One threshold tells the operator, and one threshold
// quarantines the slot.
//
// The window is in the memory of the broker and starts empty after a
// restart. That is a deliberate trade, not only the cheap one. These
// counters are a rate, and a rate reloaded from disk across an outage is
// a rate that nobody measured. A restart is rare and the operator causes
// it. Thus the hour that it forgets is an hour when the operator was
// present. The cost: a broker that restarts under load never accumulates
// an hour. The units screen already reports that condition.
//
// Memory is fixed per slot: sixty minute buckets, never a timestamp per
// request. Thus no volume of agent traffic can grow the heap of the
// broker. The store bounds the set of slots, because the fence
// substitutes only for a slot that it found there.

const budgetBuckets = 60

// The four thresholds, in the order slotWindow.said indexes them.
const (
	kindWarnRequests = iota
	kindStopRequests
	kindWarnUpload
	kindStopUpload
	kindCount
)

const (
	whereRequests = "requests"
	whereUpload   = "upload_bytes"
)

// SlotBudget is the hourly ceiling of one slot, in substituted requests
// and in uploaded body bytes. A threshold of zero is off. Stop is off by
// default. A hard stop on a false positive kills a session that works,
// so the operator must opt in (vm/pi/net.env).
type SlotBudget struct {
	WarnRequests int64
	StopRequests int64
	WarnBytes    int64
	StopBytes    int64
}

// The count does not depend on an armed threshold. The hour is also a
// read-out: the column on the Secrets screen, and the BUDGET verb. An
// operator can disable the alerts so that the alerts do not wake them.
// That operator must not lose, because of this, the number that would
// tell the operator why the alerts woke them. The cost is a mutex and sixty
// additions per request, against a TLS handshake.

func (s SlotBudget) limit(kind int) int64 {
	switch kind {
	case kindWarnRequests:
		return s.WarnRequests
	case kindStopRequests:
		return s.StopRequests
	case kindWarnUpload:
		return s.WarnBytes
	}
	return s.StopBytes
}

// slotWindow is the hour of one slot. Each bucket records the minute of
// its last write. Thus the code recognizes a bucket that is out of the
// window at its next touch, and no sweep must run.
type slotWindow struct {
	minute [budgetBuckets]int64
	reqs   [budgetBuckets]int64
	bytes  [budgetBuckets]int64
	// said is when each threshold was last reported. Without it, a window
	// that stays above a warn line would post one webhook per request.
	said [kindCount]time.Time
	// quarantined is the number of the stop that removed this slot, or
	// zero. A quarantined slot substitutes nothing. Thus a substitution from
	// a snapshot after that stop can only mean that an operator restored it.
	// A restore into a window that is still over the line would quarantine
	// it again on the next request. Then the operator has no way back.
	// Instead, the broker drops the window for that slot. A request with an
	// older snapshot still charges the slot, for its body or for a late
	// substitution. That charge is part of the hour that caused the stop,
	// and it must not drop it.
	quarantined uint64
}

// budgetHit is one threshold a slot has crossed: what to tell the
// operator and, for a stop, what to quarantine.
type budgetHit struct {
	slot  string
	kind  int
	count int64
	limit int64
}

func (h budgetHit) stop() bool { return h.kind == kindStopRequests || h.kind == kindStopUpload }

func (h budgetHit) where() string {
	if h.kind == kindWarnUpload || h.kind == kindStopUpload {
		return whereUpload
	}
	return whereRequests
}

type budget struct {
	mu    sync.Mutex
	slots map[string]*slotWindow
	// stops counts the stops that landed.
	stops uint64
}

// stopsLanded is the count of stops that landed. A request reads it
// before its snapshot of the slots. Thus a count at or above the number
// of a stop says that the snapshot came after that quarantine.
func (bg *budget) stopsLanded() uint64 {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	return bg.stops
}

// charge adds one request to the hour of a slot. seen is stopsLanded from
// before the snapshot of the request. It returns each threshold that this
// addition crossed. It quarantines nothing itself. The quarantine writes
// a file, and a file write under this lock would stall all other
// requests in the fence.
func (bg *budget) charge(slot string, seen uint64, reqs, bytes int64, lim SlotBudget, now time.Time) []budgetHit {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	w := bg.window(slot)
	if w.quarantined != 0 && seen >= w.quarantined {
		// The only way here is an operator restore; see the field.
		*w = slotWindow{}
	}
	min := now.Unix() / 60
	i := int(min % budgetBuckets)
	if w.minute[i] != min {
		w.minute[i], w.reqs[i], w.bytes[i] = min, 0, 0
	}
	w.reqs[i] += reqs
	w.bytes[i] += bytes
	totReqs, totBytes := w.totals(min)
	var hits []budgetHit
	for kind := range kindCount {
		total := totReqs
		if kind == kindWarnUpload || kind == kindStopUpload {
			total = totBytes
		}
		if w.crossed(kind, total, lim.limit(kind), now) {
			hits = append(hits, budgetHit{slot: slot, kind: kind, count: total, limit: lim.limit(kind)})
		}
	}
	return hits
}

// quarantined records the result of a stop hit. It remembers a
// quarantine that landed. Thus a later substitution of that slot means a
// restore by the operator. It forgets a quarantine that did not land.
// Thus the next request tries again and reports again. If not, the agent
// continues against a limit that nothing enforces.
func (bg *budget) quarantined(h budgetHit, ok bool) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	w := bg.window(h.slot)
	if ok {
		bg.stops++
		w.quarantined = bg.stops
		return
	}
	w.said[h.kind] = time.Time{}
}

// hour is the data that the operator surfaces show: the requests and
// uploaded bytes that each slot spent in the last hour. Slots with an
// empty window are not included.
func (bg *budget) hour(now time.Time) map[string][2]int64 {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	min := now.Unix() / 60
	out := map[string][2]int64{}
	for slot, w := range bg.slots {
		reqs, bytes := w.totals(min)
		if reqs == 0 && bytes == 0 {
			continue
		}
		out[slot] = [2]int64{reqs, bytes}
	}
	return out
}

// window is the slot's ring, created on first use. Callers hold mu.
func (bg *budget) window(slot string) *slotWindow {
	if bg.slots == nil {
		bg.slots = map[string]*slotWindow{}
	}
	w := bg.slots[slot]
	if w == nil {
		w = &slotWindow{}
		bg.slots[slot] = w
	}
	return w
}

// totals sums the buckets still inside the hour ending at min.
func (w *slotWindow) totals(min int64) (reqs, bytes int64) {
	for i := range w.minute {
		if w.minute[i] > min-budgetBuckets && w.minute[i] <= min {
			reqs += w.reqs[i]
			bytes += w.bytes[i]
		}
	}
	return reqs, bytes
}

// crossed reports one threshold. It announces a crossing when the total
// first reaches the line, and then not sooner than one hour later. Thus
// a window that stays above the line costs one alert each hour, not one
// per request. A drop back below the line re-arms it immediately.
func (w *slotWindow) crossed(kind int, total, limit int64, now time.Time) bool {
	if limit <= 0 {
		return false
	}
	if total < limit {
		w.said[kind] = time.Time{}
		return false
	}
	if at := w.said[kind]; !at.IsZero() && now.Sub(at) < time.Hour {
		return false
	}
	w.said[kind] = now
	return true
}

// threatSlotBudget marks the rows that this file writes. Here the fence
// reports a rate. It does not strip or refuse anything. Thus the row has
// its own threat name, and each consumer of strip.jsonl that switches on
// the threat name handles it. internal/alert summarises it.
// internal/observe keeps the name on the event that it makes.
const threatSlotBudget = "slot_budget"

// chargeBudget charges one request against each slot that this call
// substituted and did not charge yet. It runs two times: one time where
// the fence decided, and one time after the origin write. Reason: a
// streamed body substitutes during its copy, so the set of slots is not
// complete until that copy ends.
func (b *Broker) chargeBudget(c *call) {
	fresh := c.spent[c.charged:]
	c.charged = len(c.spent)
	for _, slot := range fresh {
		b.budgetCharge(c, slot, 1, 0)
	}
}

// chargeUpload charges the request body that reached the origin, one
// time, against each slot that the request spent. A body under the
// buffer limit has its exact length in the request. A chunked body
// announces no length, so the copy counts it. A fixed-length body that
// the copy stopped half way counts whole. That is the size that the
// agent asked the fence to send.
func (b *Broker) chargeUpload(c *call) {
	if c.uploadCharged {
		return
	}
	c.uploadCharged = true
	n := c.uploadBytes()
	if n <= 0 {
		return
	}
	for _, slot := range c.spent {
		b.budgetCharge(c, slot, 0, n)
	}
}

func (b *Broker) budgetCharge(c *call, slot string, reqs, bytes int64) {
	for _, h := range b.budget.charge(slot, c.stopsSeen, reqs, bytes, b.Budget, b.now()) {
		b.budgetHit(c, h)
	}
}

// budgetHit tells the operator. For a stop, it also quarantines the slot
// through the sidecar that the x key and the slot.disable verb already
// write. There is one quarantine in this tree on purpose. The refusal
// that the agent then gets, the restore that removes it and the purge
// after it are the ones that already exist. The broker lets the request
// that crossed the line go through. The next request that carries that
// placeholder gets the uniform 503, because the next snapshot does not
// contain the slot.
func (b *Broker) budgetHit(c *call, h budgetHit) {
	rule := "slot_budget_warn"
	if h.stop() {
		rule = "slot_budget_stop"
		err := b.disableSlot(h.slot)
		b.budget.quarantined(h, err == nil)
		if err != nil {
			// Put this in the row, do not discard it. A stop that did not land is
			// the most important item on this list. If not, the operator reads
			// "stop" and thinks that the spend stopped.
			rule = "slot_budget_stop_failed"
		}
	}
	_ = b.Logs.Strip(jsonl.Strip{
		Host:     c.host,
		Where:    h.where(),
		Rule:     rule + ":" + h.slot,
		ClientIP: clientIP(c.p),
		Threat:   threatSlotBudget,
		Slot:     h.slot,
		Count:    h.count,
		Limit:    h.limit,
	})
}

func (b *Broker) disableSlot(slot string) error {
	if b.Store == nil {
		return nil
	}
	return b.Store.Disable(slot)
}

// BudgetHour is the answer of the admin socket for the per-slot hour:
// slot, requests and uploaded bytes, three fields per slot. It sorts by
// slot, so the line is stable for a reader and for a test. It is empty
// when no slot has spent anything.
func (b *Broker) BudgetHour() string {
	h := b.budget.hour(b.now())
	slots := make([]string, 0, len(h))
	for slot := range h {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	var out []string
	for _, slot := range slots {
		out = append(out, slot,
			strconv.FormatInt(h[slot][0], 10),
			strconv.FormatInt(h[slot][1], 10))
	}
	return strings.Join(out, " ")
}
