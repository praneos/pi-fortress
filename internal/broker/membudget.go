package broker

import (
	"sync"
	"sync/atomic"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
)

// defaultMemBudget is the allowance of the full broker for bytes held in
// buffers, summed across all connections. Each per-connection cap is
// correct alone (a 1 MiB request body, a 1 MiB response, a 1 MiB WebSocket
// message, a gzip writer at ~0.8 MiB). But the engine fills 256 slots
// honestly, and their sum is 1.2-1.4 GiB. pf-broker.service runs under
// GOMEMLIMIT=700MiB and MemoryMax=1G. Thus that load made the collector
// thrash. Then the broker went past MemoryMax, and the kernel OOM killer
// stopped it. Restart=always put the broker
// back into the same load. 256 MiB of buffers is at most ~512 MiB of heap
// with the headroom of the collector. This leaves GOMEMLIMIT room for the
// items that are not budgeted: stacks, bufio readers, the 64 KiB head of
// a streamed body (fence.streamHead), gzip readers (40 KiB each, measured) and the fixed copy buffers
// of the streamed paths.
const defaultMemBudget = 256 << 20

// gzipWriterCost is the memory that one compress/flate writer holds at
// BestSpeed, measured at 795 KiB live. Its hash tables are arrays inside
// the compressor, whatever the level. 256 streams that re-encode at the
// same time would be 200 MiB, so the budget counts it like a buffer.
const gzipWriterCost = 800 << 10

// ruleMemBudget is the strip.jsonl rule of a request that the budget
// changed: a body or response streamed instead of buffered, a response
// sent uncompressed, or a request or WebSocket message refused. Where
// tells which. Count tells how many since the last row. Limit is the
// budget.
const ruleMemBudget = "mem_budget"

// memLogEvery rate-limits the mem_budget row per where. The condition is
// process-wide, and it continues as long as the load that caused it. Thus
// one row each second tells the operator all that a thousand rows would.
const memLogEvery = time.Second

// memBudget is a non-blocking weighted semaphore over bytes. Nothing waits
// on it. A caller that cannot get its bytes streams or refuses instead.
// Reason: a request in a queue behind memory that other requests hold is
// how a slow origin causes a stalled fence.
type memBudget struct {
	inUse atomic.Int64
	peak  atomic.Int64

	logMu sync.Mutex
	said  map[string]*memLogState
}

type memLogState struct {
	last   time.Time
	missed int64
}

func (m *memBudget) tryAcquire(n, limit int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := m.inUse.Load()
		if cur+n > limit {
			return false
		}
		if m.inUse.CompareAndSwap(cur, cur+n) {
			for {
				p := m.peak.Load()
				if cur+n <= p || m.peak.CompareAndSwap(p, cur+n) {
					return true
				}
			}
		}
	}
}

func (m *memBudget) release(n int64) {
	if n <= 0 {
		return
	}
	if m.inUse.Add(-n) < 0 {
		panic("broker: memory budget released more than it held")
	}
}

func (b *Broker) memLimit() int64 {
	if b.MemBudget > 0 {
		return b.MemBudget
	}
	return defaultMemBudget
}

// memTake reserves n bytes against the broker budget and adds them to
// *held. The owner of *held releases them with memGive. False takes
// nothing.
func (b *Broker) memTake(held *int64, n int64) bool {
	if !b.mem.tryAcquire(n, b.memLimit()) {
		return false
	}
	*held += max(n, 0)
	return true
}

// memGive releases all of *held and sets it to zero. Thus a second call,
// for example from a deferred cleanup after an early release, does not
// give the bytes two times.
func (b *Broker) memGive(held *int64) {
	b.mem.release(*held)
	*held = 0
}

// MemInUse and MemPeak are the bytes that the budget holds now and the
// most that it has held since start, for any status line that needs them.
func (b *Broker) MemInUse() int64 { return b.mem.inUse.Load() }
func (b *Broker) MemPeak() int64  { return b.mem.peak.Load() }

// logMemBudget writes the mem_budget row, at most one per where per
// memLogEvery. The Count of the next row carries what it skipped. The
// strip cap of a request does not apply to it, the same as for logTooBig:
// the row is about the process, not the request.
func (b *Broker) logMemBudget(ip, host, where string) {
	if b.Logs == nil {
		return
	}
	now := b.now()
	m := &b.mem
	m.logMu.Lock()
	if m.said == nil {
		m.said = map[string]*memLogState{}
	}
	st := m.said[where]
	if st == nil {
		st = &memLogState{}
		m.said[where] = st
	}
	st.missed++
	if !st.last.IsZero() && now.Sub(st.last) < memLogEvery {
		m.logMu.Unlock()
		return
	}
	count := st.missed
	st.last, st.missed = now, 0
	m.logMu.Unlock()
	_ = b.Logs.Strip(jsonl.Strip{Host: host, Where: where, Rule: ruleMemBudget, ClientIP: ip, Count: count, Limit: b.memLimit()})
}

// busyBody is the response that an agent gets when the budget is spent and
// its request could not stream: a 503 that it may retry soon. It is not
// the substitution wall (RefusedBody). RefusedBody hides which of four
// causes fired. This response is for none of them, and it needs a shorter
// Retry-After.
const busyBody = "pi-fortress: busy, retry shortly\n"

func (b *Broker) refuseBusy(c *call) error {
	return b.answer(c.client, c.req, c.expect, func() error {
		resp := &httpwire.Response{Proto: "HTTP/1.1", Status: "503 Service Unavailable", Code: 503, Body: []byte(busyBody)}
		resp.SetInPlace("Content-Type", "text/plain")
		resp.SetInPlace("Retry-After", "5")
		resp.SetInPlace("Connection", "close")
		_, err := resp.WriteTo(c.client)
		return err
	})
}
