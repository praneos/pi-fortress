package dnsd

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// A page load is tens of lookups at one time, then a few each second.
	// 20/s is a tenth of the nft flood meter. Thus a source a little under
	// the meter writes a tenth of the lines that it wrote before.
	defaultLogRate  = 20
	defaultLogBurst = 100
	// logSources is the limit of the table. The agent segment is a /24. A
	// table of this size is full only of addresses that no lease gave.
	logSources = 4096
	logSweep   = 10 * time.Second
)

// untracked is the source that a summary names for queries dropped
// because the table was full. Thus a flood of new addresses is counted,
// not logged.
const untracked = "untracked"

// logClass is the budget of a source that pays for the lines of a query.
// Each class has its own bucket. Thus ordinary chatter cannot spend the
// lines that the other two classes are there to keep.
type logClass uint8

const (
	logOrdinary logClass = iota
	// logListed is a name on the local list. Those lines are the sinkhole
	// evidence observe turns into blocked events.
	logListed
	// logCandidate is a query with the shape of a tunnel query
	// (tunnelCandidate): the rows that the tunnel heuristic of observe counts.
	// Without its own bucket, a client could empty the ordinary bucket with
	// short names. Then it could send its payload without a log line.
	logCandidate
	logClasses
)

// candidateLabel is the label length at which a query is a tunnel
// candidate. It is agentTXTLabel of observe, the shortest payload that
// observe reads as a tell. _acme-challenge is 15.
const candidateLabel = 16

// tunnelCandidate reports whether the tunnel heuristic of observe can
// count a query: a roomy type, or a label as long as a payload label.
func tunnelCandidate(name string, t uint16) bool {
	if t == 16 || t == 10 {
		return true
	}
	for l := range strings.SplitSeq(name, ".") {
		if len(l) >= candidateLabel {
			return true
		}
	}
	return false
}

type limitKey struct {
	src   netip.Addr
	class logClass
}

type bucket struct {
	tokens  float64
	last    time.Time
	dropped int
}

// limiter is a token bucket per source over the query log of one segment.
// A token is the lines of one query. The limiter counts what it refuses.
// It writes the count as one summary per source per sweep, never per query.
type limiter struct {
	rate  float64
	burst float64
	max   int
	emit  func(now time.Time, src string, n int, class logClass)

	mu        sync.Mutex
	m         map[limitKey]bucket
	overflow  [logClasses]int
	lastSweep time.Time
}

// newLimiter reports each count as listed or not listed. It reports a
// candidate count as not listed. newClassLimiter tells which class it was.
func newLimiter(rate float64, burst, max int, emit func(time.Time, string, int, bool)) *limiter {
	return newClassLimiter(rate, burst, max, func(now time.Time, src string, n int, c logClass) {
		emit(now, src, n, c == logListed)
	})
}

func newClassLimiter(rate float64, burst, max int, emit func(time.Time, string, int, logClass)) *limiter {
	return &limiter{
		rate:  rate,
		burst: float64(burst),
		max:   max,
		emit:  emit,
		m:     make(map[limitKey]bucket),
	}
}

// take reports whether src may log one query now, from the listed budget
// or the ordinary one.
func (l *limiter) take(now time.Time, src netip.Addr, listed bool) bool {
	c := logOrdinary
	if listed {
		c = logListed
	}
	return l.takeClass(now, src, c)
}

func (l *limiter) takeClass(now time.Time, src netip.Addr, class logClass) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastSweep.IsZero() {
		l.lastSweep = now
	} else if now.Sub(l.lastSweep) >= logSweep {
		l.sweep(now)
	}
	k := limitKey{src: src, class: class}
	b, ok := l.m[k]
	if !ok {
		if len(l.m) >= l.max {
			l.overflow[class]++
			return false
		}
		b = bucket{tokens: l.burst, last: now}
	}
	l.refill(&b, now)
	ok = b.tokens >= 1
	if ok {
		b.tokens--
	} else {
		b.dropped++
	}
	l.m[k] = b
	return ok
}

func (l *limiter) refill(b *bucket, now time.Time) {
	// A clock that steps backwards refills nothing. It does not go negative.
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
}

// sweep writes what each source lost since the last sweep. It forgets
// sources whose bucket is full again. A full bucket with no drops is the
// same as a new entry, so its eviction loses nothing.
func (l *limiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, b := range l.m {
		l.refill(&b, now)
		if b.dropped > 0 {
			l.emit(now, k.src.String(), b.dropped, k.class)
			b.dropped = 0
			l.m[k] = b
		} else if b.tokens >= l.burst {
			delete(l.m, k)
		}
	}
	for i, n := range l.overflow {
		if n > 0 {
			l.emit(now, untracked, n, logClass(i))
			l.overflow[i] = 0
		}
	}
}

// flush is sweep on demand, for a log about to close.
func (l *limiter) flush(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
}

func (l *limiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
