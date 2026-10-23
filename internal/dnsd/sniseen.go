package dnsd

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// sniSeenFor is how long the SNI check accepts an address that a name
	// resolved to on the segment before. A device keeps an answer after
	// its TTL: Apple devices open a connection with an expired answer while
	// they ask again. Its gate element is gone after setTimeout, so the flow
	// goes to the check. A CDN that rotates between ranges gives the check
	// a different answer now. Without this, the flow is reset.
	sniSeenFor = 24 * time.Hour
	// seenTrack bounds the entries of each segment. When a segment is this
	// full after the sweep of the expired entries, the code forgets its
	// oldest half. The other segments keep theirs. Thus one device that asks
	// many names costs its own segment only its oldest answers.
	seenTrack = 1 << 16
	// seenSweepEvery bounds how often an add sweeps the table.
	seenSweepEvery = 10 * time.Minute
)

type seenKey struct {
	seg  string
	name string
	addr netip.Addr
}

// seenAnswers is when each name last resolved to each address through the
// upstream of a segment. Only a name, never an address alone, opens a
// flow here: the SNI of the flow must be the name that was asked.
type seenAnswers struct {
	mu    sync.Mutex
	at    map[seenKey]time.Time
	n     map[string]int // entries of each segment
	swept time.Time
}

func seenName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (m *seenAnswers) add(seg, name string, addrs []netip.Addr, now time.Time) {
	if len(addrs) == 0 {
		return
	}
	name = seenName(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at == nil {
		m.at, m.n = map[seenKey]time.Time{}, map[string]int{}
	}
	if now.Sub(m.swept) >= seenSweepEvery {
		m.sweep(now)
	}
	for _, a := range addrs {
		k := seenKey{seg, name, a}
		if _, ok := m.at[k]; !ok {
			if m.n[seg] >= seenTrack {
				m.sweep(now)
			}
			if m.n[seg] >= seenTrack {
				m.evict(seg)
			}
			m.n[seg]++
		}
		m.at[k] = now
	}
}

func (m *seenAnswers) sweep(now time.Time) {
	m.swept = now
	for k, at := range m.at {
		if now.Sub(at) >= sniSeenFor {
			delete(m.at, k)
			m.n[k.seg]--
		}
	}
}

// evict forgets the oldest half of the entries of seg. Entries with the
// same time as the middle one go too, so it can forget more than half.
func (m *seenAnswers) evict(seg string) {
	var times []time.Time
	for k, at := range m.at {
		if k.seg == seg {
			times = append(times, at)
		}
	}
	if len(times) == 0 {
		return
	}
	slices.SortFunc(times, time.Time.Compare)
	cut := times[len(times)/2]
	for k, at := range m.at {
		if k.seg == seg && !at.After(cut) {
			delete(m.at, k)
			m.n[seg]--
		}
	}
}

// has is true when name resolved to addr on seg less than sniSeenFor ago.
func (m *seenAnswers) has(seg, name string, addr netip.Addr, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.at[seenKey{seg, seenName(name), addr}]
	return ok && now.Sub(at) < sniSeenFor
}
