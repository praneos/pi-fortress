package dnsd

import (
	"net/netip"
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
	// seenTrack bounds the table. If it is this full after the sweep of the
	// expired entries, the code forgets all of it. Then the check falls back
	// to the current answer and the /24, as without the table.
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
		m.at = map[seenKey]time.Time{}
	}
	if now.Sub(m.swept) >= seenSweepEvery || len(m.at)+len(addrs) > seenTrack {
		m.sweep(now)
	}
	for _, a := range addrs {
		m.at[seenKey{seg, name, a}] = now
	}
}

func (m *seenAnswers) sweep(now time.Time) {
	m.swept = now
	for k, at := range m.at {
		if now.Sub(at) >= sniSeenFor {
			delete(m.at, k)
		}
	}
	if len(m.at) >= seenTrack {
		clear(m.at)
	}
}

// has is true when name resolved to addr on seg less than sniSeenFor ago.
func (m *seenAnswers) has(seg, name string, addr netip.Addr, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.at[seenKey{seg, seenName(name), addr}]
	return ok && now.Sub(at) < sniSeenFor
}
