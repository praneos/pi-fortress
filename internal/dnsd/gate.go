package dnsd

import (
	"net/netip"
	"sync"
	"time"
)

// Refresher is an NFTWriter that can also restart the timeout of an
// element. An add of an element that is already in a set does not
// restart it on every kernel. Without a restart, an address first
// resolved near the end of the life of its element would get answers
// for longer than the gate keeps it.
type Refresher interface {
	Refresh(set string, addrs []netip.Addr) error
}

const (
	// unknownLeft is how long, in seconds, the code trusts an element to
	// stay when this process cannot say when the element was written, and
	// the restart of its timeout failed. A restart, or the nftsets carry
	// over an apply, can leave such an element. The value is short, so a
	// wrong guess costs a minute at most.
	unknownLeft = 60
	// gateTrack bounds the table. An element lives two hours. If the table
	// is this full after the sweep of the expired elements, the code
	// forgets all of it. The next answer for each address refreshes it
	// again.
	gateTrack = 1 << 16
	// refreshErrEvery bounds how often a failing refresh is logged.
	refreshErrEvery = time.Minute
)

type gateKey struct {
	set  string
	addr netip.Addr
}

// gateLife is when each element that this process wrote last got a
// full setTimeout: when its add created it, or when a refresh restarted
// it. An element that is not here has an unknown time on it.
type gateLife struct {
	mu      sync.Mutex
	at      map[gateKey]time.Time
	lastErr time.Time
}

// left is how long the shortest-lived of addrs is sure to stay in set,
// and whether any of them is unknown or has less than floor left.
func (g *gateLife) left(set string, addrs []netip.Addr, now time.Time, floor time.Duration) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	least, stale := setTimeout, false
	for _, a := range addrs {
		at, ok := g.at[gateKey{set, a}]
		if !ok {
			least, stale = min(least, unknownLeft*time.Second), true
			continue
		}
		l := setTimeout - now.Sub(at)
		if l < floor {
			stale = true
		}
		least = min(least, max(l, 0))
	}
	return least, stale
}

// mark records addrs as written whole at now. With all true it marks each
// address. With all false it marks only an address that has no live record
// in this process:
//   - An expired record: a plain add is sure that it created that element.
//   - No record, only if unknown is true: the code assumes that the plain
//     add created the element. The caller sets unknown for a writer that
//     cannot refresh.
//
// With unknown false, mark ignores an address with no record. A plain add
// after a failed refresh is sure only of the expired elements.
func (g *gateLife) mark(set string, addrs []netip.Addr, now time.Time, all, unknown bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.at == nil {
		g.at = map[gateKey]time.Time{}
	}
	for _, a := range addrs {
		k := gateKey{set, a}
		at, ok := g.at[k]
		switch {
		case all:
		case !ok:
			if !unknown {
				continue
			}
		case now.Sub(at) < setTimeout:
			continue
		}
		if len(g.at) >= gateTrack {
			g.sweep(now)
		}
		g.at[k] = now
	}
}

func (g *gateLife) sweep(now time.Time) {
	for k, at := range g.at {
		if now.Sub(at) >= setTimeout {
			delete(g.at, k)
		}
	}
	if len(g.at) >= gateTrack {
		clear(g.at)
	}
}

func (g *gateLife) sayErr(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.lastErr.IsZero() && now.Sub(g.lastErr) < refreshErrEvery {
		return false
	}
	g.lastErr = now
	return true
}

// admitGate writes addrs into the gate set of seg before the answer goes
// out. It returns how long the shortest-lived of them is sure to stay
// there. This value caps how long the cache or the client may keep the
// answer.
//
// If an element has less than the longest cache life left, or this
// process cannot vouch for it, the writer restarts its timeout when it
// can. If not, the plain add stands and the answer is cut to fit.
func (s *Server) admitGate(seg *Segment, addrs []netip.Addr, now time.Time) (time.Duration, error) {
	if len(addrs) == 0 || seg.NFTSet == "" {
		return setTimeout, nil
	}
	_, stale := s.gate.left(seg.NFTSet, addrs, now, s.cfg.MaxTTL)
	r, canRefresh := s.nft.(Refresher)
	if canRefresh && stale {
		err := r.Refresh(seg.NFTSet, addrs)
		if err == nil {
			s.gate.mark(seg.NFTSet, addrs, now, true, true)
			return setTimeout, nil
		}
		if s.gate.sayErr(now) {
			s.logf("dns segment %q: refreshing %s: %v; adding without it, and answering for no longer than each element is sure to last", seg.Name, seg.NFTSet, err)
		}
	}
	if err := s.nft.Add(seg.NFTSet, addrs); err != nil {
		return 0, err
	}
	s.gate.mark(seg.NFTSet, addrs, now, false, !canRefresh)
	left, _ := s.gate.left(seg.NFTSet, addrs, now, 0)
	return left, nil
}
