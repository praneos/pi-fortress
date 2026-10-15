package dnsd

import (
	"sync"
	"time"
)

// cacheKey names the segment and the question. By the rules of this
// daemon, a shared cache is wrong for two reasons. First, a segment can
// forward to its own provider (HOUSE_DNS_UPSTREAM, HOUSE_DOT_*). This is
// half the reason that this daemon exists instead of dnsmasq. A shared
// entry would give the house an answer from the resolver of the agents.
// Second, the resolver gate is per segment. A cache hit returns before the
// address gets to the set of the segment that asks. Thus the client gets
// the answer, and then the gate drops its connection to that address.
// Both problems were live after the house moved to pf dns. The house VM in
// the lab found the second.
//
// The CD and DO bits and the EDNS options (ECS included) of the asker are
// not in the key. They do not need to be: none of them goes out of this
// daemon. canonicalQuery asks the upstream with CD=0, DO=0 and an OPT with
// no options, whatever the client sent. Thus one question has one answer,
// and the key holds all that the answer depends on. The design strips the
// flags and does not key on them. To key on them works only if the daemon
// forwards them. To forward them means one entry per flag combination,
// RRSIGs that nothing here validates, and the subnet of a LAN client sent
// to the upstream. The cost: a stub that validates for itself (CD=1,
// DO=1) gets no RRSIGs and cannot validate. Thus the upstream of this
// resolver is the only validator. cacheflags_test.go asks with each flag
// against an upstream that answers by them.
type cacheKey struct {
	seg   string
	name  string
	qtype uint16
}

type entry struct {
	msg     []byte
	stored  time.Time
	expires time.Time
}

// cache holds whole upstream responses, keyed by question. No code edits
// the bytes in place: each reader makes a copy before it changes the id or
// ages the TTLs. Thus one entry can serve any number of clients at the
// same time.
type cache struct {
	mu   sync.Mutex
	m    map[cacheKey]entry
	max  int
	now  func() time.Time
	hits uint64
	miss uint64
	// gen counts the resets. A query reads it before it reads the list of the
	// segment, and gives it back at put. Thus an answer judged under a list
	// that a reload has since replaced cannot put itself back into the cache
	// that the reload emptied. Without gen, a query that is in flight when
	// SIGHUP arrives puts its old-policy answer back after the reload. The
	// purpose of the reload is that the new list controls from that point.
	// That purpose is then lost for the TTL of that answer.
	gen uint64
}

func newCache(max int, now func() time.Time) *cache {
	return &cache{m: make(map[cacheKey]entry, max), max: max, now: now}
}

func (c *cache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// get returns the stored message and the time that the cache held it. The
// caller counts the TTLs down by that time.
func (c *cache) get(k cacheKey) ([]byte, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		c.miss++
		return nil, 0, false
	}
	now := c.now()
	if !now.Before(e.expires) {
		delete(c.m, k)
		c.miss++
		return nil, 0, false
	}
	c.hits++
	return e.msg, now.Sub(e.stored), true
}

func (c *cache) put(k cacheKey, msg []byte, ttl time.Duration, gen uint64) {
	if ttl <= 0 || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if len(c.m) >= c.max {
		c.evict()
	}
	now := c.now()
	c.m[k] = entry{msg: msg, stored: now, expires: now.Add(ttl)}
}

// evict drops all expired entries. If that frees nothing, it drops an
// arbitrary entry. A cache that refuses to make space would keep the first
// 2000 names resolved after boot and never accept another.
func (c *cache) evict() {
	now := c.now()
	freed := false
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
			freed = true
		}
	}
	if freed {
		return
	}
	for k := range c.m {
		delete(c.m, k)
		return
	}
}

func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[cacheKey]entry, c.max)
	c.gen++
}

func (c *cache) stats() (hits, miss uint64, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.miss, len(c.m)
}
