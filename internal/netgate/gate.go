package netgate

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"pi-fortress/internal/gateset"
)

const (
	// gateRate and gateBurst are the token bucket of the GATE requests for
	// one gate set. One request is one answer of pf dns that was not in its
	// cache, and one nft process. A busy house makes tens a second. Each
	// set has its own bucket, as each segment forked its own nft before:
	// a flood of names on one segment cannot use the writes of another.
	gateRate  = 200
	gateBurst = 400
	// gateForks limits the nft processes at one time, for all sets
	// together. It is the stop for the CPU of the box.
	gateForks = 16
	// replyWait limits the write of one reply. The client waits for it.
	replyWait = 5 * time.Second
)

// gateVerb is GATE: a write to a resolver gate set, for pf dns. netgate
// writes only a set that dns.json names, only public IPv4 addresses, at
// most gateset.MaxA of them, and at most gateRate requests a second for
// each set. The write is the nft text of gateset.Cmd, as pf dns wrote it
// before.
type gateVerb struct {
	cfg *Config
	nft *gateset.Cmd
	// rate has one bucket for each set of dns.json, and no other key.
	rate  map[string]*bucket
	forks chan struct{}
	// log limits the lines of the refused and failed writes.
	log logLimit
}

func newGateVerb(cfg *Config) *gateVerb {
	rate := make(map[string]*bucket, len(cfg.Sets))
	for _, set := range cfg.Sets {
		rate[set] = newBucket(gateRate, gateBurst)
	}
	return &gateVerb{
		cfg:   cfg,
		nft:   &gateset.Cmd{Table: cfg.Table, Run: cfg.Run},
		rate:  rate,
		forks: make(chan struct{}, gateForks),
	}
}

// serve answers GATE requests on c, one after the other, from first on.
// A message that is not a GATE request closes the connection.
func (g *gateVerb) serve(c *net.UnixConn, first, buf []byte, refuse func(string, ...any)) {
	msg := first
	for {
		req, err := decodeGate(msg)
		if err != nil {
			refuse("dns.sock: %v; the connection is closed", err)
			return
		}
		status, why := g.do(req)
		c.SetWriteDeadline(time.Now().Add(replyWait))
		if _, err := c.Write(encodeReply(status, why)); err != nil {
			return
		}
		if msg, err = readMsg(c, buf); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				refuse("dns.sock: %v", err)
			}
			return
		}
	}
}

// do runs one request and gives the status and the reason of the reply.
func (g *gateVerb) do(r gateReq) (byte, string) {
	now := g.cfg.Now()
	rate, ok := g.rate[r.set]
	if !ok {
		return g.refuse(now, "set %q is not a gate set of dns.json", r.set)
	}
	if bad, ok := notPublic(r.addrs); ok {
		return g.refuse(now, "%s is not a public address", bad)
	}
	if !rate.take(now) {
		return g.refuse(now, "more than %d GATE requests a second for set %s (burst %d)", gateRate, r.set, gateBurst)
	}
	g.forks <- struct{}{}
	defer func() { <-g.forks }()
	var err error
	if r.op == opRefresh {
		err = g.nft.Refresh(r.set, r.addrs)
	} else {
		err = g.nft.Add(r.set, r.addrs)
	}
	if err != nil {
		g.log.say(now, g.cfg.Logf, "GATE %s: %v", r.set, err)
		return statusFailed, err.Error()
	}
	return statusOK, ""
}

func (g *gateVerb) refuse(now time.Time, format string, args ...any) (byte, string) {
	why := fmt.Sprintf(format, args...)
	g.log.say(now, g.cfg.Logf, "GATE refused: %s", why)
	return statusRefused, why
}

// notPublic gives the first address that gateset.Public drops.
func notPublic(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if len(gateset.Public([]netip.Addr{a})) == 0 {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// bucket is a token bucket: rate tokens a second, at most burst.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst}
}

// take uses one token at now, if there is one.
func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		if d := now.Sub(b.last).Seconds(); d > 0 {
			b.tokens = min(b.burst, b.tokens+d*b.rate)
		}
	}
	if b.last.IsZero() || now.After(b.last) {
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
