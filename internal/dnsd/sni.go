package dnsd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/nfq"
	"pi-fortress/internal/policycompile"
	"pi-fortress/internal/tlssni"
)

// The SNI check. Before, the direct-IP gate of the house dropped a new
// 443 flow to an address that the house resolver did not give. This was
// each site that a device on Private DNS opens: its lookups go to its own
// endpoint and never reach this daemon. Now the gate marks such a flow as
// pending (render, houseSNI). Its handshake passes, and this code queues
// its first data, the TLS ClientHello. The house segment gets a query for
// the name that the device sends, exactly as if the device asked it
// (sinkhole, cache, upstream, resolved set, query log). The flow goes
// through only if the name is not blocked and the flow goes to an
// address that the name resolves to.
//
// The mark values come from render (sniOK, sniBad). A verdict repeats the
// packet into forward with one of them. forward copies it to the flow, so
// an answered flow never goes into the queue again.
const (
	sniBits = 0x00f00000
	sniOK   = 0x00200000
	sniBad  = 0x00300000
	// sniWait is how long a flow can take to send its full ClientHello. A
	// client sends it immediately after the handshake. A slower flow is not a
	// browser that opens a page.
	sniWait = 5 * time.Second
	// Caps, so a device that opens flows and never finishes them cannot make
	// this grow without a limit. If a packet goes past one of the three caps,
	// the check drops it. The flow is then a gate miss that the check could not
	// examine. The gate also dropped such a flow before.
	sniMaxFlows = 4096
	sniMaxHeld  = 32
	sniMaxBytes = 64 << 10
	// sniMaxJudges bounds the name lookups in progress. Each one goes to the
	// upstream and can start an nft process. The query slots of the
	// listeners do not cover these. When all are in use, a new flow is
	// refused.
	sniMaxJudges = 256
	// sniDone keeps a verdict for packets of the flow that were already in
	// the queue behind the packets that got the verdict.
	sniDone = 30 * time.Second
	// sniMaxDone is the maximum number of verdicts kept for sniDone. sniSweep
	// is how often a sweep occurs: one time each second, or when the table
	// reaches the cap, not at each decide. If the table is still past the cap
	// after a sweep, an arbitrary eighth goes. The check holds a late packet
	// that lost its verdict as a new flow. It then refuses the packet because
	// it has no ClientHello. That is the old answer of the gate.
	sniMaxDone = 4 * sniMaxFlows
	sniSweep   = time.Second
)

// sniQueue is nfq.Queue, narrowed so the tests can drive the check.
type sniQueue interface {
	Recv() (nfq.Packet, error)
	Verdict(id uint32, verdict uint32, mark *uint32) error
	Close() error
}

type sniFlowKey struct{ src, dst netip.AddrPort }

type sniHeld struct {
	id   uint32
	mark uint32
}

type sniFlow struct {
	segs     map[uint32][]byte // TCP sequence number -> payload
	first    uint32            // sequence number of the first data byte, from the SYN
	bytes    int
	held     []sniHeld
	deciding bool
	timer    *time.Timer
}

type sniDecided struct {
	mark uint32
	at   time.Time
}

type sniCheck struct {
	q       sniQueue
	resolve func(ctx context.Context, src netip.Addr, name string) ([]netip.Addr, bool, error)
	seen    func(name string, addr netip.Addr) bool // nil: no memory of past answers
	ech     []netip.Prefix
	opaque  []netip.Prefix // where a non-TLS flow may go (SNIOpaqueFile)
	now     func() time.Time
	logf    func(format string, args ...any)
	wait    time.Duration // sniWait; shorter in tests
	slots   chan struct{} // one for each judge in progress, sniMaxJudges
	judges  sync.WaitGroup

	mu      sync.Mutex
	flows   map[sniFlowKey]*sniFlow
	done    map[sniFlowKey]sniDecided
	lastLog time.Time
	skipped int // refusals not logged since lastLog
	swept   time.Time
}

// timeoutWhy is the reason for a flow whose ClientHello did not complete
// in time. A connection that the client opened and did not use yet sends
// no data (a browser preconnect, a keepalive). It is a different case from
// a ClientHello that stopped part of the way.
func (c *sniCheck) timeoutWhy(f *sniFlow) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.bytes > 0 {
		return fmt.Sprintf("no whole ClientHello in time (%d bytes held)", f.bytes)
	}
	return "no data in time"
}

func newSNICheck(q sniQueue, resolve func(context.Context, netip.Addr, string) ([]netip.Addr, bool, error), ech []netip.Prefix) *sniCheck {
	return &sniCheck{
		q:       q,
		resolve: resolve,
		ech:     ech,
		now:     time.Now,
		logf:    log.Printf,
		wait:    sniWait,
		slots:   make(chan struct{}, sniMaxJudges),
		flows:   map[sniFlowKey]*sniFlow{},
		done:    map[sniFlowKey]sniDecided{},
	}
}

// sniLoop runs the check of a segment until ctx ends. If the queue cannot
// open, sniLoop retries it. This is not fatal: the rest of the resolver
// must continue to serve. Until the queue is bound, the kernel drops the
// packets that the queue would hold. Thus the house is not more open than
// with the old gate.
func (s *Server) sniLoop(ctx context.Context, seg *Segment) {
	ech, err := loadECH(seg.SNIECHFile)
	if err != nil {
		log.Printf("pf dns: segment %s: %v; ECH flows will be refused", seg.Name, err)
	}
	opaque, err := loadECH(seg.SNIOpaqueFile)
	if err != nil {
		log.Printf("pf dns: segment %s: %v; non-TLS flows will be refused", seg.Name, err)
	}
	for ctx.Err() == nil {
		q, err := nfq.Open(seg.SNIQueue)
		if err != nil {
			log.Printf("pf dns: segment %s: SNI queue %d: %v; its pending 443 flows are dropped until it opens", seg.Name, seg.SNIQueue, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		c := newSNICheck(q, s.sniResolver(seg), ech)
		c.opaque = opaque
		c.seen = func(name string, addr netip.Addr) bool {
			return s.seen.has(seg.Name, name, addr, s.cfg.Now())
		}
		stop := context.AfterFunc(ctx, func() { q.Close() })
		err = c.run(ctx)
		stop()
		q.Close()
		if ctx.Err() == nil {
			log.Printf("pf dns: segment %s: SNI queue %d: %v; reopening", seg.Name, seg.SNIQueue, err)
			time.Sleep(time.Second)
		}
	}
}

// sniResolver asks the segment about name as src would. The query goes
// through answer. Thus it gets the sinkhole, the cache, the forward, the
// add to the resolved set of the segment, and the log entry under the
// address of the device. blocked is a sinkhole answer.
func (s *Server) sniResolver(seg *Segment) func(context.Context, netip.Addr, string) ([]netip.Addr, bool, error) {
	return func(ctx context.Context, src netip.Addr, name string) ([]netip.Addr, bool, error) {
		qn, err := dnsmessage.NewName(name + ".")
		if err != nil {
			return nil, false, err
		}
		id, err := randomID()
		if err != nil {
			return nil, false, err
		}
		req := canonicalQuery(dnsmessage.Question{Name: qn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, id)
		if req == nil {
			return nil, false, fmt.Errorf("could not build a query for %s", name)
		}
		resp := s.answer(ctx, seg, src, req, udpMax)
		if resp == nil {
			return nil, false, fmt.Errorf("no answer for %s", name)
		}
		addrs, _, ok := aRecords(resp)
		if !ok {
			return nil, false, fmt.Errorf("unreadable answer for %s", name)
		}
		for _, a := range addrs {
			if a.IsUnspecified() {
				return nil, true, nil
			}
		}
		return addrs, false, nil
	}
}

// run returns only after the judges that it started are done. A judge
// uses the resolver and the logs of the server, which Server.Run closes
// after its loops end.
func (c *sniCheck) run(ctx context.Context) error {
	defer c.judges.Wait()
	for {
		p, err := c.q.Recv()
		if err != nil {
			return err
		}
		c.packet(ctx, p)
	}
}

// packet is one queued packet of a pending flow. The check holds data
// until the ClientHello is complete. All other packets pass, because the
// check does not examine the ACKs and the handshake of a pending flow.
func (c *sniCheck) packet(ctx context.Context, p nfq.Packet) {
	key, seq, flags, payload, ok := parseTCP4(p.Payload)
	if !ok {
		c.verdict(p.ID, nfq.Drop, nil)
		return
	}
	// A SYN can carry data (TCP Fast Open). It is still the start of a
	// connection, and its data starts at seq+1.
	syn := flags&tcpSYN != 0
	c.mu.Lock()
	if d, ok := c.done[key]; ok && c.now().Sub(d.at) < sniDone {
		if !syn {
			c.mu.Unlock()
			c.repeat(p.ID, p.Mark, d.mark)
			return
		}
		// A SYN after the verdict is a new connection on the same addresses
		// and ports. The verdict was for the name of the old one.
		delete(c.done, key)
	}
	f := c.flows[key]
	// The SYN is in the queue too (the gate marks the flow on it). Only the
	// SYN gives the exact start of the data. Data with no flow and no live
	// verdict has no known start: the check did not see the SYN, or it
	// forgot a verdict that no packet carried. A segment from the middle of
	// the stream could hold a ClientHello that the check accepts, while the
	// server reads the bytes before it. Thus the data is refused.
	if f == nil && !syn && len(payload) > 0 {
		f = &sniFlow{held: []sniHeld{{p.ID, p.Mark}}}
		c.flows[key] = f
		c.mu.Unlock()
		c.decide(key, f, sniBad, "data with no SYN before it")
		return
	}
	if f == nil && syn {
		if len(c.flows) >= sniMaxFlows {
			c.mu.Unlock()
			c.verdict(p.ID, nfq.Drop, nil)
			return
		}
		nf := &sniFlow{segs: map[uint32][]byte{}, first: seq + 1}
		c.flows[key] = nf
		nf.timer = time.AfterFunc(c.wait, func() { c.decide(key, nf, sniBad, c.timeoutWhy(nf)) })
		f = nf
	}
	// The server ignores a later SYN with a different sequence number. If the
	// check took it, it would read the stream from a different place. Thus
	// it is refused.
	if syn {
		if seq+1 != f.first {
			c.decideLocked(key, f, sniBad, "SYN moves the start of the stream")
			c.verdict(p.ID, nfq.Drop, nil)
			return
		}
		seq++
	}
	if len(payload) == 0 {
		c.mu.Unlock()
		c.verdict(p.ID, nfq.Accept, nil)
		return
	}
	if len(f.held) >= sniMaxHeld || f.bytes+len(payload) > sniMaxBytes {
		c.decideLocked(key, f, sniBad, "ClientHello too large")
		c.verdict(p.ID, nfq.Drop, nil)
		return
	}
	// The ClientHello is at the start of the stream. A segment that is not
	// all in the first sniMaxBytes after the SYN is not part of it. In that
	// window the compare of two sequence numbers does not wrap. It wraps when
	// they are 2^31 apart.
	if off := seq - f.first; off >= sniMaxBytes || uint32(len(payload)) > sniMaxBytes-off {
		c.decideLocked(key, f, sniBad, "segment outside the start of the stream")
		c.verdict(p.ID, nfq.Drop, nil)
		return
	}
	// A retransmit can repeat bytes that the check holds, from the same or a
	// different sequence number, and can carry more: the client joins the
	// segments that are not yet acknowledged. Which copy of a repeated byte a
	// server keeps depends on its TCP stack and on the order of arrival. A
	// segment that repeats a byte with a different value could show the check
	// one name and the server another. It is refused. Thus each byte of the
	// stream has one value, whatever copy the check or the server reads.
	if f.conflicts(seq, payload) {
		c.decideLocked(key, f, sniBad, "segment changes data already held")
		c.verdict(p.ID, nfq.Drop, nil)
		return
	}
	old, dup := f.segs[seq]
	f.held = append(f.held, sniHeld{p.ID, p.Mark})
	if !dup || len(payload) > len(old) {
		f.segs[seq] = append([]byte(nil), payload...)
		f.bytes += len(payload) - len(old)
	}
	if f.deciding {
		c.mu.Unlock()
		return
	}
	buf := f.stream()
	hello, need, err := tlssni.Parse(buf)
	if err == nil && need > 0 {
		c.mu.Unlock()
		return
	}
	// From here, the name lookup has its own timeout. The ClientHello clock
	// stops, because otherwise a slow upstream would look like a slow client.
	f.deciding = true
	f.timer.Stop()
	c.mu.Unlock()
	if err != nil {
		// The WhatsApp chat protocol is not TLS and gives no name. The check
		// lets it through only into its known ranges. A stream that starts like
		// a TLS handshake record but is not a ClientHello is not that protocol.
		// It stays refused.
		if errors.Is(err, tlssni.ErrNotTLS) && len(buf) > 0 && buf[0] != 0x16 && inPrefixes(c.opaque, key.dst.Addr()) {
			c.decide(key, f, sniOK, "")
			return
		}
		c.decide(key, f, sniBad, "not a TLS ClientHello: "+err.Error())
		return
	}
	select {
	case c.slots <- struct{}{}:
	default:
		c.decide(key, f, sniBad, "too many name lookups in progress")
		return
	}
	c.judges.Add(1)
	go func() {
		defer func() { <-c.slots; c.judges.Done() }()
		mark, why := c.judge(ctx, key, hello)
		c.decide(key, f, mark, why)
	}()
}

// judge is the policy. The name must resolve through the house, and must
// not be sinkholed. The address of the flow must be one that the name
// resolves to now or resolved to in the last sniSeenFor, or be in the same
// /24 as one that it resolves to now. A CDN gives a set that rotates, and
// the device asked a short time ago through the same profile and exit, not
// now. A device can also use an expired answer after a long idle, when the
// CDN has moved the name to a different range. ECH hides the real name behind the public name of
// the provider. Thus an ECH flow goes through only to the published
// ranges of that provider: the resolver of the device already filtered
// its inner name.
func (c *sniCheck) judge(ctx context.Context, key sniFlowKey, h tlssni.Hello) (uint32, string) {
	if h.ServerName == "" {
		return sniBad, "no server name"
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, blocked, err := c.resolve(rctx, key.src.Addr(), h.ServerName)
	switch {
	case err != nil:
		return sniBad, h.ServerName + ": " + err.Error()
	case blocked:
		return sniBad, h.ServerName + " is blocked"
	}
	dst := key.dst.Addr()
	for _, a := range addrs {
		if a == dst {
			return sniOK, ""
		}
	}
	if c.seen != nil && c.seen(h.ServerName, dst) {
		return sniOK, ""
	}
	if h.ECH {
		if inPrefixes(c.ech, dst) {
			return sniOK, ""
		}
		return sniBad, fmt.Sprintf("ECH to %s (outer name %s) outside the ECH ranges", dst, h.ServerName)
	}
	for _, a := range addrs {
		if p, err := a.Prefix(24); err == nil && p.Contains(dst) {
			return sniOK, ""
		}
	}
	return sniBad, fmt.Sprintf("%s does not resolve to %s", h.ServerName, dst)
}

// decide ends a flow. It repeats each packet held for the flow with the
// mark of the verdict. It keeps the verdict for packets that are still in
// the queue behind them. A second decide for the same flow finds nothing
// to do, for example when the timer fires as the name comes back. A late
// judge or timer of an old flow finds a new flow on the same addresses
// and ports, not its own, and leaves it alone.
func (c *sniCheck) decide(key sniFlowKey, f *sniFlow, mark uint32, why string) {
	c.mu.Lock()
	c.decideLocked(key, f, mark, why)
}

// decideLocked is decide for a caller that holds c.mu. It releases c.mu.
// packet uses it when it refuses a flow that it found under the same lock.
// If packet released the lock first, a judge of that flow could end it
// with the ok mark in the gap. That verdict would then go to the packets
// that come after the refused one, for example the data of a new
// connection after a SYN that moves the start of the stream.
func (c *sniCheck) decideLocked(key sniFlowKey, f *sniFlow, mark uint32, why string) {
	if c.flows[key] != f || f == nil {
		c.mu.Unlock()
		return
	}
	delete(c.flows, key)
	if f.timer != nil { // nil: data refused before it had a flow
		f.timer.Stop()
	}
	now := c.now()
	if len(c.done) >= sniMaxDone || now.Sub(c.swept) >= sniSweep {
		c.sweepDone(now)
	}
	c.done[key] = sniDecided{mark, now}
	say := mark == sniBad && now.Sub(c.lastLog) >= time.Second
	skipped := 0
	if say {
		c.lastLog = now
		skipped, c.skipped = c.skipped, 0
	} else if mark == sniBad {
		c.skipped++
	}
	c.mu.Unlock()
	if say {
		more := ""
		if skipped > 0 {
			more = fmt.Sprintf(" (and %d more refused since the last line)", skipped)
		}
		c.logf("pf dns: sni: %s -> %s refused: %s%s", key.src, key.dst, why, more)
	}
	for _, h := range f.held {
		c.repeat(h.id, h.mark, mark)
	}
}

// sweepDone drops expired verdicts. If the table is then still at its
// cap, it also drops an arbitrary eighth of it. The caller holds c.mu.
func (c *sniCheck) sweepDone(now time.Time) {
	c.swept = now
	for k, d := range c.done {
		if now.Sub(d.at) >= sniDone {
			delete(c.done, k)
		}
	}
	for k := range c.done {
		if len(c.done) < sniMaxDone-sniMaxDone/8 {
			break
		}
		delete(c.done, k)
	}
}

// repeat sends the packet back through forward with the verdict in the
// SNI bits of its mark. It keeps the rest of the mark (the WireGuard
// bypass bit) as it was.
func (c *sniCheck) repeat(id, mark, verdict uint32) {
	m := mark&^sniBits | verdict
	c.verdict(id, nfq.Repeat, &m)
}

func (c *sniCheck) verdict(id, v uint32, mark *uint32) {
	// ErrClosed means that a judge finished after the stop. The kernel
	// dropped the packet together with the queue.
	if err := c.q.Verdict(id, v, mark); err != nil && !errors.Is(err, nfq.ErrClosed) {
		c.logf("pf dns: sni: verdict for packet %d: %v", id, err)
	}
}

// conflicts is true when payload at seq repeats a byte that a held segment
// has, with a different value.
func (f *sniFlow) conflicts(seq uint32, payload []byte) bool {
	end := seq + uint32(len(payload))
	for s, d := range f.segs {
		lo, hi := seq, end
		if seqBefore(lo, s) {
			lo = s
		}
		if e := s + uint32(len(d)); seqBefore(e, hi) {
			hi = e
		}
		if seqBefore(lo, hi) && !bytes.Equal(payload[lo-seq:hi-seq], d[lo-s:hi-s]) {
			return true
		}
	}
	return false
}

// stream is the flow's data from its first byte, as far as it is
// contiguous.
func (f *sniFlow) stream() []byte {
	var out []byte
	seq := f.first
	for {
		b, ok := f.segs[seq]
		if !ok {
			// A retransmission can overlap without a start where the last segment
			// ended. Use the segment that covers seq.
			found := false
			for s, d := range f.segs {
				if seqBefore(s, seq) && seqBefore(seq, s+uint32(len(d))) {
					b, found = d[seq-s:], true
					break
				}
			}
			if !found {
				return out
			}
		}
		out = append(out, b...)
		seq += uint32(len(b))
	}
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// seqBefore is a < b in TCP's wrapping sequence space.
func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }

const tcpSYN = 0x02

// parseTCP4 reads the flow key, sequence number, flags and data of an
// IPv4 TCP packet. Anything else is not something the ruleset queues.
func parseTCP4(pkt []byte) (sniFlowKey, uint32, byte, []byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return sniFlowKey{}, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || pkt[9] != 6 || total < ihl+20 || total > len(pkt) {
		return sniFlowKey{}, 0, 0, nil, false
	}
	tcp := pkt[ihl:total]
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return sniFlowKey{}, 0, 0, nil, false
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	key := sniFlowKey{
		src: netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		dst: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
	}
	return key, binary.BigEndian.Uint32(tcp[4:8]), tcp[13], tcp[doff:], true
}

// loadECH reads the ECH ranges file (IPv4 CIDRs, comments allowed).
// An empty path lets no ECH flow through.
func loadECH(path string) ([]netip.Prefix, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for line := range strings.SplitSeq(string(raw), "\n") {
		tok := policycompile.StripLine(line)
		if tok == "" {
			continue
		}
		p, err := netip.ParsePrefix(tok)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("%s: %q is not an IPv4 prefix", path, tok)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
