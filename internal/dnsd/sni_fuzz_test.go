package dnsd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/nfq"
	"pi-fortress/internal/tlssni"
)

// FuzzSNIFlows drives the SNI check with a small program: packets of three
// flows (SYN, Fast Open SYN, data, empty ACK), releases of name lookups in
// any order, fires of flow timers (also of old flows), and steps of the
// clock. A model in the test keeps the connections ("generations") of each
// flow. The test fails if:
//
//   - a packet gets the ok mark, but the stream of its own generation does
//     not start with a whole ClientHello for a name that resolves to the
//     address of the flow (or an opaque stream into the opaque ranges);
//   - a packet gets two verdicts, or no verdict after all lookups and
//     timers end;
//   - one generation gets both marks, a packet with data gets a plain
//     accept, or a verdict changes the bits of the mark outside sniBits;
//   - a lookup goroutine stays after the end.
//
// Program format. Byte 0 is the setup: bit 0 sends flow 1 to address B,
// bit 1 sends flow 2 to address B, bit 2 makes B an opaque range, bits 3-4
// take away 0-3 of the 4 lookup slots, bit 5 puts the start of a flow
// without a SYN near the sequence wrap. Byte 1 is not used. Then each operation is 4 bytes
// [k a b c]. The kind is k%8. For packets, (a&3)%3 is the flow, (a>>2)%5 is
// the name (a, b, x (blocked), c (other address), junk) and a>>7 sets bit 0
// of the packet mark.
//
//	0 data: hello bytes from offset b*len/256, length from c (c>=0xf0: to the end)
//	1 data as 0, with one byte changed
//	2 SYN with sequence number isns[b%4]; c>0 adds Fast Open data as 0
//	3 empty ACK
//	4 release lookup a%n; b&1: do not wait for it, run the next operation at the same time
//	5 fire the timer of flow object a%n (also of a flow that has ended)
//	6 clock step: 31s if b&1, else 1s
//	7 data as 0, at a sequence number moved by int8(k)>>3
func FuzzSNIFlows(f *testing.F) {
	op := func(k, a, b, c byte) []byte { return []byte{k, a, b, c} }
	prog := func(setup byte, ops ...[]byte) []byte {
		out := []byte{setup, 0}
		for _, o := range ops {
			out = append(out, o...)
		}
		return out
	}
	const nA, nB, nX, nC, nJunk = 0 << 2, 1 << 2, 2 << 2, 3 << 2, 4 << 2
	syn, full, rel := op(2, 0, 0, 0), op(0, nA, 0, 0xff), op(4, 0, 0, 0)
	// An allowed name.
	f.Add(prog(0, syn, full, rel))
	// The late judge of an old flow and a new flow with a blocked name.
	f.Add(prog(0, syn, full, op(2, 0, 1, 0), op(2, 0, 2, 0), op(0, nX, 0, 0xff), rel, rel))
	// A split hello, second half first, with one byte of overlap.
	f.Add(prog(0, syn, op(0, nA, 128, 0xff), op(0, nA, 0, 120), rel))
	// Fast Open, then a new Fast Open connection with a blocked name.
	f.Add(prog(0, op(2, 0, 0, 0xff), rel, op(2, nX, 3, 0xff), rel))
	// A retransmit that changes bytes.
	f.Add(prog(0, syn, op(0, nA, 0, 160), op(1, nA, 0, 0xff), rel))
	// An opaque stream into B, and the same into A.
	f.Add(prog(1|4, op(0, 1|nJunk, 'W', 10), op(0, nJunk, 'W', 10)))
	// A judge that ends at the same time as a SYN, and as a timer.
	f.Add(prog(0, syn, full, op(4, 0, 1, 0), op(2, 0, 0, 0), op(0, nB, 0, 0xff), rel))
	f.Add(prog(0, syn, full, op(4, 0, 1, 0), op(5, 0, 0, 0)))
	// A flow without a SYN, its timer, a clock step, and the flow again.
	f.Add(prog(32, op(0, 2|nA, 0, 100), op(5, 0, 0, 0), op(6, 0, 1, 0), op(0, 2|nA, 0, 0xff), rel))
	// Two names mixed in one stream.
	f.Add(prog(0, syn, op(0, nA, 0, 100), op(0, nB, 108, 0xff), rel))
	// Two flows, one slot.
	f.Add(prog(1|0x18, syn, op(2, 1, 0, 0), full, op(0, 1|nB, 0, 0xff), rel, op(4, 0, 1, 0), op(7, 1|nC, 0, 0xff)))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		h := newFzHarness(t, data[0])
		ops := data[2:]
		n := min(len(ops)/4, 64)
		for i := range n {
			o := ops[4*i : 4*i+4]
			h.run(o[0], o[1], o[2], o[3])
		}
		h.drain()
		if testing.Verbose() {
			t.Logf("program:\n  %s", strings.Join(h.trace, "\n  "))
		}
	})
}

var fzNames = [5]string{"a.example", "b.example", "x.example", "c.example", "junk"}

var (
	fzDstA  = netip.MustParseAddr("203.0.113.9")
	fzDstB  = netip.MustParseAddr("198.51.100.7")
	fzOther = netip.MustParseAddr("192.0.2.50")
	fzAns   = map[string][]netip.Addr{"a.example": {fzDstA}, "b.example": {fzDstB}, "c.example": {fzOther}}
	fzISNs  = [4]uint32{1000, 0xffffff00, 777777, 31337}
)

var fzHellos struct {
	once sync.Once
	b    [4][]byte
}

// fzGen is one connection of a flow, as the client knows it.
type fzGen struct {
	id, flow  int
	synSeen   bool   // the client opened it with a SYN at isn
	syn       bool   // the check took that SYN as the start of the stream
	isn, base uint32 // base: where data starts without a SYN
	bytes     map[uint32]byte
	conflict  bool
	min       uint32 // lowest sequence number of data held
	any       bool
	trig      bool // without a SYN: the check has decided where the stream starts
	trigMin   uint32
	decided   bool
	at        time.Time
	mark      uint32
	checked   bool
	legit     bool
}

type fzPkt struct {
	gen     *fzGen
	mark    uint32
	payload bool
}

type fzCall struct {
	name     string
	gen      *fzGen
	rel      chan struct{}
	released bool
}

type fzFlowObj struct {
	key sniFlowKey
	f   *sniFlow
}

type fzVerdict struct {
	id, v, mark uint32
	set         bool
}

// fzQueue records each verdict in order. Unlike fakeQueue, it never blocks
// and it keeps duplicates.
type fzQueue struct {
	mu  sync.Mutex
	log []fzVerdict
}

func (q *fzQueue) Recv() (nfq.Packet, error) { return nfq.Packet{}, errors.New("not used") }
func (q *fzQueue) Close() error              { return nil }
func (q *fzQueue) Verdict(id, v uint32, mark *uint32) error {
	fv := fzVerdict{id: id, v: v}
	if mark != nil {
		fv.mark, fv.set = *mark, true
	}
	q.mu.Lock()
	q.log = append(q.log, fv)
	q.mu.Unlock()
	return nil
}

type fzHarness struct {
	t      *testing.T
	ctx    context.Context
	c      *sniCheck
	q      *fzQueue
	clk    *volClock
	hellos [4][]byte
	dst    [3]netip.Addr
	base   [3]uint32
	opaque []netip.Prefix
	cur    [3]*fzGen
	gens   int
	pkts   map[uint32]*fzPkt
	nextID uint32
	seen   int
	count  map[uint32]int
	newOK  []*fzGen
	flows  []fzFlowObj
	known  map[*sniFlow]bool
	async  *fzGen // the generation of a lookup released without a wait
	trace  []string

	mu        sync.Mutex
	calls     []*fzCall
	callsSeen int
	live      int // lookups registered and not released
}

func newFzHarness(t *testing.T, setup byte) *fzHarness {
	fzHellos.once.Do(func() {
		for i := range fzHellos.b {
			fzHellos.b[i] = clientHello(t, fzNames[i])
		}
	})
	h := &fzHarness{
		t: t, ctx: context.Background(), q: &fzQueue{},
		clk:    &volClock{t: time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)},
		hellos: fzHellos.b,
		pkts:   map[uint32]*fzPkt{}, count: map[uint32]int{}, known: map[*sniFlow]bool{},
	}
	h.dst = [3]netip.Addr{fzDstA, fzDstA, fzDstA}
	for i := 1; i < 3; i++ {
		if setup&(1<<(i-1)) != 0 {
			h.dst[i] = fzDstB
		}
	}
	if setup&4 != 0 {
		h.opaque = []netip.Prefix{netip.PrefixFrom(fzDstB, 32)}
	}
	for i := range h.base {
		h.base[i] = 5000 + uint32(i)*70000
		if setup&32 != 0 {
			h.base[i] = 0xfffffe00 - uint32(i)*0x10000
		}
	}
	h.c = newSNICheck(h.q, h.resolve, nil)
	h.c.logf = func(string, ...any) {}
	h.c.wait = time.Hour // the test fires the timers itself
	h.c.now = h.clk.now
	h.c.opaque = h.opaque
	h.c.slots = make(chan struct{}, 4-int(setup>>3)&3)
	t.Cleanup(func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, c := range h.calls {
			if !c.released {
				c.released = true
				close(c.rel)
			}
		}
	})
	return h
}

// resolve blocks each lookup until the program releases it.
func (h *fzHarness) resolve(ctx context.Context, _ netip.Addr, name string) ([]netip.Addr, bool, error) {
	call := &fzCall{name: name, rel: make(chan struct{})}
	h.mu.Lock()
	h.calls = append(h.calls, call)
	h.mu.Unlock()
	select {
	case <-call.rel:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	if name == "x.example" {
		return nil, true, nil
	}
	return fzAns[name], false, nil
}

func (h *fzHarness) fail(format string, args ...any) {
	h.t.Helper()
	h.t.Fatalf("%s\nprogram:\n  %s", fmt.Sprintf(format, args...), strings.Join(h.trace, "\n  "))
}

func (h *fzHarness) logf(format string, args ...any) {
	h.trace = append(h.trace, fmt.Sprintf(format, args...))
}

func (h *fzHarness) newGen(flow int) *fzGen {
	h.gens++
	g := &fzGen{id: h.gens, flow: flow, base: h.base[flow], bytes: map[uint32]byte{}}
	h.cur[flow] = g
	return g
}

func (h *fzHarness) start(g *fzGen) uint32 {
	if g.synSeen {
		return g.isn + 1
	}
	return g.base
}

// payload is the data of a packet operation, and its offset in the stream.
func (h *fzHarness) payload(k, name, b, c byte) ([]byte, uint32) {
	if name == 4 {
		return bytes.Repeat([]byte{b}, 1+int(c)%64), uint32(k>>3) * 8
	}
	hello := h.hellos[name]
	off := int(b) * len(hello) / 256
	end := len(hello)
	if c < 0xf0 {
		end = min(end, off+1+int(c)*len(hello)/240)
	}
	return append([]byte(nil), hello[off:end]...), uint32(off)
}

func (h *fzHarness) send(g *fzGen, flow int, seq uint32, flags byte, data []byte, mark uint32) uint32 {
	h.nextID++
	id := h.nextID
	p := tcp4f(h.dst[flow].String(), seq, flags, data)
	binary.BigEndian.PutUint16(p[20:22], 40001+uint16(flow))
	h.pkts[id] = &fzPkt{gen: g, mark: mark, payload: len(data) > 0}
	h.c.packet(h.ctx, nfq.Packet{ID: id, Mark: mark, Payload: p})
	return id
}

// settle waits until each lookup in progress is either new and blocked in
// resolve, or was released and has ended. New lookups belong to g, the
// generation of the packet of this step. It returns their number.
func (h *fzHarness) settle(g *fzGen) int {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for i := 0; ; i++ {
		h.mu.Lock()
		n = len(h.calls) - h.callsSeen
		h.mu.Unlock()
		if len(h.c.slots) == h.live+n {
			break
		}
		if time.Now().After(deadline) {
			h.fail("stall: %d slots, %d lookups blocked, %d new", len(h.c.slots), h.live, n)
		}
		if i < 200 {
			runtime.Gosched()
		} else {
			time.Sleep(20 * time.Microsecond)
		}
	}
	h.mu.Lock()
	for _, c := range h.calls[h.callsSeen:] {
		if g == nil {
			h.mu.Unlock()
			h.fail("a lookup started without a packet")
		}
		c.gen = g
	}
	h.callsSeen = len(h.calls)
	h.mu.Unlock()
	h.live += n
	h.c.mu.Lock()
	for k, f := range h.c.flows {
		if !h.known[f] {
			h.known[f] = true
			h.flows = append(h.flows, fzFlowObj{k, f})
		}
	}
	h.c.mu.Unlock()
	h.process()
	return n
}

// process reads the new verdicts.
func (h *fzHarness) process() {
	h.t.Helper()
	h.q.mu.Lock()
	vs := append([]fzVerdict(nil), h.q.log[h.seen:]...)
	h.seen = len(h.q.log)
	h.q.mu.Unlock()
	for _, v := range vs {
		h.count[v.id]++
		p := h.pkts[v.id]
		switch {
		case p == nil:
			h.fail("verdict for unknown packet %d", v.id)
		case h.count[v.id] > 1:
			h.fail("packet %d: a second verdict %+v", v.id, v)
		}
		h.logf("    -> packet %d: %s", v.id, fzVerdictString(v))
		switch v.v {
		case nfq.Accept:
			if p.payload || v.set {
				h.fail("packet %d: plain accept %+v of a packet with data", v.id, v)
			}
		case nfq.Drop:
		case nfq.Repeat:
			m := v.mark & sniBits
			if !v.set || v.mark&^sniBits != p.mark&^sniBits || (m != sniOK && m != sniBad) {
				h.fail("packet %d: bad repeat %+v (packet mark %#x)", v.id, v, p.mark)
			}
			g := p.gen
			if g == nil {
				if m == sniOK {
					h.fail("packet %d: ok mark on a flow that never started", v.id)
				}
				continue
			}
			if !g.decided {
				g.decided, g.at, g.mark = true, h.clk.now(), m
			} else if g.mark != m {
				h.fail("packet %d: generation %d got both marks", v.id, g.id)
			}
			if m == sniOK {
				h.newOK = append(h.newOK, g)
			}
		default:
			h.fail("packet %d: unknown verdict %+v", v.id, v)
		}
	}
}

func fzVerdictString(v fzVerdict) string {
	switch {
	case v.v == nfq.Accept:
		return "accept"
	case v.v == nfq.Drop:
		return "drop"
	case v.mark&sniBits == sniOK:
		return "ok"
	case v.mark&sniBits == sniBad:
		return "bad"
	}
	return fmt.Sprintf("%+v", v)
}

func (h *fzHarness) verdictOf(id uint32) (fzVerdict, bool) {
	h.q.mu.Lock()
	defer h.q.mu.Unlock()
	for _, v := range h.q.log {
		if v.id == id {
			return v, true
		}
	}
	return fzVerdict{}, false
}

func (h *fzHarness) record(g *fzGen, seq uint32, data []byte) {
	for i, b := range data {
		s := seq + uint32(i)
		if old, ok := g.bytes[s]; ok {
			if old != b {
				g.conflict = true
			}
		} else {
			g.bytes[s] = b
		}
	}
	if !g.any || seqBefore(seq, g.min) {
		g.min, g.any = seq, true
	}
}

// trigger fixes the start of a stream without a SYN when the check has
// decided on it: a lookup started or a verdict came in this step.
func (h *fzHarness) trigger(g *fzGen, lookups int) {
	if g != nil && !g.syn && !g.trig && g.any && (lookups > 0 || g.decided) {
		g.trig, g.trigMin = true, g.min
	}
}

// legit is the model's answer for g: the stream from its start is a whole
// ClientHello for a name that resolves to the address, or an opaque stream
// into an opaque range.
func (h *fzHarness) legit(g *fzGen) (bool, string) {
	if g.conflict {
		return false, "the client sent two values for one byte"
	}
	start := g.min
	switch {
	case g.syn:
		start = g.isn + 1
	case g.trig:
		start = g.trigMin
	}
	var buf []byte
	for s := start; ; s++ {
		b, ok := g.bytes[s]
		if !ok {
			break
		}
		buf = append(buf, b)
	}
	dst := h.dst[g.flow]
	hello, need, err := tlssni.Parse(buf)
	switch {
	case err == nil && need == 0:
		for _, a := range fzAns[hello.ServerName] {
			if a == dst && hello.ServerName != "x.example" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("name %q does not resolve to %s", hello.ServerName, dst)
	case errors.Is(err, tlssni.ErrNotTLS) && len(buf) > 0 && buf[0] != 0x16 && inPrefixes(h.opaque, dst):
		return true, ""
	}
	return false, fmt.Sprintf("stream of %d bytes from %d: need %d, err %v", len(buf), start, need, err)
}

func (h *fzHarness) checkOK() {
	h.t.Helper()
	for _, g := range h.newOK {
		if !g.checked {
			g.checked = true
			var why string
			g.legit, why = h.legit(g)
			if !g.legit {
				h.fail("generation %d of flow %d got the ok mark: %s", g.id, g.flow, why)
			}
		}
	}
	h.newOK = h.newOK[:0]
}

func (h *fzHarness) run(k, a, b, c byte) {
	h.t.Helper()
	kind := k % 8
	flow := int(a&3) % 3
	name := (a >> 2) % 5
	mark := uint32(a >> 7)
	async := h.async
	settled := false
	settle := func(g *fzGen) int {
		settled = true
		return h.settle(g)
	}
	switch kind {
	case 0, 1, 7:
		g := h.cur[flow]
		if g != nil && g.decided && h.clk.now().Sub(g.at) >= sniDone {
			// The verdict is in conntrack. Later packets of this connection
			// do not come to the queue.
			h.logf("data flow %d: skipped, connection ended", flow)
			break
		}
		if g == nil {
			g = h.newGen(flow)
		}
		data, off := h.payload(k, name, b, c)
		if kind == 1 {
			data[len(data)/2] ^= 0x55
		}
		seq := h.start(g) + off
		if kind == 7 {
			seq += uint32(int32(int8(k)) >> 3)
		}
		pre := g.decided
		h.logf("data flow %d gen %d: %s bytes [%d,%d) at seq %d (kind %d)", flow, g.id, fzNames[name], off, int(off)+len(data), seq, kind)
		id := h.send(g, flow, seq, 0x10, data, mark)
		n := settle(g)
		v, ok := h.verdictOf(id)
		// A packet that came at the same time as the verdict of its own
		// generation can be held or late. Its bytes cannot change that verdict.
		if !pre && !(ok && v.v == nfq.Drop) && g != async {
			h.record(g, seq, data)
		}
		h.trigger(g, n)
	case 2:
		g := h.cur[flow]
		isn := fzISNs[b%4]
		retx := g != nil && !g.decided && g.synSeen && g.isn == isn
		if retx && g == async {
			// The check can see this as a retransmit or as a new connection.
			isn ^= 0x40000
			retx = false
		}
		if !retx {
			g = h.newGen(flow)
			g.synSeen, g.isn = true, isn
		}
		var data []byte
		if c > 0 {
			data, _ = h.payload(0, name, 0, c)
		}
		pre := g.decided
		h.logf("SYN flow %d gen %d: seq %d retransmit %v, %s fast open %d bytes", flow, g.id, isn, retx, fzNames[name], len(data))
		id := h.send(g, flow, isn, tcpSYN, data, mark)
		n := settle(g)
		v, ok := h.verdictOf(id)
		dropped := ok && v.v == nfq.Drop
		if !retx {
			g.syn = !dropped
		} else if !dropped {
			g.syn = true
		}
		if len(data) > 0 && !dropped && !pre {
			h.record(g, isn+1, data)
		}
		h.trigger(g, n)
	case 3:
		g := h.cur[flow]
		if g != nil && g.decided && h.clk.now().Sub(g.at) >= sniDone {
			h.logf("ACK flow %d: skipped, connection ended", flow)
			break
		}
		seq := h.base[flow]
		if g != nil {
			seq = h.start(g)
		}
		h.logf("ACK flow %d", flow)
		h.send(g, flow, seq, 0x10, nil, mark)
		settle(g)
	case 4:
		var pend []*fzCall
		h.mu.Lock()
		for _, c := range h.calls {
			if !c.released {
				pend = append(pend, c)
			}
		}
		if len(pend) == 0 {
			h.mu.Unlock()
			h.logf("release: none")
			break
		}
		call := pend[int(a)%len(pend)]
		call.released = true
		close(call.rel)
		h.mu.Unlock()
		h.live--
		if b&1 != 0 && async == nil {
			h.logf("release %s of gen %d, no wait", call.name, call.gen.id)
			h.async = call.gen
			return
		}
		h.logf("release %s of gen %d", call.name, call.gen.id)
		settle(nil)
	case 5:
		if len(h.flows) == 0 {
			h.logf("fire: none")
			break
		}
		fo := h.flows[int(a)%len(h.flows)]
		h.logf("fire timer of a flow object of %v", fo.key.src)
		h.c.decide(fo.key, fo.f, sniBad, h.c.timeoutWhy(fo.f))
		settle(nil)
	case 6:
		if async != nil {
			settle(nil)
		}
		d := time.Second
		if b&1 != 0 {
			d = sniDone + time.Second
		}
		h.clk.add(d)
		h.logf("clock +%v", d)
	}
	if !settled {
		h.settle(nil)
	}
	h.async = nil
	h.checkOK()
}

// drain ends the program: it releases each lookup and fires each timer
// until no flow is left. Then each packet must have one verdict, and no
// lookup goroutine may stay.
func (h *fzHarness) drain() {
	h.t.Helper()
	h.settle(nil)
	h.async = nil
	h.checkOK()
	h.logf("drain")
	for round := 0; ; round++ {
		if round > 100 {
			h.fail("drain does not end")
		}
		h.mu.Lock()
		rel := 0
		for _, c := range h.calls {
			if !c.released {
				c.released = true
				close(c.rel)
				rel++
			}
		}
		h.mu.Unlock()
		if rel > 0 {
			h.live -= rel
			h.settle(nil)
			h.checkOK()
			continue
		}
		var live []fzFlowObj
		h.c.mu.Lock()
		for k, f := range h.c.flows {
			live = append(live, fzFlowObj{k, f})
		}
		h.c.mu.Unlock()
		if len(live) == 0 {
			break
		}
		for _, fo := range live {
			h.c.decide(fo.key, fo.f, sniBad, h.c.timeoutWhy(fo.f))
		}
		h.settle(nil)
		h.checkOK()
	}
	for id := uint32(1); id <= h.nextID; id++ {
		if h.count[id] != 1 {
			h.fail("packet %d: %d verdicts at the end, want 1", id, h.count[id])
		}
	}
	done := make(chan struct{})
	go func() { h.c.judges.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		h.fail("a lookup goroutine did not end")
	}
	if n := len(h.c.slots); n != 0 {
		h.fail("%d lookup slots still taken", n)
	}
}
