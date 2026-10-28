package netgate

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/nfq"
)

// fakeQueue is the kernel queue of a test: the test puts packets in, and
// the queue records each verdict.
type fakeQueue struct {
	in     chan nfq.Packet
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	verdicts []fakeVerdict
	got      chan struct{}
}

type fakeVerdict struct {
	id, v uint32
	mark  *uint32
}

func newFakeQueue() *fakeQueue {
	return &fakeQueue{in: make(chan nfq.Packet, 16), closed: make(chan struct{}), got: make(chan struct{}, 1024)}
}

func (q *fakeQueue) Recv() (nfq.Packet, error) {
	select {
	case p := <-q.in:
		return p, nil
	case <-q.closed:
		return nfq.Packet{}, nfq.ErrClosed
	}
}

func (q *fakeQueue) Verdict(id, v uint32, mark *uint32) error {
	q.mu.Lock()
	var m *uint32
	if mark != nil {
		c := *mark
		m = &c
	}
	q.verdicts = append(q.verdicts, fakeVerdict{id, v, m})
	q.mu.Unlock()
	q.got <- struct{}{}
	return nil
}

func (q *fakeQueue) Close() error {
	q.once.Do(func() { close(q.closed) })
	return nil
}

func (q *fakeQueue) isClosed() bool {
	select {
	case <-q.closed:
		return true
	default:
		return false
	}
}

// wait gives the verdicts after n of them came, or fails.
func (q *fakeQueue) wait(t *testing.T, n int) []fakeVerdict {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		q.mu.Lock()
		if len(q.verdicts) >= n {
			out := append([]fakeVerdict(nil), q.verdicts...)
			q.mu.Unlock()
			return out
		}
		q.mu.Unlock()
		select {
		case <-q.got:
		case <-deadline:
			t.Fatalf("%d verdicts, want %d", len(q.verdicts), n)
		}
	}
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.verdicts)
}

// sniHarness is a harness whose queue 1 is fq.
func sniHarness(t *testing.T, mod func(*Config)) (*harness, *fakeQueue, chan uint16) {
	t.Helper()
	fq := newFakeQueue()
	opened := make(chan uint16, 8)
	h := newHarness(t, func(c *Config) {
		c.OpenQueue = func(n uint16) (Queue, error) {
			opened <- n
			return fq, nil
		}
		if mod != nil {
			mod(c)
		}
	})
	return h, fq, opened
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for range 300 {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(what)
}

// A packet goes to pf dns with its id, mark and payload. The verdict comes
// back, and the mark changes only in the SNI bits.
func TestSNIRelayRoundTrip(t *testing.T) {
	h, fq, opened := sniHarness(t, nil)
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if n := <-opened; n != 1 {
		t.Fatalf("netgate bound queue %d, want 1", n)
	}
	const pending = 0x00100000
	payload := bytes.Repeat([]byte{0x45, 0x16}, 900)
	fq.in <- nfq.Packet{ID: 7, Mark: 0x1 | pending, Payload: payload}
	fq.in <- nfq.Packet{ID: 8, Mark: 0x1 | pending}
	fq.in <- nfq.Packet{ID: 9, Mark: pending, Payload: []byte{1}}
	p, err := sc.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != 7 || p.Mark != 0x1|pending || !bytes.Equal(p.Payload, payload) {
		t.Fatalf("packet %d mark %#x, %d bytes", p.ID, p.Mark, len(p.Payload))
	}
	for range 2 {
		if _, err := sc.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	ok := p.Mark&^SNIBits | SNIOK
	if err := sc.Verdict(7, nfq.Repeat, &ok); err != nil {
		t.Fatal(err)
	}
	if err := sc.Verdict(8, nfq.Accept, nil); err != nil {
		t.Fatal(err)
	}
	if err := sc.Verdict(9, nfq.Drop, nil); err != nil {
		t.Fatal(err)
	}
	got := fq.wait(t, 3)
	if got[0].id != 7 || got[0].v != nfq.Repeat || got[0].mark == nil || *got[0].mark != 0x1|SNIOK {
		t.Fatalf("verdict %+v, want repeat with mark %#x", got[0], 0x1|SNIOK)
	}
	if got[1].id != 8 || got[1].v != nfq.Accept || got[1].mark != nil {
		t.Fatalf("verdict %+v, want accept with no mark", got[1])
	}
	if got[2].id != 9 || got[2].v != nfq.Drop || got[2].mark != nil {
		t.Fatalf("verdict %+v, want drop with no mark", got[2])
	}
}

// pf dns sends only a code for the SNI bits. Whatever mark it has, the
// packet keeps the other bits that the kernel gave it.
func TestSNIVerdictSetsOnlyTheSNIBits(t *testing.T) {
	h, fq, _ := sniHarness(t, nil)
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	fq.in <- nfq.Packet{ID: 1, Mark: 0xdead0001}
	fq.in <- nfq.Packet{ID: 2, Mark: 0x00100001}
	for range 2 {
		if _, err := sc.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	// All bits set in the mark of pf dns: only the code of SNIBad goes.
	bad := uint32(0xffffffff)&^SNIBits | SNIBad
	if err := sc.Verdict(1, nfq.Repeat, &bad); err != nil {
		t.Fatal(err)
	}
	// A raw message: the same, with no mark at all on the wire.
	raw := []byte{verbVerdict, nfq.Repeat, bitsOK, 0, 0, 0, 0, 2}
	if _, err := sc.c.Write(raw); err != nil {
		t.Fatal(err)
	}
	got := fq.wait(t, 2)
	if *got[0].mark != 0xdead0001&^SNIBits|SNIBad {
		t.Fatalf("mark %#x, want %#x", *got[0].mark, 0xdead0001&^SNIBits|SNIBad)
	}
	if *got[1].mark != 0x00000001|SNIOK {
		t.Fatalf("mark %#x, want %#x", *got[1].mark, 0x1|SNIOK)
	}
	// A repeat with a mark that is neither ok nor bad does not go out.
	m := uint32(0x00100000)
	if err := sc.Verdict(3, nfq.Repeat, &m); err == nil {
		t.Fatal("a repeat with the pending bits went out")
	}
	if err := sc.Verdict(3, nfq.Repeat, nil); err == nil {
		t.Fatal("a repeat with no mark went out")
	}
}

// A verdict for an id that waits for none (unknown, or a second verdict)
// has no effect, and the relay goes on.
func TestSNIUnknownAndSecondVerdictsAreIgnored(t *testing.T) {
	h, fq, _ := sniHarness(t, nil)
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	fq.in <- nfq.Packet{ID: 5}
	if _, err := sc.Recv(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{99, 5, 5} {
		if err := sc.Verdict(id, nfq.Drop, nil); err != nil {
			t.Fatal(err)
		}
	}
	fq.in <- nfq.Packet{ID: 6}
	if _, err := sc.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := sc.Verdict(6, nfq.Accept, nil); err != nil {
		t.Fatal(err)
	}
	got := fq.wait(t, 2)
	time.Sleep(50 * time.Millisecond)
	if n := fq.count(); n != 2 || got[0].id != 5 || got[1].id != 6 {
		t.Fatalf("verdicts %+v (%d), want one for 5 and one for 6", got, n)
	}
	if !h.logged("verdict for packet 99, which waits for none") {
		t.Fatal("no log line for the unknown id")
	}
}

// A message that is not a valid verdict closes the relay and the queue.
func TestSNIProtocolErrorClosesTheQueue(t *testing.T) {
	for name, raw := range map[string][]byte{
		"repeat with no bits": {verbVerdict, nfq.Repeat, bitsNone, 0, 0, 0, 0, 1},
		"accept with bits":    {verbVerdict, nfq.Accept, bitsOK, 0, 0, 0, 0, 1},
		"unknown verdict":     {verbVerdict, 2, bitsNone, 0, 0, 0, 0, 1},
		"short":               {verbVerdict, nfq.Drop},
		"gate on the relay":   {verbGate, opAdd, 0, 0},
	} {
		h, fq, _ := sniHarness(t, nil)
		sc, err := DialSNI(h.sock("dns.sock"), 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sc.c.Write(raw); err != nil {
			t.Fatal(err)
		}
		eventually(t, name+": the queue is still open", fq.isClosed)
		if _, err := sc.Recv(); err == nil {
			t.Fatalf("%s: the relay still sends", name)
		}
		if n := fq.count(); n != 0 {
			t.Fatalf("%s: %d verdicts", name, n)
		}
		sc.Close()
	}
}

func TestSNIRefusals(t *testing.T) {
	h, fq, opened := sniHarness(t, nil)
	if _, err := DialSNI(h.sock("dns.sock"), 2); err == nil || !strings.Contains(err.Error(), "not an SNI queue") {
		t.Fatalf("queue 2: %v", err)
	}
	if len(opened) != 0 {
		t.Fatal("netgate bound a queue that dns.json does not name")
	}
	first, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialSNI(h.sock("dns.sock"), 1); err == nil || !strings.Contains(err.Error(), "has a client already") {
		t.Fatalf("a second client of queue 1: %v", err)
	}
	// The client goes away: the queue closes, so the kernel drops what it
	// held. Then a new client can bind it.
	first.Close()
	eventually(t, "the queue stayed open after its client went away", fq.isClosed)
	var again *SNIConn
	eventually(t, "no new client after the first went away", func() bool {
		again, err = DialSNI(h.sock("dns.sock"), 1)
		return err == nil
	})
	again.Close()
}

func TestSNIOpenFailure(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.OpenQueue = func(uint16) (Queue, error) { return nil, errors.New("nfq: bind queue 1: operation not permitted") }
	})
	if _, err := DialSNI(h.sock("dns.sock"), 1); err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("DialSNI = %v, want the bind error", err)
	}
	// The failed open freed the queue for the next try.
	if _, err := DialSNI(h.sock("dns.sock"), 1); err == nil || strings.Contains(err.Error(), "client already") {
		t.Fatalf("second DialSNI = %v", err)
	}
}

// A packet that waits too long is dropped. Its late verdict finds nothing.
func TestSNIOldPacketsAreDropped(t *testing.T) {
	h, fq, _ := sniHarness(t, func(c *Config) {
		c.sniAge, c.sniHeld, c.sniSweep = time.Second, sniHeld, 10*time.Millisecond
	})
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	fq.in <- nfq.Packet{ID: 11}
	if _, err := sc.Recv(); err != nil {
		t.Fatal(err)
	}
	h.advance(2 * time.Second)
	got := fq.wait(t, 1)
	if got[0].id != 11 || got[0].v != nfq.Drop {
		t.Fatalf("verdict %+v, want a drop of 11", got[0])
	}
	if err := sc.Verdict(11, nfq.Accept, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := fq.count(); n != 1 {
		t.Fatalf("%d verdicts; the late accept went to the kernel", n)
	}
}

// Over the cap of waiting packets, netgate drops the packet at once.
func TestSNIHeldCap(t *testing.T) {
	h, fq, _ := sniHarness(t, func(c *Config) {
		c.sniAge, c.sniHeld, c.sniSweep = sniAge, 2, sniSweep
	})
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	for id := uint32(1); id <= 3; id++ {
		fq.in <- nfq.Packet{ID: id}
	}
	got := fq.wait(t, 1)
	if got[0].id != 3 || got[0].v != nfq.Drop {
		t.Fatalf("verdict %+v, want a drop of 3", got[0])
	}
	for range 2 {
		if _, err := sc.Recv(); err != nil {
			t.Fatal(err)
		}
	}
}

// The stop of netgate closes each relay and its queue.
func TestSNIServerStopClosesTheQueue(t *testing.T) {
	h, fq, _ := sniHarness(t, nil)
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	h.stop()
	if !fq.isClosed() {
		t.Fatal("the queue is open after the stop of netgate")
	}
	if _, err := sc.Recv(); err == nil {
		t.Fatal("Recv after the stop of netgate")
	}
}

// The SNI marks are those of the ruleset (internal/render, houseSNI).
func TestSNIMarksAreRenders(t *testing.T) {
	src, err := os.ReadFile("../render/ruleset.go")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint32{"sniBits": SNIBits, "sniOK": SNIOK, "sniBad": SNIBad} {
		m := regexp.MustCompile(`(?m)^\s*` + name + `\s*=\s*"(0x[0-9a-f]+)"`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no %s in render", name)
		}
		got, err := strconv.ParseUint(string(m[1]), 0, 32)
		if err != nil || uint32(got) != want {
			t.Fatalf("render %s = %s, netgate has %#x", name, m[1], want)
		}
	}
}

func TestSNIWire(t *testing.T) {
	if q, err := decodeSNIHello(encodeSNIHello(1)); err != nil || q != 1 {
		t.Fatalf("hello: %d %v", q, err)
	}
	for _, b := range [][]byte{{}, {verbSNI, 0, 0, 0}, {verbSNI, 1, 0, 1}, {verbSNI, 0, 0, 1, 0}, {'X', 0, 0, 1}} {
		if _, err := decodeSNIHello(b); !errors.Is(err, errProto) {
			t.Errorf("hello %v: %v", b, err)
		}
	}
	p := nfq.Packet{ID: 0xfedcba98, Mark: 0x00100001, Payload: []byte("hello")}
	b, err := encodePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := decodePacket(b)
	if err != nil || q.ID != p.ID || q.Mark != p.Mark || !bytes.Equal(q.Payload, p.Payload) {
		t.Fatalf("packet round trip: %+v %v", q, err)
	}
	if _, err := encodePacket(nfq.Packet{Payload: make([]byte, maxPayload+1)}); err == nil {
		t.Fatal("a payload over the copy range encoded")
	}
	for _, b := range [][]byte{{}, {verbPacket, 0, 0}, append([]byte{verbPacket, 1}, make([]byte, 10)...), make([]byte, maxPacket+1)} {
		if _, err := decodePacket(b); !errors.Is(err, errProto) {
			t.Errorf("packet of %d bytes: %v", len(b), err)
		}
	}
	for _, v := range []verdict{{1, nfq.Drop, bitsNone}, {2, nfq.Accept, bitsNone}, {3, nfq.Repeat, bitsOK}, {0xffffffff, nfq.Repeat, bitsBad}} {
		b, err := encodeVerdict(v)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeVerdict(b); err != nil || got != v {
			t.Fatalf("verdict round trip %+v: %+v %v", v, got, err)
		}
	}
	for _, v := range []verdict{{1, nfq.Drop, bitsOK}, {1, nfq.Repeat, bitsNone}, {1, 2, bitsNone}, {1, nfq.Repeat, 3}} {
		if _, err := encodeVerdict(v); err == nil {
			t.Errorf("verdict %+v encoded", v)
		}
	}
}

// FuzzDecodeVerdict: no input panics the decoder. A verdict that it takes
// is the one encoding of itself, and changes no bit of a mark outside
// SNIBits.
func FuzzDecodeVerdict(f *testing.F) {
	for _, v := range []verdict{{1, nfq.Drop, bitsNone}, {7, nfq.Accept, bitsNone}, {9, nfq.Repeat, bitsOK}, {0xffffffff, nfq.Repeat, bitsBad}} {
		b, err := encodeVerdict(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, uint32(0x00100001))
	}
	f.Add([]byte{verbVerdict, nfq.Repeat, bitsNone, 0, 0, 0, 0, 1}, uint32(0xffffffff))
	f.Add([]byte{verbVerdict, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint32(0))
	f.Add([]byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, old uint32) {
		v, err := decodeVerdict(b)
		if err != nil {
			if !errors.Is(err, errProto) {
				t.Fatalf("error %v is not a protocol error", err)
			}
			return
		}
		again, err := encodeVerdict(v)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("two encodings of one verdict: %x %x (%v)", b, again, err)
		}
		m := v.mark(old)
		if v.verdict != nfq.Repeat {
			if m != nil {
				t.Fatalf("verdict %d sets a mark", v.verdict)
			}
			return
		}
		if m == nil || *m&^SNIBits != old&^SNIBits || (*m&SNIBits != SNIOK && *m&SNIBits != SNIBad) {
			t.Fatalf("repeat of %#x gives %#x", old, *m)
		}
	})
}

// FuzzDecodePacket: no input panics the decoder of pf dns, and a packet
// that it takes is the one encoding of itself.
func FuzzDecodePacket(f *testing.F) {
	b, _ := encodePacket(nfq.Packet{ID: 7, Mark: 0x00100001, Payload: []byte{0x45, 0, 0, 40}})
	f.Add(b)
	f.Add([]byte{verbPacket, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := decodePacket(b)
		if err != nil {
			return
		}
		again, err := encodePacket(p)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("two encodings of one packet (%v)", err)
		}
	})
}
