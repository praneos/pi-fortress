package dnsd

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"pi-fortress/internal/nfq"
)

// benchQueue collects the verdicts of a benchmark. Each goroutine of the
// benchmark has its own channel. The top byte of the packet ID selects it.
// The SYN gets a plain accept; only the held packets come back.
type benchQueue struct{ got []chan uint32 }

func (q *benchQueue) Recv() (nfq.Packet, error) { return nfq.Packet{}, errors.New("not used") }
func (q *benchQueue) Close() error              { return nil }
func (q *benchQueue) Verdict(id, v uint32, mark *uint32) error {
	if v != nfq.Accept {
		m := uint32(0)
		if mark != nil {
			m = *mark
		}
		q.got[id>>24] <- m
	}
	return nil
}

// sniBenchFlow is the SYN and the ClientHello in two segments of one flow
// to 172.66.147.243:443. next gives the packets a new source address and
// port, so each call is a new flow.
type sniBenchFlow struct{ syn, a, b []byte }

func newSNIBenchFlow(hello []byte) *sniBenchFlow {
	cut := len(hello) / 2
	return &sniBenchFlow{
		syn: tcp4f("172.66.147.243", 4999, tcpSYN, nil),
		a:   tcp4("172.66.147.243", 5000, hello[:cut]),
		b:   tcp4("172.66.147.243", 5000+uint32(cut), hello[cut:]),
	}
}

func (f *sniBenchFlow) next(g byte, n uint32) {
	for _, p := range [][]byte{f.syn, f.a, f.b} {
		copy(p[12:16], []byte{10, g, byte(n >> 16), byte(n >> 8)})
		binary.BigEndian.PutUint16(p[20:22], 1024+uint16(n&0xff))
	}
}

// run sends one flow through the check and waits for the verdicts of the
// two held segments.
func (f *sniBenchFlow) run(tb testing.TB, c *sniCheck, got chan uint32, id uint32) {
	ctx := context.Background()
	c.packet(ctx, nfq.Packet{ID: id, Payload: f.syn})
	c.packet(ctx, nfq.Packet{ID: id + 1, Payload: f.a})
	c.packet(ctx, nfq.Packet{ID: id + 2, Payload: f.b})
	for range 2 {
		if m := <-got; m&sniBits != sniOK {
			tb.Errorf("verdict mark %#x, want ok", m)
		}
	}
}

func benchSNICheck() (*sniCheck, *benchQueue) {
	q := &benchQueue{}
	for range 64 {
		q.got = append(q.got, make(chan uint32, 4))
	}
	ip := []netip.Addr{netip.MustParseAddr("172.66.147.243")}
	resolve := func(context.Context, netip.Addr, string) ([]netip.Addr, bool, error) { return ip, false, nil }
	c := newSNICheck(q, resolve, nil)
	c.logf = func(string, ...any) {}
	return c, q
}

// BenchmarkSNIPacket is one new 443 flow of the house: the SYN, a
// ClientHello in two segments, the judge with a resolver that answers at
// once, and the verdict of the held packets.
func BenchmarkSNIPacket(b *testing.B) {
	c, q := benchSNICheck()
	f := newSNIBenchFlow(clientHello(b, "example.com"))
	b.ReportAllocs()
	n := uint32(0)
	for b.Loop() {
		f.next(0, n)
		f.run(b, c, q.got[0], n&0xffff*4)
		n++
	}
}

// BenchmarkSNIPacketParallel is BenchmarkSNIPacket with flows from many
// devices at the same time on one check. The real check reads one queue,
// so this is the upper bound of the contention on its lock.
func BenchmarkSNIPacketParallel(b *testing.B) {
	c, q := benchSNICheck()
	hello := clientHello(b, "example.com")
	var next atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		g := next.Add(1) - 1
		if int(g) >= len(q.got) {
			b.Error("too many goroutines")
			return
		}
		f := newSNIBenchFlow(hello)
		n := uint32(0)
		for pb.Next() {
			f.next(byte(g), n)
			f.run(b, c, q.got[g], g<<24|n&0xffff*4)
			n++
		}
	})
}
