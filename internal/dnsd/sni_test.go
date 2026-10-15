package dnsd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/nfq"
	"pi-fortress/internal/tlssni"
)

// fakeQueue is a substitute for the kernel queue. The test supplies the
// packets, and fakeQueue collects the verdicts.
type fakeQueue struct {
	mu       sync.Mutex
	verdicts map[uint32]fakeVerdict
	got      chan struct{}
}

type fakeVerdict struct {
	v    uint32
	mark uint32
	set  bool
}

func newFakeQueue() *fakeQueue {
	return &fakeQueue{verdicts: map[uint32]fakeVerdict{}, got: make(chan struct{}, 64)}
}

func (q *fakeQueue) Recv() (nfq.Packet, error) { return nfq.Packet{}, errors.New("not used") }
func (q *fakeQueue) Close() error              { return nil }
func (q *fakeQueue) Verdict(id, v uint32, mark *uint32) error {
	q.mu.Lock()
	fv := fakeVerdict{v: v}
	if mark != nil {
		fv.mark, fv.set = *mark, true
	}
	q.verdicts[id] = fv
	q.mu.Unlock()
	q.got <- struct{}{}
	return nil
}

// wait returns the verdict for id. It fails the test if no verdict comes.
func (q *fakeQueue) wait(t *testing.T, id uint32) fakeVerdict {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		q.mu.Lock()
		v, ok := q.verdicts[id]
		q.mu.Unlock()
		if ok {
			return v
		}
		select {
		case <-q.got:
		case <-deadline:
			t.Fatalf("no verdict for packet %d", id)
		}
	}
}

func (q *fakeQueue) none(t *testing.T, id uint32) {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if v, ok := q.verdicts[id]; ok {
		t.Fatalf("packet %d already has a verdict %+v; it should be held", id, v)
	}
}

// clientHello is the first message that crypto/tls sends for name. It is
// a real one, with a post-quantum key share, so its size is that of a
// browser.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		tc := tls.Client(c, &tls.Config{ServerName: name})
		_ = tc.Handshake()
		c.Close()
	}()
	buf := make([]byte, 16<<10)
	var out []byte
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if len(out) >= 5 && len(out) >= 5+int(binary.BigEndian.Uint16(out[3:5])) || err != nil {
			return out
		}
	}
}

// tcp4 is a minimal IPv4 TCP packet from the phone to dst:443.
func tcp4(dst string, seq uint32, data []byte) []byte { return tcp4f(dst, seq, 0x10, data) }

func tcp4f(dst string, seq uint32, flags byte, data []byte) []byte {
	p := make([]byte, 40+len(data))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = 6
	copy(p[12:16], netip.MustParseAddr("10.78.0.160").AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 50806)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint32(p[24:28], seq)
	p[32] = 5 << 4
	p[33] = flags
	copy(p[40:], data)
	return p
}

type fakeResolve struct {
	mu    sync.Mutex
	asked []string
	src   []netip.Addr
	ans   map[string][]netip.Addr
	block map[string]bool
}

func (r *fakeResolve) resolve(_ context.Context, src netip.Addr, name string) ([]netip.Addr, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, name)
	r.src = append(r.src, src)
	if r.block[name] {
		return nil, true, nil
	}
	return r.ans[name], false, nil
}

func newTestCheck(t *testing.T, r *fakeResolve) (*sniCheck, *fakeQueue) {
	q := newFakeQueue()
	c := newSNICheck(q, r.resolve, []netip.Prefix{netip.MustParsePrefix("104.16.0.0/13")})
	c.logf = t.Logf
	c.wait = 200 * time.Millisecond
	return c, q
}

var hn = []netip.Addr{netip.MustParseAddr("209.216.230.207")}

// The phone on Private DNS opens HN by address. The house gets a query
// for the name that the phone sends, as if the phone asked. The name
// resolves to that address. The packet goes back into forward with the
// ok bits, and the rest of its mark (the WireGuard bypass bit) stays as
// it was.
func TestSNIAcceptsANameThatResolvesToTheAddress(t *testing.T) {
	r := &fakeResolve{ans: map[string][]netip.Addr{"news.ycombinator.com": hn}}
	c, q := newTestCheck(t, r)
	ctx := context.Background()
	c.packet(ctx, nfq.Packet{ID: 1, Payload: tcp4("209.216.230.207", 1000, nil)})
	if v := q.wait(t, 1); v.v != nfq.Accept || v.set {
		t.Fatalf("a pending flow's empty ACK: %+v, want a plain accept", v)
	}
	c.packet(ctx, nfq.Packet{ID: 2, Mark: 0x1, Payload: tcp4("209.216.230.207", 1000, clientHello(t, "News.YCombinator.com"))})
	if v := q.wait(t, 2); v.v != nfq.Repeat || !v.set || v.mark != sniOK|0x1 {
		t.Fatalf("verdict %+v, want repeat with mark %#x", v, sniOK|0x1)
	}
	if len(r.asked) != 1 || r.asked[0] != "news.ycombinator.com" || r.src[0] != netip.MustParseAddr("10.78.0.160") {
		t.Fatalf("asked %v as %v, want news.ycombinator.com as the phone", r.asked, r.src)
	}
	// A packet of the same flow that was in the queue before the verdict
	// gets the same answer, without a second lookup.
	c.packet(ctx, nfq.Packet{ID: 3, Payload: tcp4("209.216.230.207", 3000, []byte("x"))})
	if v := q.wait(t, 3); v.mark != sniOK || len(r.asked) != 1 {
		t.Fatalf("late packet %+v after %d lookups", v, len(r.asked))
	}
}

// A ClientHello in two segments (a post-quantum key share makes it
// larger than one) stays held until the second segment arrives. This is
// also true when the second segment arrives first.
func TestSNIHoldsASplitClientHello(t *testing.T) {
	r := &fakeResolve{ans: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("172.66.147.243")}}}
	c, q := newTestCheck(t, r)
	ctx := context.Background()
	hello := clientHello(t, "example.com")
	cut := len(hello) / 2
	c.packet(ctx, nfq.Packet{ID: 9, Payload: tcp4f("172.66.147.243", 4999, tcpSYN, nil)})
	if v := q.wait(t, 9); v.v != nfq.Accept {
		t.Fatalf("SYN: %+v", v)
	}
	c.packet(ctx, nfq.Packet{ID: 10, Payload: tcp4("172.66.147.243", 5000+uint32(cut), hello[cut:])})
	c.packet(ctx, nfq.Packet{ID: 11, Payload: tcp4("172.66.147.243", 5000, hello[:cut])})
	for _, id := range []uint32{10, 11} {
		if v := q.wait(t, id); v.mark != sniOK {
			t.Fatalf("packet %d: %+v", id, v)
		}
	}
	// And with only the first half, the check makes no decision yet.
	c2, q2 := newTestCheck(t, r)
	c2.packet(ctx, nfq.Packet{ID: 20, Payload: tcp4("172.66.147.243", 7000, hello[:cut])})
	q2.none(t, 20)
	c2.packet(ctx, nfq.Packet{ID: 21, Payload: tcp4("172.66.147.243", 7000+uint32(cut), hello[cut:])})
	if v := q2.wait(t, 20); v.mark != sniOK {
		t.Fatalf("held half: %+v", v)
	}
}

func TestSNIRefuses(t *testing.T) {
	r := &fakeResolve{
		ans: map[string][]netip.Addr{
			"example.com":        {netip.MustParseAddr("172.66.147.243")},
			"cdn.example":        {netip.MustParseAddr("151.101.1.10")},
			"cloudflare-ech.com": {netip.MustParseAddr("104.18.10.10")},
		},
		block: map[string]bool{"tracker.example": true},
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name, dst string
		data      []byte
		want      uint32
	}{
		{"blocked name", "203.0.113.9", clientHello(t, "tracker.example"), sniBad},
		{"name for another address", "198.51.100.7", clientHello(t, "example.com"), sniBad},
		{"a CDN's neighbour address", "151.101.1.77", clientHello(t, "cdn.example"), sniOK},
		{"not TLS", "198.51.100.7", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), sniBad},
		{"unresolvable", "198.51.100.7", clientHello(t, "nothing.example"), sniBad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, q := newTestCheck(t, r)
			c.packet(ctx, nfq.Packet{ID: 1, Payload: tcp4(tc.dst, 1, tc.data)})
			if v := q.wait(t, 1); v.v != nfq.Repeat || v.mark != tc.want {
				t.Fatalf("verdict %+v, want mark %#x", v, tc.want)
			}
		})
	}
}

// The WhatsApp chat protocol ("WA" and a Noise handshake, not TLS) passes
// into the opaque ranges (the Meta ranges, HOUSE_ALLOW_WHATSAPP) and
// nowhere else. The check still judges a TLS flow into these ranges by
// its name. It never reads a malformed TLS start as an opaque protocol.
func TestSNIOpaqueRanges(t *testing.T) {
	r := &fakeResolve{block: map[string]bool{"connect.facebook.net": true}}
	wa := []byte("WA\x06\x03\x00\x00\x24\x12\x22\x1a\x20")
	ctx := context.Background()
	for _, tc := range []struct {
		name, dst string
		opaque    bool
		data      []byte
		want      uint32
	}{
		{"WhatsApp into Meta", "57.144.15.33", true, wa, sniOK},
		{"WhatsApp outside Meta", "198.51.100.7", true, wa, sniBad},
		{"toggle off", "57.144.15.33", false, wa, sniBad},
		{"blocked name into Meta", "57.144.15.33", true, clientHello(t, "connect.facebook.net"), sniBad},
		{"malformed TLS into Meta", "57.144.15.33", true, []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0, 0, 1, 0}, sniBad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, q := newTestCheck(t, r)
			if tc.opaque {
				c.opaque = []netip.Prefix{netip.MustParsePrefix("57.144.0.0/14")}
			}
			c.packet(ctx, nfq.Packet{ID: 1, Payload: tcp4(tc.dst, 1, tc.data)})
			if v := q.wait(t, 1); v.v != nfq.Repeat || v.mark != tc.want {
				t.Fatalf("verdict %+v, want mark %#x", v, tc.want)
			}
		})
	}
}

// The check refuses a flow that never finishes its ClientHello when the
// wait ends. It does not hold the flow forever.
func TestSNIGivesUpOnAnUnfinishedHello(t *testing.T) {
	c, q := newTestCheck(t, &fakeResolve{})
	hello := clientHello(t, "example.com")
	c.packet(context.Background(), nfq.Packet{ID: 1, Payload: tcp4("198.51.100.7", 1, hello[:100])})
	q.none(t, 1)
	if v := q.wait(t, 1); v.mark != sniBad {
		t.Fatalf("verdict %+v after the wait", v)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.flows) != 0 {
		t.Fatalf("%d flows still held", len(c.flows))
	}
}

func TestParseTCP4(t *testing.T) {
	key, seq, flags, data, ok := parseTCP4(tcp4f("209.216.230.207", 42, tcpSYN, []byte("hi")))
	if !ok || seq != 42 || flags != tcpSYN || string(data) != "hi" || key.dst != netip.MustParseAddrPort("209.216.230.207:443") || key.src != netip.MustParseAddrPort("10.78.0.160:50806") {
		t.Fatalf("%v %d %q %v", key, seq, data, ok)
	}
	for _, bad := range [][]byte{nil, make([]byte, 19), tcp4("1.2.3.4", 1, nil)[:30]} {
		if _, _, _, _, ok := parseTCP4(bad); ok {
			t.Fatalf("parsed %x", bad)
		}
	}
	udp := tcp4("1.2.3.4", 1, nil)
	udp[9] = 17
	if _, _, _, _, ok := parseTCP4(udp); ok {
		t.Fatal("parsed UDP as TCP")
	}
}

// ECH shows only the public name of the provider, so the check cannot
// match the address to the real name. The flow passes inside the
// published ranges of the provider and nowhere else.
func TestSNIJudgesECHByRange(t *testing.T) {
	r := &fakeResolve{ans: map[string][]netip.Addr{"cloudflare-ech.com": {netip.MustParseAddr("104.18.10.10")}}}
	c, _ := newTestCheck(t, r)
	key := func(dst string) sniFlowKey {
		return sniFlowKey{netip.MustParseAddrPort("10.78.0.160:1"), netip.AddrPortFrom(netip.MustParseAddr(dst), 443)}
	}
	h := tlssni.Hello{ServerName: "cloudflare-ech.com", ECH: true}
	if m, why := c.judge(context.Background(), key("104.21.3.4"), h); m != sniOK {
		t.Fatalf("ECH inside the ranges refused: %s", why)
	}
	if m, _ := c.judge(context.Background(), key("198.51.100.7"), h); m != sniBad {
		t.Fatal("ECH outside the ranges accepted")
	}
}

// The shadow query uses the pipeline of the segment, not a separate
// lookup. A sinkholed name comes back blocked and does not reach the
// upstream. A forwarded name goes into the resolved set of the segment
// and into its query log, under the address of the device.
func TestSNIResolverIsTheSegmentsOwnLookup(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "house.conf")
	if err := os.WriteFile(sink, []byte("address=/tracker.example/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, map[string][4]byte{"news.ycombinator.com": {209, 216, 230, 207}}, nil, 60)
	nft := &fakeNFT{}
	log := filepath.Join(dir, "house.log")
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      nft,
		Segments: []Segment{{
			Name: "house", Iface: "lo", IP: netip.MustParseAddr("127.0.0.2"),
			Upstream: up.addr(), NFTSet: "resolved_house_v4", SinkholeFiles: []string{sink},
			LogPath: log,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	resolve := srv.sniResolver(srv.segs[0])
	phone := netip.MustParseAddr("10.78.0.160")
	ctx := context.Background()

	addrs, blocked, err := resolve(ctx, phone, "news.ycombinator.com")
	if err != nil || blocked || len(addrs) != 1 || addrs[0] != hn[0] {
		t.Fatalf("news.ycombinator.com: %v %v %v", addrs, blocked, err)
	}
	if _, blocked, err := resolve(ctx, phone, "tracker.example"); err != nil || !blocked {
		t.Fatalf("a sinkholed name was not reported blocked: %v %v", blocked, err)
	}
	srv.CloseLogs()
	nft.mu.Lock()
	sets, adds := nft.sets, nft.adds
	nft.mu.Unlock()
	if len(sets) != 1 || sets[0] != "resolved_house_v4" || len(adds) != 1 || adds[0][0] != hn[0] {
		t.Fatalf("resolved set writes %v %v, want HN's address in resolved_house_v4 only", sets, adds)
	}
	raw, _ := os.ReadFile(log)
	if !strings.Contains(string(raw), "10.78.0.160") || !strings.Contains(string(raw), "news.ycombinator.com") {
		t.Fatalf("the shadow query is not in the house log under the device:\n%s", raw)
	}
}

// Before, each decide swept the verdicts kept for late packets with a
// scan of the full map. Only the number of flows that decide in sniDone
// limited the map. Thus a house that opened flows fast enough made each
// verdict cost the full table. Now the table has a cap, and a sweep
// occurs a maximum of one time each second.
func TestSNIDoneIsBoundedAndSweptOnATimer(t *testing.T) {
	c, _ := newTestCheck(t, &fakeResolve{})
	clk := &volClock{t: time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)}
	c.now = clk.now
	decide := func(i int) {
		key := sniFlowKey{
			src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 78, byte(i >> 8), byte(i)}), uint16(i)),
			dst: netip.MustParseAddrPort("209.216.230.207:443"),
		}
		c.mu.Lock()
		c.flows[key] = &sniFlow{timer: time.AfterFunc(time.Hour, func() {})}
		c.mu.Unlock()
		c.decide(key, sniOK, "")
	}
	for i := range 3 * sniMaxDone {
		decide(i)
		if i%997 == 0 {
			clk.add(time.Millisecond)
		}
	}
	if n := len(c.done); n > sniMaxDone {
		t.Fatalf("done holds %d verdicts, over its cap of %d", n, sniMaxDone)
	}
	clk.add(sniDone)
	decide(0)
	if n := len(c.done); n != 1 {
		t.Fatalf("after every verdict expired: %d left", n)
	}
}
