package dnsd

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
)

// testClock is a clock that the test moves by hand. With it, a test can
// put a cached answer a known time into the past, and it does not sleep.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rawUpstream answers every query with bytes the test chose, so a reply
// no builder would produce can still be put on the wire.
type rawUpstream struct {
	conn  *net.UDPConn
	reply func(req []byte) [][]byte
	asked int64
	mu    sync.Mutex
}

func newRawUpstream(t *testing.T, reply func(req []byte) [][]byte) *rawUpstream {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &rawUpstream{conn: c, reply: reply}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, maxMsg)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.mu.Lock()
			u.asked++
			u.mu.Unlock()
			req := append([]byte(nil), buf[:n]...)
			for _, out := range u.reply(req) {
				_, _ = c.WriteToUDP(out, from)
			}
		}
	}()
	return u
}

func (u *rawUpstream) addr() string { return u.conn.LocalAddr().String() }

func (u *rawUpstream) count() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.asked
}

// clockHarness is newAliasHarness with a clock the test winds and an
// upstream address the test supplies.
func clockHarness(t *testing.T, sinkholed []string, upstream string, clk *testClock) *harness {
	t.Helper()
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "blocked-domains.conf")
	var lines []string
	for _, n := range sinkholed {
		lines = append(lines, "address=/"+n+"/0.0.0.0")
	}
	if err := os.WriteFile(sinkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nft := &fakeNFT{}
	logPath := filepath.Join(dir, "dns.jsonl")
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      nft,
		Now:      clk.now,
		LogRate:  -1,
		Segments: []Segment{{
			Iface:         "lo",
			IP:            netip.MustParseAddr("127.0.0.1"),
			Upstream:      upstream,
			SinkholeFiles: []string{sinkPath},
			NFTSet:        "resolved_v4",
			LogPath:       logPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	return &harness{srv: srv, nft: nft, log: logPath, now: clk.now}
}

// wire builds a query the way a client does.
func wire(t *testing.T, name string, qt dnsmessage.Type, id uint16) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: qt, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// answerBytes builds a reply with one CNAME and one A, each with its own
// TTL. The minimum-TTL rule must get this shape right.
func aliasAnswer(t *testing.T, req []byte, alias, target string, ip [4]byte, cnameTTL, aTTL uint32) []byte {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	b := newBuilder(hdr, q, dnsmessage.RCodeSuccess)
	if b == nil {
		t.Fatal("no builder")
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	err = b.CNAMEResource(
		dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(alias + "."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: cnameTTL},
		dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = b.AResource(
		dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: aTTL},
		dnsmessage.AResource{A: ip},
	)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	msg[2] |= 0x80
	return msg
}

// A record with a real TTL of zero is the ceiling of the whole
// answer. The chain is valid only while each link of it is valid.
// A link that expires immediately makes the message uncacheable.
// The code took zero as "no record seen yet". So the positive TTL of the
// next record overwrote it, and the cache then kept the answer that long.
func TestAGenuineZeroTTLKeepsTheAnswerOutOfTheCache(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 0, 300)}
	})
	h := clockHarness(t, nil, up.addr(), clk)
	for i := 0; i < 2; i++ {
		msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"),
			wire(t, "alias.test", dnsmessage.TypeA, 0x1111), 0)
		if msg == nil {
			t.Fatal("no reply")
		}
	}
	if n := up.count(); n != 2 {
		t.Fatalf("upstream asked %d times, want 2: a zero-TTL record was cached", n)
	}
}

// A cache hit gives back the stored bytes. If nothing counts
// the TTLs down, every client after the first gets a record that is
// good for the full original lifetime, whatever the age of the entry.
func TestACachedAnswerCountsItsTTLDown(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	h := clockHarness(t, nil, up.addr(), clk)
	src := netip.MustParseAddr("10.77.0.10")
	if msg := h.srv.answer(context.Background(), h.srv.segs[0], src, wire(t, "alias.test", dnsmessage.TypeA, 1), 0); msg == nil {
		t.Fatal("no reply")
	}
	clk.advance(100 * time.Second)
	msg := h.srv.answer(context.Background(), h.srv.segs[0], src, wire(t, "alias.test", dnsmessage.TypeA, 2), 0)
	if msg == nil {
		t.Fatal("no reply")
	}
	if n := up.count(); n != 1 {
		t.Fatalf("upstream asked %d times, want 1: the second ask was not a cache hit", n)
	}
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	for _, a := range m.Answers {
		if got := a.Header.TTL; got != 200 {
			t.Fatalf("%s TTL %d after 100s of a 300s entry, want 200", a.Header.Name, got)
		}
	}
}

// An answer too big for UDP comes back with TC set and
// nothing in it. The client then must retry over TCP, and it does.
// But the leg of the forwarder itself is still UDP, so the retry gets
// the same truncated stub. Then the name is unreachable through this
// resolver, however the client asks.
func TestATruncatedUpstreamAnswerIsRetriedOverTCP(t *testing.T) {
	udp, tcp := pairedPorts(t)
	full := make(chan []byte, 1)
	go func() {
		buf := make([]byte, maxMsg)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			stub := append([]byte(nil), req...)
			stub[2] |= 0x80 | 0x02 // response, truncated
			_, _ = udp.WriteToUDP(stub, from)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var hdr [2]byte
				if _, err := readFullConn(c, hdr[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := readFullConn(c, req); err != nil {
					return
				}
				resp := aliasAnswer(t, req, "big.test", "target.test", [4]byte{9, 9, 9, 9}, 300, 300)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
				select {
				case full <- resp:
				default:
				}
			}()
		}
	}()

	u := udpExchanger{addr: udp.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := u.exchange(ctx, wire(t, "big.test", dnsmessage.TypeA, 0x4242))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp) >= 12 && resp[2]&0x02 != 0 {
		t.Fatal("a truncated answer was taken as the answer; nothing retried it over TCP")
	}
	addrs, _, _ := aRecords(resp)
	if len(addrs) != 1 || addrs[0].String() != "9.9.9.9" {
		t.Fatalf("addresses %v, want the TCP answer's", addrs)
	}
}

// A datagram that matches on transaction id and question
// is not yet an answer. Without a QR check, the leg accepts a query
// that comes back reflected. Without a walk of the records that the
// counts promise, the resolver gates and caches a reply whose bodies
// run off the end, as if the reply were whole.
func TestAReplyThatIsNotAWholeAnswerIsIgnored(t *testing.T) {
	cases := []struct {
		name string
		bend func(bad []byte) []byte
	}{
		{"a query reflected back", func(bad []byte) []byte {
			bad[2] &^= 0x80
			return bad
		}},
		{"an opcode that was not asked", func(bad []byte) []byte {
			bad[2] = bad[2]&^0x78 | 0x08
			return bad
		}},
		{"records that run off the end", func(bad []byte) []byte {
			return bad[:len(bad)-6]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newRawUpstream(t, func(req []byte) [][]byte {
				// The bad datagram first, with an address of its
				// own, and the honest answer behind it. A leg that
				// refuses the bad one continues to read and returns the
				// good one. So the test sees which one the leg took, and
				// does not wait for the full upstream timeout.
				bad := aliasAnswer(t, req, "alias.test", "target.test", [4]byte{6, 6, 6, 6}, 300, 300)
				good := aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)
				return [][]byte{tc.bend(bad), good}
			})
			u := udpExchanger{addr: up.addr()}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := u.exchange(ctx, wire(t, "alias.test", dnsmessage.TypeA, 0x1234))
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			addrs, _, _ := aRecords(resp)
			if len(addrs) != 1 || addrs[0].String() != "1.2.3.4" {
				t.Fatalf("%q was accepted: addresses %v", tc.name, addrs)
			}
		})
	}
}

// The resolver must refuse an opcode that it does not implement. It
// must not echo it into a synthesised answer, forward it, or serve it
// from the query cache under the question that the header has.
func TestAnUnsupportedOpcodeIsRefused(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	h := clockHarness(t, nil, up.addr(), clk)
	req := wire(t, "alias.test", dnsmessage.TypeA, 0x1234)
	req[2] = req[2]&^0x78 | 0x28 // opcode 5, UPDATE
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if msg == nil {
		t.Fatal("no reply to an unsupported opcode")
	}
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	if m.Header.RCode != dnsmessage.RCodeNotImplemented {
		t.Fatalf("rcode %v for opcode 5, want NOTIMP", m.Header.RCode)
	}
	if n := up.count(); n != 0 {
		t.Fatalf("an opcode the resolver does not implement was forwarded %d times", n)
	}
}

// The second-question probe took any parse
// error as the end of the section. So it read a QDCOUNT that promises a
// question that the message does not have as a single-question
// query, not as the malformed message that it is.
func TestASecondQuestionThatDoesNotParseIsAFormatError(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte { return nil })
	h := clockHarness(t, nil, up.addr(), clk)
	req := wire(t, "alias.test", dnsmessage.TypeA, 0x1234)
	req[5] = 2 // QDCOUNT says two, and only one is here
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if msg == nil {
		t.Fatal("no reply")
	}
	if len(msg) < 12 {
		t.Fatalf("short reply %d bytes", len(msg))
	}
	if got := dnsmessage.RCode(msg[3] & 0x0f); got != dnsmessage.RCodeFormatError {
		t.Fatalf("rcode %v for a truncated question section, want FORMERR", got)
	}
}

// The resolver read the OPT record for its buffer size and
// nothing else. An EDNS version that this resolver does not speak got
// an ordinary answer, not BADVERS. Every locally built answer came back
// with no OPT. So a client that asked in EDNS got an answer as if the
// resolver had never heard of EDNS.
func TestAnUnsupportedEDNSVersionIsRefused(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	h := clockHarness(t, nil, up.addr(), clk)
	req := withOPT(t, wire(t, "alias.test", dnsmessage.TypeA, 0x1234), 1232, 1, false)
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if msg == nil {
		t.Fatal("no reply to an EDNS version we do not speak")
	}
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	ext := dnsmessage.RCode(0)
	for _, a := range m.Additionals {
		if a.Header.Type == dnsmessage.TypeOPT {
			ext = a.Header.ExtendedRCode(m.Header.RCode)
		}
	}
	if ext != dnsmessage.RCode(16) {
		t.Fatalf("extended rcode %d, want 16 (BADVERS)", ext)
	}
	if n := up.count(); n != 0 {
		t.Fatalf("an EDNS version we do not speak was forwarded %d times", n)
	}
}

func TestALocalAnswerCarriesAnOPTWhenTheClientSentOne(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte { return nil })
	h := clockHarness(t, []string{"blocked.test"}, up.addr(), clk)
	req := withOPT(t, wire(t, "blocked.test", dnsmessage.TypeA, 0x1234), 1232, 0, false)
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if msg == nil {
		t.Fatal("no reply")
	}
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range m.Additionals {
		if a.Header.Type == dnsmessage.TypeOPT {
			found = true
		}
	}
	if !found {
		t.Fatal("an EDNS query got an answer with no OPT record")
	}
}

// A type that this resolver filters is policy suppression. The reader
// pairs a query line with a reply line. If the resolver emits the
// query and no reply, nothing can distinguish the suppression from
// ordinary traffic that never resolved.
func TestAFilteredTypeIsLoggedAsABlock(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte { return nil })
	h := clockHarness(t, nil, up.addr(), clk)
	h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"),
		wire(t, "tracker.test", dnsmessage.TypeAAAA, 0x1234), 0)
	recs := h.logLines(t)
	if len(recs) != 1 {
		t.Fatalf("%d rows for one filtered query, want 1: %+v", len(recs), recs)
	}
	// The row states the verdict. It does not infer it from a verb and an
	// answer string. An empty upstream answer is ActNodata. When both had
	// one spelling, the reader could not tell a deliberate suppression
	// from traffic that did not resolve by chance. internal/observe does
	// the count.
	if recs[0].Act != dnslog.ActFiltered {
		t.Fatalf("row %+v, want the filtered verdict", recs[0])
	}
}

// The log budget is charged before the answer comes
// back. So a name that is blocked only after the walk of the chain
// spends an ordinary token. Under a flood the ordinary bucket is
// empty, and the block line disappears. That is the one line that had
// a reserved budget of its own.
func TestABlockFoundInTheChainSpendsTheBlockedBudget(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte {
		return [][]byte{aliasAnswer(t, req, "innocent.test", "blocked.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	h := clockHarness(t, []string{"blocked.test"}, up.addr(), clk)
	// A budget of one ordinary line, already spent, and a blocked
	// budget untouched.
	seg := h.srv.segs[0]
	lg := seg.log.Load()
	lg.lim = newLimiter(1, 1, logSources, func(now time.Time, src string, n int, listed bool) {
		seg.event(now, dnslog.Event{Src: src, Act: dnslog.ActSuppressed, N: n, Listed: listed})
	})
	src := netip.MustParseAddr("10.77.0.10")
	if !lg.lim.take(clk.now(), src, false) {
		t.Fatal("the fixture's first ordinary token was not there")
	}
	h.srv.answer(context.Background(), seg, src, wire(t, "innocent.test", dnsmessage.TypeA, 0x1234), 0)
	recs := h.logLines(t)
	var blocked int
	for _, r := range recs {
		if r.Act == dnslog.ActBlocked {
			blocked++
		}
	}
	if blocked == 0 {
		t.Fatalf("the block left no evidence: %+v", recs)
	}
}

// A query that read the list before a reload, and puts its answer in
// the cache after it, reinserts an entry that the new policy never
// judged. The cache reset must be ordered against the queries in
// flight, not only against the list.
func TestAnAnswerJudgedBeforeReloadIsNotCachedAfterIt(t *testing.T) {
	clk := newTestClock()
	gate := make(chan struct{})
	up := newRawUpstream(t, func(req []byte) [][]byte {
		<-gate
		return [][]byte{aliasAnswer(t, req, "alias.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})
	h := clockHarness(t, nil, up.addr(), clk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"),
			wire(t, "alias.test", dnsmessage.TypeA, 0x1234), 0)
	}()
	// The query has read the list; the reload lands while it waits.
	eventually(t, "the query reached the upstream", func() bool { return up.count() > 0 })
	if err := h.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	close(gate)
	<-done
	if _, _, size := h.srv.cache.stats(); size != 0 {
		t.Fatalf("%d entries survived a reload; they were judged under the list it replaced", size)
	}
}

// loadSink publishes the new list before
// the log reopen, which can still fail. So when a Reload reports an
// error, it has already changed the policy that the resolver answers by.
func TestAFailedReloadChangesNothing(t *testing.T) {
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte { return nil })
	h := clockHarness(t, []string{"blocked.test"}, up.addr(), clk)
	seg := h.srv.segs[0]
	// The list on disk now says something else. The log cannot be
	// reopened, because a directory is where the file was.
	if err := os.WriteFile(seg.SinkholeFiles[0], []byte("address=/other.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.log); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.log, 0755); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err == nil {
		t.Fatal("a reload whose log could not be reopened reported success")
	}
	if _, ok := seg.local.Load().lookup("blocked.test"); !ok {
		t.Fatal("a failed reload published its new list anyway")
	}
}

// -check builds the server to certify a configuration. So the build
// must refuse a port that no listener can ever bind. It cannot wait for
// the bind, because the bind never occurs under -check.
func TestNewRefusesAPortThatCannotBeBound(t *testing.T) {
	base := func(port int) Config {
		return Config{
			NFTTable: "inet fortress",
			Listen:   port,
			NFT:      &fakeNFT{},
			Segments: []Segment{{
				Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"),
				Upstream: "127.0.0.1:53", NFTSet: "resolved_v4",
			}},
		}
	}
	for _, port := range []int{-1, 65536, 1 << 20} {
		if _, err := New(base(port)); err == nil {
			t.Fatalf("port %d was accepted", port)
		}
	}
	if _, err := New(base(5353)); err != nil {
		t.Fatalf("port 5353: %v", err)
	}
}

// The daemon retries a failed bind forever, in silence. So a
// resolver whose address never came back looks the same as one
// that works: nothing in the journal, nothing for systemd, nothing
// for an operator to see.
func TestABindThatKeepsFailingKeepsSayingSo(t *testing.T) {
	needUnbindable(t)
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var logs logCapture
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   freePort(t),
		NFT:      discardNFT{},
		Segments: []Segment{{
			// An address that is on no interface of this box: the bind
			// fails and continues to fail.
			IP: netip.MustParseAddr("192.0.2.77"), Iface: "lo",
			Upstream: "127.0.0.1:9", SinkholeFiles: []string{sink}, NFTSet: "resolved_v4",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.logf = logs.logf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}()
	eventually(t, "the failed bind was reported", func() bool {
		return strings.Contains(strings.Join(logs.get(), "\n"), "192.0.2.77")
	})
}

// Run returns as soon as its loops do, but the
// query goroutines that they started still run. The CloseLogs that its
// caller then runs removes the log from under them. The result is an
// unsynchronised write to seg.log against unsynchronised reads.
func TestRunWaitsForTheQueriesItStarted(t *testing.T) {
	up := newStallUpstream(t)
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   port,
		NFT:      discardNFT{},
		LogRate:  -1,
		Segments: []Segment{{
			IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo",
			Upstream: up.pc.LocalAddr().String(), SinkholeFiles: []string{sink},
			NFTSet: "resolved_v4", LogPath: filepath.Join(dir, "dns.jsonl"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	waitFor(t, addr)

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(query(t, "example.com")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the query reached the upstream", func() bool { return up.n.Load() > 0 })

	// Cancel while the query is still in flight, then let it finish. The
	// answer that it logs must not race with the log close.
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(up.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

// pairedPorts is a UDP socket and a TCP listener on the same port, which
// is what an upstream resolver is.
func pairedPorts(t *testing.T) (*net.UDPConn, net.Listener) {
	t.Helper()
	for i := 0; i < 20; i++ {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp4", uc.LocalAddr().String())
		if err != nil {
			uc.Close()
			continue
		}
		t.Cleanup(func() { uc.Close(); ln.Close() })
		return uc, ln
	}
	t.Fatal("no port free on both udp and tcp")
	return nil, nil
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// withOPT appends an OPT record to a query, which is how a client says
// it speaks EDNS and how large a datagram it can take.
func withOPT(t *testing.T, req []byte, size uint16, version uint8, do bool) []byte {
	t.Helper()
	out := append([]byte(nil), req...)
	rr := []byte{0, 0, 41, byte(size >> 8), byte(size), 0, version, 0, 0, 0, 0}
	if do {
		rr[7] = 0x80
	}
	out = append(out, rr...)
	binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(out[10:12])+1)
	return out
}

// blackhole is a listener that accepts and then sends nothing, so a TLS
// handshake against it hangs until its own deadline. It binds the port
// that the caller names on a different loopback address, because a
// dotClient dials every pinned address on one port.
func blackhole(t *testing.T, port string) netip.Addr {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Skipf("no second loopback address here: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return netip.MustParseAddr("127.0.0.2")
}

// A lost datagram is the ordinary case on UDP, not an outage. If the
// resolver asks once and waits for all of upstreamTO, one dropped packet
// becomes a five-second SERVFAIL, and the client sees that. dnsmasq sent
// again and hid this. So the lab found it only after pf dns served the
// segment alone.
func TestALostUpstreamDatagramIsAskedAgain(t *testing.T) {
	var seen int64
	up := newRawUpstream(t, func(req []byte) [][]byte {
		// Drop the first ask completely: no answer, no error. From in here,
		// that is exactly how a dropped datagram looks.
		if atomic.AddInt64(&seen, 1) == 1 {
			return nil
		}
		return [][]byte{aliasAnswer(t, req, "lossy.test", "target.test", [4]byte{1, 2, 3, 4}, 300, 300)}
	})

	u := udpExchanger{addr: up.addr()}
	ctx, cancel := context.WithTimeout(context.Background(), upstreamTO+2*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := u.exchange(ctx, wire(t, "lossy.test", dnsmessage.TypeA, 0x7777))
	took := time.Since(start)
	if err != nil {
		t.Fatalf("exchange after one lost datagram: %v", err)
	}
	addrs, _, _ := aRecords(resp)
	if len(addrs) != 1 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("addresses %v, want the answer to the second ask", addrs)
	}
	if n := up.count(); n < 2 {
		t.Fatalf("upstream asked %d times: the lost datagram was never re-sent", n)
	}
	// The purpose of a resend is that the client does not wait for the
	// full budget. Without a retry, this returns at upstreamTO, as a
	// failure. With a retry, it returns a little after udpRetryAfter.
	if took >= upstreamTO {
		t.Fatalf("took %v, want well under %v: the retry did not shorten the wait", took, upstreamTO)
	}
}

// The budget still ends. An upstream that never answers must fail, not
// re-send forever. Otherwise a dead forwarder keeps the query slot open.
func TestASilentUpstreamStillGivesUp(t *testing.T) {
	up := newRawUpstream(t, func(req []byte) [][]byte { return nil })
	u := udpExchanger{addr: up.addr()}
	ctx, cancel := context.WithTimeout(context.Background(), upstreamTO+3*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := u.exchange(ctx, wire(t, "silent.test", dnsmessage.TypeA, 0x7788)); err == nil {
		t.Fatal("a silent upstream returned an answer")
	}
	if took := time.Since(start); took > upstreamTO+time.Second {
		t.Fatalf("took %v, want about %v: retries ran past the budget", took, upstreamTO)
	}
}
