package dnsd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/gateset"
)

// fakeNFT records the writes, and a test can make it fail. This is how
// the tests see the order: if the write is on the answer path, a failed
// write must cost the client its answer.
type fakeNFT struct {
	mu    sync.Mutex
	adds  [][]netip.Addr
	sets  []string
	fail  error
	calls atomic.Int64
}

func (f *fakeNFT) Add(set string, addrs []netip.Addr) error {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sets = append(f.sets, set)
	f.adds = append(f.adds, addrs)
	return nil
}

func (f *fakeNFT) flat() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.adds {
		for _, x := range a {
			out = append(out, x.String())
		}
	}
	return out
}

// upstream is a DNS server that answers A queries from a table. It
// counts the queries that it gets, so a cache hit shows as a query that
// never arrived.
type upstream struct {
	t     testing.TB
	table map[string][4]byte
	ttl   uint32
	conn  *net.UDPConn
	asked atomic.Int64
	// cname sends the query to a different name first, as a real upstream
	// answers an alias. The CNAME and the A of the target arrive in the one
	// message, under two different names.
	cname map[string]string
	// last is the most recent request as it arrived, so a test can say
	// what the resolver asked rather than only what it answered.
	last atomic.Pointer[[]byte]
	// manyA, when over 1, answers with that number of addresses. They count
	// up from the address in the table. aliasTTL, when not 0, is the CNAME
	// TTL in place of ttl. The address-only tests need these to see a cap
	// and a minimum across the chain.
	manyA    atomic.Int64
	aliasTTL atomic.Uint32
	// byFlags, when set, answers a query with CD, DO or any EDNS option
	// with the address in the table plus 62 in the last byte. This is an
	// upstream whose answer changes with the flags of the asker, as a
	// validating or ECS-aware upstream does (cacheflags_test.go).
	byFlags atomic.Bool
	// rcodes answers a name with that rcode and nothing else: an
	// upstream that fails (SERVFAIL) or refuses the asker (REFUSED).
	rcodes sync.Map
}

// lastQuery is the request the upstream saw most recently.
func (u *upstream) lastQuery(t *testing.T) []byte {
	t.Helper()
	p := u.last.Load()
	if p == nil {
		t.Fatal("the upstream was never asked")
	}
	return *p
}

func newUpstream(t testing.TB, table map[string][4]byte, cname map[string]string, ttl uint32) *upstream {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{t: t, table: table, cname: cname, ttl: ttl, conn: c}
	go u.serve()
	t.Cleanup(func() { c.Close() })
	return u
}

func (u *upstream) addr() string { return u.conn.LocalAddr().String() }

func (u *upstream) serve() {
	buf := make([]byte, 4096)
	for {
		n, from, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		u.asked.Add(1)
		req := make([]byte, n)
		copy(req, buf[:n])
		u.last.Store(&req)
		var p dnsmessage.Parser
		hdr, err := p.Start(req)
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(q.Name.String(), ".")
		target, aliased := u.cname[name]
		if !aliased {
			target = name
		}
		ip, ok := u.table[target]
		if ok && u.byFlags.Load() && askerFlagged(req) {
			ip[3] += 62
		}
		rcode := dnsmessage.RCodeSuccess
		if !ok {
			rcode = dnsmessage.RCodeNameError
		}
		if rc, set := u.rcodes.Load(name); set {
			rcode, ok = rc.(dnsmessage.RCode), false
		}
		b := newBuilder(hdr, q, rcode)
		if b == nil {
			continue
		}
		if ok {
			_ = b.StartAnswers()
			if aliased {
				cttl := u.ttl
				if v := u.aliasTTL.Load(); v != 0 {
					cttl = v
				}
				_ = b.CNAMEResource(
					dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: cttl},
					dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")},
				)
			}
			_ = b.AResource(
				dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: u.ttl},
				dnsmessage.AResource{A: ip},
			)
			for i := int64(1); i < u.manyA.Load(); i++ {
				more := ip
				more[3] += byte(i)
				_ = b.AResource(
					dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: u.ttl},
					dnsmessage.AResource{A: more},
				)
			}
		}
		// A real upstream answers EDNS in EDNS and copies DO. In the past,
		// this is how the flags of the asker went into the cache.
		e := clientEDNS(req)
		msg := finish(b, e, dnsmessage.RCodeSuccess)
		if msg == nil {
			continue
		}
		_, _ = u.conn.WriteToUDP(msg, from)
	}
}

type harness struct {
	srv *Server
	nft *fakeNFT
	up  *upstream
	log string
	// allow is the paranoid forward set's allow.domains, so a test can
	// rewrite it and reload.
	allow string
	now   func() time.Time
}

func newHarness(t *testing.T, sinkholed []string, table map[string][4]byte, ttl uint32) *harness {
	t.Helper()
	return newAliasHarness(t, sinkholed, table, nil, ttl)
}

// newAliasHarness is newHarness with an upstream that answers some names
// with a CNAME to a different name. This is the only way to reach the
// chain policy from outside the package.
func newAliasHarness(t *testing.T, sinkholed []string, table map[string][4]byte, cname map[string]string, ttl uint32) *harness {
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
	up := newUpstream(t, table, cname, ttl)
	nft := &fakeNFT{}
	logPath := filepath.Join(dir, "dns.jsonl")
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   0,
		NFT:      nft,
		Now:      func() time.Time { return now },
		Segments: []Segment{{
			Iface:         "lo",
			IP:            netip.MustParseAddr("127.0.0.1"),
			Upstream:      up.addr(),
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
	return &harness{srv: srv, nft: nft, up: up, log: logPath, now: func() time.Time { return now }}
}

// ask sends one query directly through answer. That is the full path,
// except the socket.
func (h *harness) ask(t *testing.T, name string, qt dnsmessage.Type) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  qt,
		Class: dnsmessage.ClassINET,
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := h.srv.answer(ctx, h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if resp == nil {
		t.Fatalf("%s %v: no reply", name, qt)
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("%s: unpack: %v", name, err)
	}
	if m.Header.ID != 0x1234 {
		t.Fatalf("id %#x, want the client's", m.Header.ID)
	}
	if !m.Header.Response {
		t.Fatal("not a response")
	}
	return m.Header, m.Answers
}

// askFrom is ask with a client address that the caller selects, so a
// test can put a query outside the net of the segment.
func (h *harness) askFrom(t *testing.T, name string, src netip.Addr) {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.srv.answer(ctx, h.srv.segs[0], src, req, 0)
}

func firstA(t *testing.T, answers []dnsmessage.Resource) string {
	t.Helper()
	for _, a := range answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(r.A).String()
		}
	}
	return ""
}

// logLines is what the daemon wrote, read back through the parser that
// the reader uses. There is one row per transaction. There is no
// separate query line to pair with, and that is the purpose of the shape.
func (h *harness) logLines(t *testing.T) []dnslog.Event {
	t.Helper()
	raw, err := os.ReadFile(h.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []dnslog.Event
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if l == "" {
			continue
		}
		ev, ok := dnslog.ParseEvent(l)
		if !ok {
			t.Fatalf("wrote a line its own reader refuses: %q", l)
		}
		out = append(out, ev)
	}
	return out
}

func TestForwardsAndFillsTheSet(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {93, 184, 216, 34}}, 300)
	_, answers := h.ask(t, "example.com", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "93.184.216.34" {
		t.Fatalf("answer %q", got)
	}
	if got := h.nft.flat(); len(got) != 1 || got[0] != "93.184.216.34" {
		t.Fatalf("nft %v", got)
	}
	if h.nft.sets[0] != "resolved_v4" {
		t.Fatalf("set %q", h.nft.sets[0])
	}
}

// A segment that gets the full answer gets each address. The gate set gets
// only the first maxGateA of them. Thus one large answer cannot fill the set.
func TestAFullAnswerAdmitsAtMostMaxGateA(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"wide.example": {93, 184, 216, 1}}, 300)
	h.up.manyA.Store(maxGateA + 6)
	_, answers := h.ask(t, "wide.example", dnsmessage.TypeA)
	if len(answers) != maxGateA+6 {
		t.Fatalf("client got %d addresses, want %d", len(answers), maxGateA+6)
	}
	set := h.nft.flat()
	if len(set) != maxGateA {
		t.Fatalf("gate set took %d, want %d", len(set), maxGateA)
	}
	if set[0] != "93.184.216.1" || set[maxGateA-1] != "93.184.216.64" {
		t.Fatalf("gate set took %v, want the first %d of the answer", set, maxGateA)
	}
}

// gateAddrs keeps the order of the answer, sends a repeated address one
// time, and stops at n distinct addresses.
func TestGateAddrsDropsRepeatsAndStopsAtN(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	in := []netip.Addr{a("1.1.1.1"), a("1.1.1.1"), a("2.2.2.2"), a("1.1.1.1"), a("3.3.3.3"), a("4.4.4.4")}
	got := gateAddrs(in, 3)
	if want := []netip.Addr{a("1.1.1.1"), a("2.2.2.2"), a("3.3.3.3")}; !slices.Equal(got, want) {
		t.Fatalf("gateAddrs %v, want %v", got, want)
	}
	if got := gateAddrs(nil, 3); len(got) != 0 {
		t.Fatalf("gateAddrs of nothing %v", got)
	}
	if got := gateAddrs(in, 0); len(got) != 0 {
		t.Fatalf("gateAddrs with n 0 %v", got)
	}
}

// A public name rebound to a local address still gets an answer. But the
// gate set never learns the address, so the gate drops the dial as a
// direct one.
func TestARebindIsAnsweredButNeverAdmitted(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{
		"rebind.example": {192, 168, 29, 1},
		"cgnat.example":  {100, 64, 0, 1},
		"loop.example":   {127, 0, 0, 1},
		"ten.example":    {10, 0, 0, 1},
	}, 300)
	for _, name := range []string{"rebind.example", "cgnat.example", "loop.example", "ten.example"} {
		_, answers := h.ask(t, name, dnsmessage.TypeA)
		if firstA(t, answers) == "" {
			t.Fatalf("%s: no answer", name)
		}
	}
	if got := h.nft.flat(); len(got) != 0 {
		t.Fatalf("gate set learned %v", got)
	}
	if got := gateset.Public([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("172.16.0.1"), netip.MustParseAddr("::ffff:10.0.0.1")}); len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("public %v", got)
	}
}

// The gate drops a connection to an address that is not in the set. So,
// after a failed set write, the answer must not name that address.
// SERVFAIL is the proof that the write gates the reply.
func TestASetWriteThatFailedCostsTheAnswer(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {1, 2, 3, 4}}, 300)
	h.nft.fail = errors.New("nft: no such set")
	hdr, answers := h.ask(t, "example.com", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, want SERVFAIL", hdr.RCode)
	}
	if got := firstA(t, answers); got != "" {
		t.Fatalf("handed out %q with the set write failed", got)
	}
}

// A refused add (a full set gives this) goes to the journal one time each
// minute, not one time for each query.
func TestASetWriteThatFailedIsLogged(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {1, 2, 3, 4}, "example.net": {1, 2, 3, 5}}, 300)
	var said []string
	h.srv.logf = func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
	h.nft.fail = errors.New("nft: set is full")
	h.ask(t, "example.com", dnsmessage.TypeA)
	h.ask(t, "example.net", dnsmessage.TypeA)
	if len(said) != 1 || !strings.Contains(said[0], "resolved_v4") || !strings.Contains(said[0], "set is full") {
		t.Fatalf("log %q, want one line that names the set and the error", said)
	}
}

func TestSinkholeAnswersZeroAndNeverForwards(t *testing.T) {
	h := newHarness(t, []string{"webhook.site"}, map[string][4]byte{"webhook.site": {1, 2, 3, 4}}, 300)
	_, answers := h.ask(t, "sub.webhook.site", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "0.0.0.0" {
		t.Fatalf("answer %q, want the sinkhole", got)
	}
	if h.up.asked.Load() != 0 {
		t.Fatal("a sinkholed name reached the upstream")
	}
	if h.nft.calls.Load() != 0 {
		t.Fatal("the sinkhole address went into the gate set")
	}
	recs := h.logLines(t)
	last := recs[len(recs)-1]
	if last.Act != dnslog.ActBlocked || last.Answer != "0.0.0.0" {
		t.Fatalf("log %+v, want a blocked row", last)
	}
}

// An operator can write "*.name" by hand in a sinkhole file. The compiled
// lists write the same entry as "name". Both forms must block the same
// names: the name and each name under it.
func TestSinkholeStarEntryCoversTheNameAndItsSubdomains(t *testing.T) {
	table := map[string][4]byte{"a.wild.test": {1, 2, 3, 4}, "wild.test": {1, 2, 3, 4}}
	h := newHarness(t, []string{"*.wild.test"}, table, 300)
	for _, name := range []string{"a.wild.test", "wild.test"} {
		_, answers := h.ask(t, name, dnsmessage.TypeA)
		if got := firstA(t, answers); got != "0.0.0.0" {
			t.Fatalf("%s: answer %q, want the sinkhole", name, got)
		}
	}
	if h.up.asked.Load() != 0 {
		t.Fatal("a name under a *. entry reached the upstream")
	}
}

// An alias is the obvious way around a list of names. The name on the
// list is never in the query. It is only in the answer.
func TestACNAMEToASinkholedNameIsSinkholed(t *testing.T) {
	h := newAliasHarness(t,
		[]string{"tracker.adtech.net"},
		map[string][4]byte{"tracker.adtech.net": {1, 2, 3, 4}},
		map[string]string{"metrics.yourbank.com": "tracker.adtech.net"},
		300)
	_, answers := h.ask(t, "metrics.yourbank.com", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "0.0.0.0" {
		t.Fatalf("answer %q, want the sinkhole", got)
	}
	if got := h.nft.flat(); len(got) != 0 {
		t.Fatalf("the blocked target's address reached the gate set as %v", got)
	}
	// The resolver asks the upstream, because only the upstream knows the
	// target of the alias. But its answer must not stay in the cache. If it
	// does, the next client gets it, and nothing examines the chain again.
	if h.up.asked.Load() != 1 {
		t.Fatalf("upstream asked %d times, want 1", h.up.asked.Load())
	}
	h.ask(t, "metrics.yourbank.com", dnsmessage.TypeA)
	if h.up.asked.Load() != 2 {
		t.Fatal("the blocked answer was served from the cache")
	}
}

// The same walk must not block an ordinary alias. Almost every CDN name
// is a CNAME to a different name.
func TestACNAMEToAnUnlistedNameIsAnswered(t *testing.T) {
	h := newAliasHarness(t,
		[]string{"tracker.adtech.net"},
		map[string][4]byte{"edge.cdn.example": {9, 9, 9, 9}},
		map[string]string{"www.example.com": "edge.cdn.example"},
		300)
	_, answers := h.ask(t, "www.example.com", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "9.9.9.9" {
		t.Fatalf("answer %q, want the target's address", got)
	}
	if got := h.nft.flat(); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("gate set %v, want the target's address", got)
	}
}

func TestAAAAAndHTTPSAreDropped(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {1, 2, 3, 4}}, 300)
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.Type(typeHTTPS), dnsmessage.Type(typeSVCB)} {
		hdr, answers := h.ask(t, "example.com", qt)
		if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 {
			t.Fatalf("%v: rcode %v answers %d, want NODATA", qt, hdr.RCode, len(answers))
		}
	}
	if h.up.asked.Load() != 0 {
		t.Fatal("a filtered type reached the upstream")
	}
}

func TestDomainNeededAndBogusPriv(t *testing.T) {
	h := newHarness(t, nil, nil, 300)
	hdr, _ := h.ask(t, "wpad", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("a dotless name got %v", hdr.RCode)
	}
	hdr, _ = h.ask(t, "10.0.77.10.in-addr.arpa", dnsmessage.TypePTR)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("a private reverse lookup got %v", hdr.RCode)
	}
	if h.up.asked.Load() != 0 {
		t.Fatal("one of them was forwarded")
	}
	// A public address still resolves in reverse.
	h.ask(t, "34.216.184.93.in-addr.arpa", dnsmessage.TypePTR)
	if h.up.asked.Load() != 1 {
		t.Fatal("a public reverse lookup was not forwarded")
	}
}

func TestTruncationTellsTheClientToUseTCP(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {1, 2, 3, 4}}, 300)
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(q)
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	// A 20-byte ceiling no real answer fits under.
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 20)
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	if !m.Header.Truncated {
		t.Fatal("over the client's buffer and not truncated")
	}
}

func TestNewRefusesWhatItCannotServe(t *testing.T) {
	base := func() Config {
		return Config{
			NFTTable: "inet fortress",
			NFT:      discardNFT{},
			// Not loopback: a loopback segment is allowed to carry no
			// nft set, so the "no set" case below would not refuse.
			Segments: []Segment{{
				IP: netip.MustParseAddr("10.77.0.1"), Iface: "eth1.20",
				Upstream: "127.0.0.1:53", NFTSet: "resolved_v4",
			}},
		}
	}
	cases := []struct {
		name string
		bend func(*Config)
	}{
		{"no segments", func(c *Config) { c.Segments = nil }},
		{"no table", func(c *Config) { c.NFTTable = "" }},
		{"no interface", func(c *Config) { c.Segments[0].Iface = "" }},
		{"no set", func(c *Config) { c.Segments[0].NFTSet = "" }},
		{"upstream without a port", func(c *Config) { c.Segments[0].Upstream = "127.0.0.1" }},
		// "addr@iface:port" pins the upstream to an interface (the
		// WireGuard house). The test checks both halves. With a bad half, the
		// socket would dial unbound and go out by the default route.
		{"an interface-pinned upstream whose address is a name", func(c *Config) { c.Segments[0].Upstream = "resolver.test@wg0:53" }},
		{"an interface-pinned upstream with no interface", func(c *Config) { c.Segments[0].Upstream = "10.64.0.1@:53" }},
		{"an interface-pinned upstream with a bad interface", func(c *Config) { c.Segments[0].Upstream = "10.64.0.1@wg0/x:53" }},
		{"no address to bind", func(c *Config) { c.Segments[0].IP = netip.Addr{} }},
		// A cached answer that lives longer than the set elements of its miss
		// would give out an address that the gate has already forgotten.
		{"a max ttl past the gate set timeout", func(c *Config) { c.MaxTTL = setTimeout + time.Second }},
		{"a negative max ttl", func(c *Config) { c.MaxTTL = -time.Second }},
		{"an interface named twice", func(c *Config) {
			// Field by field, not a copy of the struct. A Segment
			// has the atomically published list, and a copy of a
			// Segment copies a value that must not be copied.
			first := &c.Segments[0]
			c.Segments = append(c.Segments, Segment{
				Iface: first.Iface, IP: first.IP,
				Upstream: first.Upstream, NFTSet: first.NFTSet,
			})
		}},
		// DoT is both fields or neither. With half of it, a box
		// thinks that it encrypts, but it does not. That is worse than a
		// box that refuses to start.
		{"DoT addresses with no name", func(c *Config) {
			c.Segments[0].Upstream = ""
			c.Segments[0].DoTIPs = []netip.Addr{netip.MustParseAddr("9.9.9.9")}
		}},
		{"a DoT name with no addresses", func(c *Config) {
			c.Segments[0].Upstream = ""
			c.Segments[0].DoTName = "dns.quad9.net"
		}},
		{"DoT alongside a plaintext upstream", func(c *Config) {
			c.Segments[0].DoTName = "dns.quad9.net"
			c.Segments[0].DoTIPs = []netip.Addr{netip.MustParseAddr("9.9.9.9")}
		}},
		{"a DoT name that is not a DNS name", func(c *Config) {
			c.Segments[0].Upstream = ""
			c.Segments[0].DoTName = "9.9.9.9"
			c.Segments[0].DoTIPs = []netip.Addr{netip.MustParseAddr("9.9.9.9")}
		}},
		// The output chain pins v4 on 853. The box would dial a v6
		// upstream, and then its own ruleset would drop it.
		{"a DoT address that is not IPv4", func(c *Config) {
			c.Segments[0].Upstream = ""
			c.Segments[0].DoTName = "dns.quad9.net"
			c.Segments[0].DoTIPs = []netip.Addr{netip.MustParseAddr("2620:fe::fe")}
		}},
		{"a DoT address listed twice", func(c *Config) {
			c.Segments[0].Upstream = ""
			c.Segments[0].DoTName = "dns.quad9.net"
			c.Segments[0].DoTIPs = []netip.Addr{
				netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("9.9.9.9"),
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.bend(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// The stub segment answers the box itself and the house dnsmasq. That
// traffic never goes through the gate, so there is no set to feed. A
// demand for a set would make the segment impossible to configure.
// Every other segment must still name one, as the table above proves.
// The house runs on this daemon beside
// the agent. So two segments must pass New with nothing shared: each
// has a different interface, address, upstream, sinkhole list, nft set
// and log. The daemon has kept Segments as a slice since phase 1. But
// nothing ever built one with two entries that New must accept. The
// only two-segment case was the duplicate-interface refusal above. That
// case proves the check, not the capability.
//
// Two live segments need two real interfaces, so that
// assertion is in vm/itest against the Pi VM. This test pins the config
// plumbing that -check reports. An operator runs -check before an apply.
func TestNewTakesTwoSegmentsThatShareNothing(t *testing.T) {
	dir := t.TempDir()
	sink := func(name, line string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(line), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	agentSink := sink("blocked-domains.conf", "address=/blocked.test/0.0.0.0\n")
	houseSink := sink("house-domains.conf", "address=/ads.example/0.0.0.0\n")
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      discardNFT{},
		Segments: []Segment{{
			Iface: "eth1.20", IP: netip.MustParseAddr("10.77.0.1"),
			Upstream: "127.0.0.1:5301", SinkholeFiles: []string{agentSink},
			NFTSet: "resolved_v4", LogPath: filepath.Join(dir, "dns.jsonl"),
		}, {
			Name: "house", Iface: "eth1.78", IP: netip.MustParseAddr("10.78.0.1"),
			Upstream: "127.0.0.1:5302", SinkholeFiles: []string{houseSink},
			NFTSet: "resolved_house_v4", LogPath: filepath.Join(dir, "dns-house.jsonl"),
		}},
	})
	if err != nil {
		t.Fatalf("two segments refused: %v", err)
	}
	got := srv.Segments()
	if len(got) != 2 {
		t.Fatalf("-check reported %d segments: %q", len(got), got)
	}
	// Each line must describe its own segment. A set named twice is the
	// important failure: if the house feeds resolved_v4, the agent gate
	// opens for an address that only the house asked about.
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"eth1.20", "10.77.0.1", "resolved_v4",
		"eth1.78", "10.78.0.1", "resolved_house_v4",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("-check lost %q:\n%s", want, joined)
		}
	}
	if strings.Count(joined, "resolved_house_v4") != 1 {
		t.Fatalf("the house set is not reported exactly once:\n%s", joined)
	}
}

func TestNewTakesALoopbackSegmentWithNoSet(t *testing.T) {
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      discardNFT{},
		Segments: []Segment{{
			Name: "stub", IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo",
			Upstream: "9.9.9.9:53",
		}},
	})
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	got := srv.Segments()
	if len(got) != 1 || !strings.Contains(got[0], "set=-") {
		t.Fatalf("-check should show no set, got %q", got)
	}
}

// -check is the only thing an operator runs before an apply commits. So
// it must say which leg is in use. If not, a box that silently reverted
// to plaintext looks exactly like a box that did not.
func TestCheckSaysWhenTheUpstreamIsEncrypted(t *testing.T) {
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      discardNFT{},
		Segments: []Segment{{
			IP: netip.MustParseAddr("10.77.0.1"), Iface: "eth1.20",
			NFTSet: "resolved_v4", DoTName: "dns.quad9.net",
			DoTIPs: []netip.Addr{
				netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("149.112.112.112"),
			},
		}},
	})
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	got := srv.Segments()
	if len(got) != 1 || !strings.Contains(got[0], "upstream=dot:dns.quad9.net(2)") {
		t.Fatalf("-check should name the DoT upstream, got %q", got)
	}
}

func TestReloadRereadsTheList(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"late.test": {1, 2, 3, 4}}, 300)
	h.ask(t, "late.test", dnsmessage.TypeA)
	if h.up.asked.Load() != 1 {
		t.Fatal("not forwarded before the list named it")
	}
	path := h.srv.segs[0].SinkholeFiles[0]
	if err := os.WriteFile(path, []byte("address=/late.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	_, answers := h.ask(t, "late.test", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "0.0.0.0" {
		t.Fatalf("after reload %q, want the sinkhole", got)
	}
	if h.up.asked.Load() != 1 {
		t.Fatal("forwarded after the list named it")
	}
}

// FuzzAnswer: arbitrary bytes on the wire never panic, and never produce
// a reply that is not a response to the id that was asked.
func FuzzAnswer(f *testing.F) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	seed, _ := b.Finish()
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, req []byte) {
		h := fuzzServer(t)
		msg := h.answer(context.Background(), h.segs[0], netip.MustParseAddr("10.77.0.10"), req, 512)
		if msg == nil {
			return
		}
		if len(msg) < 12 {
			t.Fatalf("reply of %d bytes", len(msg))
		}
		if msg[0] != req[0] || msg[1] != req[1] {
			t.Fatalf("reply id %x%x, asked %x%x", msg[0], msg[1], req[0], req[1])
		}
		if msg[2]&0x80 == 0 {
			t.Fatal("reply is not marked as a response")
		}
		var m dnsmessage.Message
		if err := m.Unpack(msg); err != nil {
			t.Fatalf("wrote a message it cannot parse: %v", err)
		}
	})
}

var fuzzOnce sync.Once
var fuzzSrv *Server

func fuzzServer(t *testing.T) *Server {
	fuzzOnce.Do(func() {
		s, err := New(Config{
			NFTTable: "inet fortress",
			NFT:      discardNFT{},
			Now:      time.Now,
			Segments: []Segment{{
				IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo",
				// Nothing listens there, so a forward fails fast and the
				// fuzzer stays on the paths that do not need a network.
				Upstream: "127.0.0.1:1", NFTSet: "resolved_v4",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		fuzzSrv = s
	})
	return fuzzSrv
}

// An address= line with a real address is a local answer, not a
// sinkhole. The lab fixtures are such lines. An answer of 0.0.0.0 for
// them would be a silent difference from dnsmasq.
func TestAddressLineWithARealAddressIsAnswered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixtures.conf")
	body := "address=/pf-open-echo.test/192.0.2.3\n" +
		"address=/webhook.site/0.0.0.0\n" +
		"address=/broken.test/not-an-address\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, map[string][4]byte{}, nil, 300)
	nft := &fakeNFT{}
	srv, err := New(Config{
		NFTTable: "inet fortress", NFT: nft, Now: time.Now,
		Segments: []Segment{{
			IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo",
			Upstream: up.addr(), SinkholeFiles: []string{path},
			NFTSet: "resolved_v4", LogPath: filepath.Join(dir, "dns.jsonl"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	h := &harness{srv: srv, nft: nft, up: up, log: filepath.Join(dir, "dns.jsonl")}

	_, answers := h.ask(t, "pf-open-echo.test", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "192.0.2.3" {
		t.Fatalf("fixture answered %q, want its configured address", got)
	}
	// The answer told a client to connect to that address, so the gate must
	// already hold it.
	if got := h.nft.flat(); len(got) != 1 || got[0] != "192.0.2.3" {
		t.Fatalf("nft %v, want the fixture address in the set", got)
	}
	if h.up.asked.Load() != 0 {
		t.Fatal("a configured name reached the upstream")
	}

	_, answers = h.ask(t, "webhook.site", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "0.0.0.0" {
		t.Fatalf("sinkhole answered %q", got)
	}
	// A malformed value must sinkhole, never resolve: a block that
	// cannot be read has to fail shut.
	_, answers = h.ask(t, "broken.test", dnsmessage.TypeA)
	if got := firstA(t, answers); got != "0.0.0.0" {
		t.Fatalf("an unreadable address= value answered %q, want the sinkhole", got)
	}
	if n := h.nft.calls.Load(); n != 1 {
		t.Fatalf("nft called %d times; only the real address belongs in the set", n)
	}
	// The two sinkholes state the verdict. The address= line with a real
	// address does not: the row writes "resolved". The row says what occurred
	// to the query, and no word in the vocabulary says
	// "this came out of a config file rather than the upstream". The
	// text shape had that in its config verb. Nothing reads that data (observe
	// counts a sinkhole by ActBlocked). Thus this comment records the loss.
	// The code does not add a new verdict for it.
	var blocked, resolved int
	for _, r := range h.logLines(t) {
		switch r.Act {
		case dnslog.ActBlocked:
			blocked++
		case dnslog.ActResolved:
			resolved++
			if r.Name != "pf-open-echo.test" || r.Answer != "192.0.2.3" {
				t.Fatalf("only the real address= line resolves: %+v", r)
			}
		default:
			t.Fatalf("unexpected verdict %q: %+v", r.Act, r)
		}
	}
	if blocked != 2 || resolved != 1 {
		t.Fatalf("%d blocked %d resolved, want both sinkholes blocked", blocked, resolved)
	}
}

// setTimeout is a copy of what the ruleset renders. It is here because
// dnsd and render share no import. If the set timeout changes there and
// this value does not, New accepts a max ttl that the gate cannot back.
func TestSetTimeoutMatchesTheRenderedSets(t *testing.T) {
	src, err := os.ReadFile("../render/ruleset.go")
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`flags timeout(?:\\n|\s)+timeout ([0-9][0-9a-z]*)`).FindAllSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("no timeout set in the ruleset")
	}
	for _, m := range found {
		d, err := time.ParseDuration(string(m[1]))
		if err != nil {
			t.Fatalf("set timeout %q: %v", m[1], err)
		}
		if d != setTimeout {
			t.Errorf("ruleset set timeout %v, dnsd assumes %v", d, setTimeout)
		}
	}
}
