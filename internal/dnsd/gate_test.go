package dnsd

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// refreshNFT is fakeNFT that can also restart the timeout of an
// element, as gateset.Cmd does. A test can make only that restart fail.
type refreshNFT struct {
	fakeNFT
	rmu       sync.Mutex
	refreshed [][]netip.Addr
	rfail     error
}

func (f *refreshNFT) Refresh(set string, addrs []netip.Addr) error {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	if f.rfail != nil {
		return f.rfail
	}
	f.refreshed = append(f.refreshed, addrs)
	return nil
}

func (f *refreshNFT) refreshes() int {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	return len(f.refreshed)
}

// gateBox is one segment whose clock the test moves, an upstream with an
// hour's TTL, and the writer the test chooses.
type gateBox struct {
	srv *Server
	up  *upstream
	clk *volClock
}

type volClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *volClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *volClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newGateBox(t *testing.T, nft NFTWriter, name string, table map[string][4]byte) *gateBox {
	t.Helper()
	up := newUpstream(t, table, nil, 3600)
	clk := &volClock{t: time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)}
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      nft,
		Now:      clk.now,
		Segments: []Segment{{Name: name, Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: up.addr(), NFTSet: "resolved_v4"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.logf = func(string, ...any) {}
	return &gateBox{srv: srv, up: up, clk: clk}
}

// askMsg asks name A as the client spelt it and returns the whole reply.
func (g *gateBox) askMsg(t *testing.T, name string) dnsmessage.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := g.srv.answer(ctx, g.srv.segs[0], netip.MustParseAddr("10.78.0.20"), query(t, name), 0)
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

func minTTL(m dnsmessage.Message) uint32 {
	ttl := ^uint32(0)
	for _, a := range m.Answers {
		ttl = min(ttl, a.Header.TTL)
	}
	return ttl
}

// The client connection needs the gate set element that an answer
// opened. An add of an element that is already there does not restart
// its timeout. An address can resolve first through one name, and then,
// near the end of its two hours, through a different name. In the past,
// the resolver cached that answer and gave it out for the full hour of
// the second name after the element had gone. The gate then dropped the
// connections that the answer invited. The second answer now lives no
// longer than the element.
func TestAnAnswerDoesNotOutliveItsGateElement(t *testing.T) {
	g := newGateBox(t, &fakeNFT{}, "house", map[string][4]byte{"a.test": {93, 184, 216, 34}, "b.test": {93, 184, 216, 34}})
	if ttl := minTTL(g.askMsg(t, "a.test")); ttl != 3600 {
		t.Fatalf("a fresh element: ttl %d, want the record's 3600", ttl)
	}
	g.clk.add(setTimeout - time.Minute)
	if ttl := minTTL(g.askMsg(t, "b.test")); ttl > 60 {
		t.Fatalf("an element with a minute left handed out for %ds", ttl)
	}
	g.clk.add(30 * time.Second)
	if ttl := minTTL(g.askMsg(t, "b.test")); ttl > 30 {
		t.Fatalf("a cache hit handed out %ds against 30s left", ttl)
	}
	asked := g.up.asked.Load()
	g.clk.add(31 * time.Second)
	if ttl := minTTL(g.askMsg(t, "b.test")); ttl != 3600 {
		t.Fatalf("after the element expired and was written again: ttl %d", ttl)
	}
	if g.up.asked.Load() != asked+1 {
		t.Fatal("the answer was served from the cache after its element expired")
	}
}

// The resolver asks a writer that can restart the timeout of an element
// to do so in two cases. One: the element has less than the longest
// cache life left. Two: this process never wrote it (a restart, or the
// nftsets carry over an apply, leaves elements with an unknown time on
// them). If a refresh fails, the resolver uses the plain add and keeps
// the answers for an unknown element short.
func TestAShortLivedOrUnknownElementIsRefreshed(t *testing.T) {
	table := map[string][4]byte{"a.test": {93, 184, 216, 34}, "b.test": {93, 184, 216, 34}}
	nft := &refreshNFT{}
	g := newGateBox(t, nft, "house", table)
	g.askMsg(t, "a.test")
	if nft.refreshes() != 1 {
		t.Fatalf("an element this process never wrote was refreshed %d times", nft.refreshes())
	}
	g.clk.add(time.Hour)
	if g.askMsg(t, "b.test"); nft.refreshes() != 1 {
		t.Fatal("an element with an hour left was refreshed")
	}
	g.clk.add(30 * time.Minute)
	if ttl := minTTL(g.askMsg(t, "a.test")); ttl != 3600 || nft.refreshes() != 2 {
		t.Fatalf("half an hour left: ttl %d after %d refreshes, want 3600 after 2", ttl, nft.refreshes())
	}

	bad := &refreshNFT{rfail: errors.New("nft: no such file or directory")}
	g = newGateBox(t, bad, "house", table)
	if ttl := minTTL(g.askMsg(t, "a.test")); ttl > unknownLeft {
		t.Fatalf("an unknown element whose refresh failed handed out %ds", ttl)
	}
	if n := len(bad.flat()); n != 1 {
		t.Fatalf("the failed refresh did not fall back to the add: %d writes", n)
	}
}

// In the past, a cache hit gave back the spelling of the name from the
// first asker. A stub that randomises the case of its question (0x20)
// drops an answer whose question does not match its own. So on a
// segment that answers with the message of the upstream and does not
// rebuild it (the house), the hit has the spelling of the asker.
func TestACacheHitAnswersInTheAskersCase(t *testing.T) {
	g := newGateBox(t, &fakeNFT{}, "house", map[string][4]byte{"ExAmPlE.TeSt": {93, 184, 216, 34}})
	first := g.askMsg(t, "ExAmPlE.TeSt")
	if got := first.Questions[0].Name.String(); got != "ExAmPlE.TeSt." {
		t.Fatalf("miss: question %s", got)
	}
	asked := g.up.asked.Load()
	hit := g.askMsg(t, "eXaMpLe.tEsT")
	if g.up.asked.Load() != asked {
		t.Fatal("the second spelling was not a cache hit")
	}
	if got := hit.Questions[0].Name.String(); got != "eXaMpLe.tEsT." {
		t.Fatalf("hit: question %s, want the asker's eXaMpLe.tEsT.", got)
	}
	if got := hit.Answers[0].Header.Name.String(); got != "eXaMpLe.tEsT." {
		t.Fatalf("hit: answer owner %s", got)
	}
}

func TestAskersCaseRewritesOnlyACaseFold(t *testing.T) {
	mk := func(name string) []byte { return query(t, name) }
	for _, c := range []struct {
		stored, asked, want string
	}{
		{"example.test", "EXAMPLE.test", "EXAMPLE.test."},
		{"example.test", "examplf.test", "example.test."},
		{"a-b.test", "a-B.test", "a-B.test."},
		{"a.test", "ab.test", "a.test."},
	} {
		msg := mk(c.stored)
		askersCase(msg, mk(c.asked))
		var p dnsmessage.Parser
		if _, err := p.Start(msg); err != nil {
			t.Fatal(err)
		}
		q, err := p.Question()
		if err != nil {
			t.Fatal(err)
		}
		if got := q.Name.String(); got != c.want {
			t.Errorf("%s asked as %s: %s, want %s", c.stored, c.asked, got, c.want)
		}
	}
}

// setTimeout is the resolved_* timeout of render, written down a second
// time. The gate element life is what every answer is cut to fit. The
// test reads it from the render source, so the two cannot become
// different without notice. render declares each resolved set with
// resolvedSet: the agent's, the house's and the one of each segment.
func TestSetTimeoutIsRendersSetTimeout(t *testing.T) {
	src, err := os.ReadFile("../render/ruleset.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`func resolvedSet\(name string\) string \{\s*return "  set " \+ name \+ " \{\\n    type ipv4_addr\\n    size " \+ [^"]+"\\n    flags timeout\\n    timeout (\w+)\\n  \}"`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("no resolvedSet declaration with a timeout in render")
	}
	if d, err := time.ParseDuration(m[1]); err != nil || d != setTimeout {
		t.Errorf("render gives the resolved sets a timeout of %s; dnsd assumes %s", m[1], setTimeout)
	}
	for _, use := range []string{`resolvedSet("resolved_v4")`, `resolvedSet("resolved_house_v4")`, `resolvedSet(set)`} {
		if !strings.Contains(string(src), use) {
			t.Errorf("render does not declare a resolved set with %s", use)
		}
	}
	if n := strings.Count(string(src), "flags timeout"); n != 1 {
		t.Errorf("render has %d sets with flags timeout, want only resolvedSet", n)
	}
}
