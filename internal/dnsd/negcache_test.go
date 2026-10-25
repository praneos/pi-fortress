package dnsd

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// negReply is an upstream reply with no answer records. soa adds one SOA
// record to the authority section, with that record TTL and that MINIMUM.
func negReply(t *testing.T, req []byte, rcode dnsmessage.RCode, soa bool, soaTTL, minimum uint32) []byte {
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
	b := newBuilder(hdr, q, rcode)
	if b == nil {
		t.Fatal("no builder")
	}
	if soa {
		if err := b.StartAuthorities(); err != nil {
			t.Fatal(err)
		}
		err := b.SOAResource(
			dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("test."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: soaTTL},
			dnsmessage.SOAResource{
				NS: dnsmessage.MustNewName("ns.test."), MBox: dnsmessage.MustNewName("admin.test."),
				Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: minimum,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// negHarness gives each query the reply that mk makes, with a clock the
// test winds.
func negHarness(t *testing.T, mk func(req []byte) []byte) (*harness, *rawUpstream, *testClock) {
	t.Helper()
	clk := newTestClock()
	up := newRawUpstream(t, func(req []byte) [][]byte { return [][]byte{mk(req)} })
	return clockHarness(t, nil, up.addr(), clk), up, clk
}

func (h *harness) askRaw(t *testing.T, name string, qt dnsmessage.Type) *dnsmessage.Message {
	t.Helper()
	msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), wire(t, name, qt, 0x2222), 0)
	if msg == nil {
		t.Fatal("no reply")
	}
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	return &m
}

// The negative TTL is the smaller of the SOA record TTL and its MINIMUM
// (RFC 2308 section 5), and never more than five minutes.
func TestANegativeAnswerIsCachedForItsSOAMinimum(t *testing.T) {
	cases := []struct {
		name        string
		rcode       dnsmessage.RCode
		qt          dnsmessage.Type
		soaTTL, min uint32
		want        time.Duration
	}{
		{"nxdomain, minimum is smaller", dnsmessage.RCodeNameError, dnsmessage.TypeA, 600, 60, 60 * time.Second},
		{"nxdomain, soa ttl is smaller", dnsmessage.RCodeNameError, dnsmessage.TypeA, 30, 3600, 30 * time.Second},
		{"nxdomain, both over the cap", dnsmessage.RCodeNameError, dnsmessage.TypeA, 86400, 86400, 300 * time.Second},
		{"nodata", dnsmessage.RCodeSuccess, dnsmessage.TypeA, 900, 120, 120 * time.Second},
		{"nodata for mx", dnsmessage.RCodeSuccess, dnsmessage.TypeMX, 900, 120, 120 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, up, clk := negHarness(t, func(req []byte) []byte { return negReply(t, req, c.rcode, true, c.soaTTL, c.min) })
			m := h.askRaw(t, "nothing.example.org", c.qt)
			if m.RCode != c.rcode || len(m.Answers) != 0 {
				t.Fatalf("first reply: rcode %v, %d answers", m.RCode, len(m.Answers))
			}
			clk.advance(c.want - time.Second)
			m = h.askRaw(t, "nothing.example.org", c.qt)
			if n := up.count(); n != 1 {
				t.Fatalf("upstream asked %d times inside the negative TTL, want 1", n)
			}
			if m.RCode != c.rcode || len(m.Answers) != 0 || len(m.Authorities) != 1 {
				t.Fatalf("cached reply: rcode %v, %d answers, %d authorities", m.RCode, len(m.Answers), len(m.Authorities))
			}
			// The client gets the time that the entry has left, so it does not
			// keep the answer longer than this cache does.
			if got := m.Authorities[0].Header.TTL; got != 1 {
				t.Fatalf("cached SOA TTL %d, want 1", got)
			}
			clk.advance(time.Second)
			h.askRaw(t, "nothing.example.org", c.qt)
			if n := up.count(); n != 2 {
				t.Fatalf("upstream asked %d times after the negative TTL, want 2", n)
			}
		})
	}
}

// Without an SOA, the reply gives no negative TTL, so it is not cached.
// Other rcodes are failures, not answers, and are not cached either.
func TestANegativeAnswerWithoutTTLIsNotCached(t *testing.T) {
	cases := []struct {
		name  string
		rcode dnsmessage.RCode
		soa   bool
		min   uint32
	}{
		{"nxdomain without soa", dnsmessage.RCodeNameError, false, 0},
		{"nodata without soa", dnsmessage.RCodeSuccess, false, 0},
		{"minimum of zero", dnsmessage.RCodeNameError, true, 0},
		{"servfail with soa", dnsmessage.RCodeServerFailure, true, 60},
		{"refused with soa", dnsmessage.RCodeRefused, true, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, up, _ := negHarness(t, func(req []byte) []byte { return negReply(t, req, c.rcode, c.soa, 600, c.min) })
			h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
			h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
			if n := up.count(); n != 2 {
				t.Fatalf("upstream asked %d times, want 2: the reply was cached", n)
			}
		})
	}
}

// A truncated negative reply is a stub, as a truncated positive one is.
func TestATruncatedNegativeAnswerIsNotCached(t *testing.T) {
	h, up, _ := negHarness(t, func(req []byte) []byte {
		msg := negReply(t, req, dnsmessage.RCodeNameError, true, 600, 60)
		msg[2] |= 0x02
		return msg
	})
	h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
	h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
	if n := up.count(); n != 2 {
		t.Fatalf("upstream asked %d times, want 2: a truncated reply was cached", n)
	}
}

// A negative answer adds no element to a gate set, and the entry does not
// live longer than MaxTTL.
func TestANegativeAnswerAddsNoGateElement(t *testing.T) {
	h, up, clk := negHarness(t, func(req []byte) []byte { return negReply(t, req, dnsmessage.RCodeNameError, true, 600, 60) })
	h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
	clk.advance(30 * time.Second)
	h.askRaw(t, "nothing.example.org", dnsmessage.TypeA)
	if n := up.count(); n != 1 {
		t.Fatalf("upstream asked %d times, want 1", n)
	}
	if n := h.nft.calls.Load(); n != 0 {
		t.Fatalf("%d gate set writes for a negative answer, want 0", n)
	}
}

func TestNegTTL(t *testing.T) {
	req := wire(t, "nothing.example.org", dnsmessage.TypeA, 1)
	if got, ok := negTTL(negReply(t, req, dnsmessage.RCodeNameError, true, 600, 60)); !ok || got != 60 {
		t.Fatalf("negTTL = %d, %v; want 60, true", got, ok)
	}
	// An answer section with a record is a positive answer.
	pos := aliasAnswer(t, req, "nothing.example.org", "target.test", [4]byte{1, 2, 3, 4}, 60, 60)
	if _, ok := negTTL(pos); ok {
		t.Fatal("negTTL accepted a positive answer")
	}
	if _, ok := negTTL([]byte{1, 2, 3}); ok {
		t.Fatal("negTTL accepted a short message")
	}
}
