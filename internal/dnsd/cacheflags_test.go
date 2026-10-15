package dnsd

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The cache key is segment, name and type. CD, DO and EDNS options are not
// in it (cache.go). That is correct only while none of them gets to the
// upstream, so the answer cannot depend on them. These tests use an
// upstream that does answer by flags (byFlags). If CD, DO or an option
// ever leaked into canonicalQuery, the flagged address (last octet + 62)
// would come back.
// Then the first client to ask would decide what the rest of the segment
// gets.

var plainA = [4]byte{1, 2, 3, 4}

// askerFlagged is what byFlags answers by: CD in the header, DO in the
// OPT, or any option in the OPT's rdata.
func askerFlagged(req []byte) bool {
	if len(req) >= 4 && req[3]&0x10 != 0 {
		return true
	}
	present, do, opts := optOf(req)
	return present && (do || opts > 0)
}

// optOf reads a message's OPT record: whether it has one, its DO bit, and
// how many options it carries.
func optOf(msg []byte) (present, do bool, opts int) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false, false, 0
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false, false, 0
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return false, false, 0
		}
		if h.Type != dnsmessage.TypeOPT {
			if p.SkipAdditional() != nil {
				return false, false, 0
			}
			continue
		}
		r, err := p.OPTResource()
		if err != nil {
			return true, h.DNSSECAllowed(), -1
		}
		return true, h.DNSSECAllowed(), len(r.Options)
	}
}

func withCD(req []byte) []byte {
	out := append([]byte(nil), req...)
	out[3] |= 0x10
	return out
}

// withECS appends an OPT with an EDNS Client Subnet option (RFC 7871,
// code 8) for the /24 that the caller names.
func withECS(req []byte, subnet [3]byte) []byte {
	out := append([]byte(nil), req...)
	opt := []byte{0, 8, 0, 7, 0, 1, 24, 0, subnet[0], subnet[1], subnet[2]}
	rr := []byte{0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, byte(len(opt))}
	out = append(append(out, rr...), opt...)
	binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(out[10:12])+1)
	return out
}

// replyA is the single A address in resp.
func replyA(t *testing.T, resp []byte) [4]byte {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for _, r := range m.Answers {
		if a, ok := r.Body.(*dnsmessage.AResource); ok {
			return a.A
		}
	}
	t.Fatalf("no A in %+v", m.Answers)
	return [4]byte{}
}

// flagPair asks first and then second for the same name on one segment,
// against an upstream that answers by flags. Both must get the plain
// answer from one upstream exchange. The second is a cache hit. The flags
// of neither caller decided what went into the entry.
func flagPair(t *testing.T, first, second []byte) (r1, r2 []byte) {
	t.Helper()
	h := newHarness(t, nil, map[string][4]byte{"a.test": plainA}, 60)
	h.up.byFlags.Store(true)
	r1 = h.raw(t, first)
	r2 = h.raw(t, second)
	if n := h.up.asked.Load(); n != 1 {
		t.Fatalf("upstream asked %d times, want 1 (the second must be a cache hit)", n)
	}
	if askerFlagged(h.up.lastQuery(t)) {
		t.Fatal("a client's CD, DO or EDNS option reached the upstream query")
	}
	for i, r := range [][]byte{r1, r2} {
		if got := replyA(t, r); got != plainA {
			t.Fatalf("caller %d got %v, want %v: the answer followed the asker's flags", i+1, got, plainA)
		}
	}
	return r1, r2
}

func TestCacheCDAnswerIsNotServedToAPlainClient(t *testing.T) {
	t.Run("cd first", func(t *testing.T) {
		flagPair(t, withCD(query(t, "a.test")), query(t, "a.test"))
	})
	t.Run("plain first", func(t *testing.T) {
		flagPair(t, query(t, "a.test"), withCD(query(t, "a.test")))
	})
}

func TestCacheDOAnswerIsNotServedToAPlainClient(t *testing.T) {
	check := func(t *testing.T, first, second []byte) {
		t.Helper()
		r1, r2 := flagPair(t, first, second)
		// DO is off on each answer. Nothing here asked for RRSIGs, so the message
		// has none to flag.
		for i, r := range [][]byte{r1, r2} {
			if _, do, _ := optOf(r); do {
				t.Fatalf("caller %d: DO set on an answer fetched without DO", i+1)
			}
		}
	}
	t.Run("do first", func(t *testing.T) {
		check(t, withOPT(t, query(t, "a.test"), 1232, 0, true), query(t, "a.test"))
	})
	t.Run("plain first", func(t *testing.T) {
		check(t, query(t, "a.test"), withOPT(t, query(t, "a.test"), 1232, 0, true))
	})
}

// The resolver drops ECS. It does not forward it and does not key on it.
// An answer made for the subnet of one client must not get to another
// client. The upstream must not get the subnet of a LAN client. The caller
// also gets no ECS option back. RFC 7871 section 7.2.1 reads this as
// "not used".
func TestCacheECSIsDroppedNotKeyed(t *testing.T) {
	a := withECS(query(t, "a.test"), [3]byte{203, 0, 113})
	b := withECS(query(t, "a.test"), [3]byte{198, 51, 100})
	for _, tc := range []struct {
		name          string
		first, second []byte
	}{
		{"subnet then subnet", a, b},
		{"subnet then plain", a, query(t, "a.test")},
		{"plain then subnet", query(t, "a.test"), b},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r1, r2 := flagPair(t, tc.first, tc.second)
			for i, r := range [][]byte{r1, r2} {
				if present, _, opts := optOf(r); present && opts != 0 {
					t.Fatalf("caller %d: reply carries %d EDNS options, want none", i+1, opts)
				}
			}
		})
	}
}
