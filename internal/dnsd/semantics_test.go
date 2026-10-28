package dnsd

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// raw sends bytes the caller built and returns the response bytes, so a
// test can put EDNS options on a query that `ask` does not write.
func (h *harness) raw(t *testing.T, req []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := h.srv.answer(ctx, h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
	if resp == nil {
		t.Fatal("no reply")
	}
	return resp
}

// Before, the request went to the upstream as the client wrote it. Thus
// the answer was for that client: DO=1 brought RRSIGs back, and CD=1
// brought back data that nobody validated. The cache, with a key of name
// and qtype, then served it to the next caller on the segment. This did
// no harm while each client was a dnsmasq that sent the same flags. It
// did harm after dnsmasq went to port=0 and the clients became ordinary
// OS resolvers that ask this daemon directly.
func TestTheQuestionUpstreamIsOursNotTheClients(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"a.test": {1, 2, 3, 4}}, 60)

	h.raw(t, withOPT(t, query(t, "a.test"), 1232, 0, true))
	up := h.up.lastQuery(t)
	if e := clientEDNS(up); !e.present {
		t.Fatal("the question upstream lost EDNS entirely")
	} else if e.do {
		t.Fatal("the client's DO bit went upstream, so its answer is in the cache for everyone")
	} else if e.size != udpMax {
		t.Fatalf("upstream buffer %d, want our own %d: a small client must not shrink the cached answer", e.size, udpMax)
	}
	// Checking Disabled belongs to the client, not to us. The cache must not
	// keep an unvalidated answer under an ordinary question.
	if len(up) >= 4 && up[3]&0x10 != 0 {
		t.Fatal("the client's CD bit went upstream")
	}
	// This resolver rerolls the id for each exchange, so the client cannot
	// select the id that this resolver uses on the wire.
	if len(up) >= 2 && up[0] == 0x42 && up[1] == 0x42 {
		t.Fatal("the client's transaction id went upstream verbatim")
	}
}

// The OPT record belongs to one hop. A client that asked without EDNS
// must not get an OPT back from an entry that an EDNS client filled. A
// client that asked with EDNS must get the buffer of this resolver.
func TestTheCachedAnswerCarriesNoOnesOPTButTheCallers(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"a.test": {1, 2, 3, 4}}, 60)

	// An EDNS client fills the entry.
	first := h.raw(t, withOPT(t, query(t, "a.test"), 1232, 0, true))
	if e := clientEDNS(first); !e.present {
		t.Fatal("an EDNS caller was answered without an OPT record")
	} else if e.do {
		t.Fatal("DO is set on an answer this resolver did not ask for with DO")
	}
	// A plain client reads the same entry.
	second := h.raw(t, query(t, "a.test"))
	if h.up.asked.Load() != 1 {
		t.Fatalf("upstream asked %d times, want 1: the second query was not a cache hit", h.up.asked.Load())
	}
	if clientEDNS(second).present {
		t.Fatal("a caller that asked without EDNS was handed the other caller's OPT record")
	}
	if len(second) < 12 || second[10] != 0 || second[11] != 0 {
		t.Fatalf("ARCOUNT %d, want 0 with no OPT", uint16(second[10])<<8|uint16(second[11]))
	}
	// The answer itself survived the rewrite.
	var m dnsmessage.Message
	if err := m.Unpack(second); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers %+v", m.Answers)
	}
}

// stripOPT refuses, and does not guess, when the OPT is not last. If it
// removes bytes from the middle, each offset after them moves. A
// compression pointer in a later record then still points to the old
// location of the name.
func TestStripOPTRefusesAnOPTThatIsNotLast(t *testing.T) {
	msg := withOPT(t, query(t, "a.test"), 1232, 0, false)
	if _, ok := stripOPT(msg); !ok {
		t.Fatal("an OPT at the end was not stripped")
	}
	trailing := append(append([]byte(nil), msg...), 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4)
	trailing[11] = 2
	if _, ok := stripOPT(trailing); ok {
		t.Fatal("an OPT with a record behind it was stripped anyway")
	}
}

// A CNAME whose target reads into the OPT bytes parses while the OPT is
// there. After the cut, the target is past the end, and no client can
// read the message. stripOPT refuses it, so the cache does not keep it.
func TestStripOPTRefusesANameThatReadsIntoTheOPT(t *testing.T) {
	for name, rdata := range map[string][]byte{
		// The label "b" ends with the root byte of the OPT name.
		"label runs past rdlength": {1, 'b'},
		// A pointer to the OPT name at offset 38.
		"pointer forward to the OPT": {0xC0, 38},
	} {
		msg := []byte{0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1,
			1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1, // a.test A IN
			0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2} // CNAME, rdlength 2
		msg = append(msg, rdata...)
		msg = append(msg, 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0) // OPT at 38
		if !readable(msg) {
			t.Fatalf("%s: the fixture does not parse with its OPT", name)
		}
		if out, ok := stripOPT(msg); ok {
			t.Errorf("%s: stripped to %x, which does not parse", name, out)
		}
	}
}

// A message with no OPT at all goes through without a change. There is
// nothing to remove.
func TestStripOPTLeavesAMessageWithoutOne(t *testing.T) {
	msg := query(t, "a.test")
	out, ok := stripOPT(msg)
	if !ok {
		t.Fatal("a message with no OPT was refused")
	}
	if string(out) != string(msg) {
		t.Fatal("a message with no OPT was rewritten")
	}
}

// An A record with an RDLENGTH other than 4 is refused. The parser reads
// 4 bytes as the address and then steps over RDLENGTH bytes. With
// RDLENGTH 0, the address is the first 4 bytes of the next record, which
// is not the rdata of any record. The input is a fuzz input: six A
// records with RDLENGTH 0 and no question.
func TestARecordsRefusesAnRDLengthOtherThan4(t *testing.T) {
	rr := func(rdata ...byte) []byte {
		return append([]byte{0, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, byte(len(rdata))}, rdata...)
	}
	head := func(an int) []byte { return []byte{0, 7, 0x81, 0x80, 0, 0, 0, byte(an), 0, 0, 0, 0} }
	msg := head(6)
	for range 6 {
		msg = append(msg, rr()...)
	}
	msg = append(msg, 0x5d, 0xb8, 0xd8, 0x22)
	if addrs, _, ok := aRecords(msg); ok {
		t.Fatalf("six A records with RDLENGTH 0 gave %v", addrs)
	}
	if got := answerOf(msg); got != "NODATA" {
		t.Fatalf("answerOf logs %q for an A record with RDLENGTH 0", got)
	}
	for _, n := range []int{0, 2, 3, 5, 8} {
		rdata := make([]byte, n)
		msg := append(append(head(2), rr(rdata...)...), rr(1, 2, 3, 4)...)
		if addrs, _, ok := aRecords(msg); ok {
			t.Errorf("RDLENGTH %d: gave %v", n, addrs)
		}
	}
	msg = append(append(head(2), rr(9, 9, 9, 9)...), rr(1, 2, 3, 4)...)
	addrs, _, ok := aRecords(msg)
	if !ok || len(addrs) != 2 || addrs[0].String() != "9.9.9.9" || addrs[1].String() != "1.2.3.4" {
		t.Fatalf("two good A records: %v %v", addrs, ok)
	}
}
