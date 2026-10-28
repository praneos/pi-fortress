package dnsd

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// FuzzUpstreamReply gives the helpers that read an upstream reply bytes
// that the upstream chose. FuzzAnswer never reaches them, because its
// upstream is a closed port. The test fails if a helper panics, or if:
//
//   - rrTTLs, chainNames or aRecords return more items than the message
//     has room for;
//   - negTTL gives a TTL over maxNegTTL, or accepts a reply with an
//     address;
//   - aRecords accepts an A record whose RDLENGTH is not 4;
//   - aRecords gives an address whose owner name chainNames does not give.
//     The forwarder judges the names of chainNames and admits the
//     addresses of aRecords, so an owner outside that list is an address
//     that no policy saw;
//   - ageTTLs changes the length or a byte that is not a TTL, or raises a
//     TTL;
//   - askersCase changes the length, or a byte outside the question name,
//     or a byte other than by ASCII letter case;
//   - stripOPT accepts a message that dnsmessage parses, and dnsmessage
//     cannot parse the result, or the result still has an OPT;
//   - withCallerOPT changes a message for a caller without EDNS, or makes
//     a whole message that dnsmessage cannot parse.
func FuzzUpstreamReply(f *testing.F) {
	for _, s := range upstreamSeeds(f) {
		f.Add(s[0], s[1], uint32(30))
	}
	f.Add([]byte{}, []byte{}, uint32(0))
	f.Add(make([]byte, 12), make([]byte, 12), uint32(1))
	f.Fuzz(func(t *testing.T, req, reply []byte, ageSecs uint32) {
		orig := bytes.Clone(reply)
		_ = answerOf(reply)

		offs, ttlOK := rrTTLs(reply)
		if len(offs) > len(reply)/11 {
			t.Fatalf("rrTTLs: %d records in %d bytes", len(offs), len(reply))
		}
		names, namesOK := chainNames(reply)
		if len(names) > 2*len(reply)/11 {
			t.Fatalf("chainNames: %d names in %d bytes", len(names), len(reply))
		}
		addrs, _, addrsOK := aRecords(reply)
		if len(addrs) > len(reply)/15 {
			t.Fatalf("aRecords: %d addresses in %d bytes", len(addrs), len(reply))
		}
		if namesOK && addrsOK {
			judged := map[string]bool{}
			for _, n := range names {
				judged[n] = true
			}
			for _, o := range aOwners(reply) {
				if o != "" && !judged[o] {
					t.Fatalf("address of %q is not in the chain %q", o, names)
				}
			}
		}
		if addrsOK {
			for _, n := range aLengths(reply) {
				if n != 4 {
					t.Fatalf("aRecords accepted an A record with RDLENGTH %d", n)
				}
			}
		}
		// negTTL: a negative answer only, and never over the cap.
		if neg, ok := negTTL(reply); ok {
			if neg > maxNegTTL {
				t.Fatalf("negTTL: %d, over the cap %d", neg, maxNegTTL)
			}
			if addrsOK && len(addrs) > 0 {
				t.Fatalf("negTTL accepted a reply with %d addresses", len(addrs))
			}
		}
		if !bytes.Equal(reply, orig) {
			t.Fatal("a reader changed the message")
		}

		// ageTTLs: a copy of the same length, only TTLs change, and only down.
		aged := ageTTLs(reply, time.Duration(ageSecs)*time.Second)
		if len(aged) != len(reply) {
			t.Fatalf("ageTTLs: %d bytes, was %d", len(aged), len(reply))
		}
		isTTL := make([]bool, len(reply))
		if ttlOK {
			for _, o := range offs {
				for k := o; k < o+4; k++ {
					isTTL[k] = true
				}
				if binary.BigEndian.Uint32(aged[o:]) > binary.BigEndian.Uint32(reply[o:]) {
					t.Fatalf("ageTTLs raised the TTL at %d", o)
				}
			}
		}
		for k := range aged {
			if !isTTL[k] && aged[k] != reply[k] {
				t.Fatalf("ageTTLs changed byte %d, which is not a TTL", k)
			}
		}
		if !bytes.Equal(reply, orig) {
			t.Fatal("ageTTLs changed its input")
		}

		// askersCase: only the letter case of the question name.
		cased := bytes.Clone(reply)
		askersCase(cased, req)
		if len(cased) != len(reply) {
			t.Fatalf("askersCase: %d bytes, was %d", len(cased), len(reply))
		}
		qEnd, _ := plainName(reply, 12)
		for k := range cased {
			a, b := reply[k], cased[k]
			if a == b {
				continue
			}
			if k < 12 || k >= qEnd || a|0x20 != b|0x20 || a|0x20 < 'a' || a|0x20 > 'z' {
				t.Fatalf("askersCase changed byte %d from %#x to %#x (name ends at %d)", k, a, b, qEnd)
			}
		}

		// stripOPT: the cache form of the message.
		bare, bareOK := stripOPT(reply)
		if !bytes.Equal(reply, orig) {
			t.Fatal("stripOPT changed its input")
		}
		if bareOK && len(bare) < len(reply) {
			if !bytes.Equal(bare[:10], reply[:10]) || !bytes.Equal(bare[12:], reply[12:len(bare)]) {
				t.Fatal("stripOPT changed bytes before the OPT")
			}
			if binary.BigEndian.Uint16(bare[10:]) != binary.BigEndian.Uint16(reply[10:])-1 {
				t.Fatal("stripOPT: ARCOUNT is not one less")
			}
		}
		if bareOK && readable(reply) {
			if !readable(bare) {
				t.Fatalf("stripOPT made a message that does not parse:\n in %x\nout %x", reply, bare)
			}
			if hasOPT(bare) {
				t.Fatalf("stripOPT left an OPT: %x", bare)
			}
		}

		// withCallerOPT: no change without EDNS; a whole message with an
		// OPT appended stays parseable.
		if got := withCallerOPT(bare, ednsOPT{}); !bytes.Equal(got, bare) {
			t.Fatal("withCallerOPT changed a message for a caller without EDNS")
		}
		withOPT := withCallerOPT(bare, ednsOPT{present: true, size: 1232})
		if len(withOPT) != len(bare) && len(withOPT) != len(bare)+11 {
			t.Fatalf("withCallerOPT: %d bytes from %d", len(withOPT), len(bare))
		}
		if len(bare) <= maxMsg && len(withOPT) > maxMsg {
			t.Fatalf("withCallerOPT: %d bytes, more than a TCP frame holds", len(withOPT))
		}
		if end, ok := walkEnd(bare); ok && end == len(bare) && readable(bare) && !hasOPT(bare) && len(withOPT) > len(bare) {
			if !readable(withOPT) || !hasOPT(withOPT) {
				t.Fatalf("withCallerOPT made a message that does not parse: %x", withOPT)
			}
		}
	})
}

// aOwners is the owner name of each A record in the answer section, in
// the form chainNames gives. It stops where the section stops parsing.
func aOwners(msg []byte) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil || p.SkipAllQuestions() != nil {
		return nil
	}
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		if h.Type == dnsmessage.TypeA {
			out = append(out, strings.TrimSuffix(h.Name.String(), "."))
		}
		if p.SkipAnswer() != nil {
			return out
		}
	}
}

// aLengths is the RDLENGTH of each A record in the answer section. It
// stops where the section stops parsing.
func aLengths(msg []byte) []uint16 {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil || p.SkipAllQuestions() != nil {
		return nil
	}
	var out []uint16
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		if h.Type == dnsmessage.TypeA {
			out = append(out, h.Length)
		}
		if p.SkipAnswer() != nil {
			return out
		}
	}
}

func hasOPT(msg []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if h.Type == dnsmessage.TypeOPT {
			return true
		}
		if p.SkipAdditional() != nil {
			return false
		}
	}
}

// walkEnd is the offset after the last record that the header counts.
func walkEnd(msg []byte) (int, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	i, ok := 12, false
	for range binary.BigEndian.Uint16(msg[4:6]) {
		if i, ok = skipName(msg, i); !ok || i+4 > len(msg) {
			return 0, false
		}
		i += 4
	}
	rrs := int(binary.BigEndian.Uint16(msg[6:8])) + int(binary.BigEndian.Uint16(msg[8:10])) + int(binary.BigEndian.Uint16(msg[10:12]))
	for range rrs {
		if i, ok = skipRR(msg, i); !ok {
			return 0, false
		}
	}
	return i, true
}

// upstreamSeeds are query and reply pairs as a resolver sends them.
func upstreamSeeds(f *testing.F) [][2][]byte {
	name := func(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }
	query := func(n string, t dnsmessage.Type) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: name(n), Type: t, Class: dnsmessage.ClassINET})
		m, err := b.Finish()
		if err != nil {
			f.Fatal(err)
		}
		return m
	}
	type rr struct {
		owner string
		body  dnsmessage.ResourceBody
	}
	reply := func(q string, t dnsmessage.Type, rcode dnsmessage.RCode, compress bool, ans, auth []rr, opt []dnsmessage.Option) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode})
		if compress {
			b.EnableCompression()
		}
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: name(q), Type: t, Class: dnsmessage.ClassINET})
		h := func(o string) dnsmessage.ResourceHeader {
			return dnsmessage.ResourceHeader{Name: name(o), Class: dnsmessage.ClassINET, TTL: 300}
		}
		_ = b.StartAnswers()
		for _, r := range ans {
			var err error
			switch body := r.body.(type) {
			case *dnsmessage.AResource:
				err = b.AResource(h(r.owner), *body)
			case *dnsmessage.AAAAResource:
				err = b.AAAAResource(h(r.owner), *body)
			case *dnsmessage.CNAMEResource:
				err = b.CNAMEResource(h(r.owner), *body)
			}
			if err != nil {
				f.Fatal(err)
			}
		}
		_ = b.StartAuthorities()
		for _, r := range auth {
			if err := b.SOAResource(h(r.owner), *r.body.(*dnsmessage.SOAResource)); err != nil {
				f.Fatal(err)
			}
		}
		_ = b.StartAdditionals()
		if opt != nil {
			var oh dnsmessage.ResourceHeader
			_ = oh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
			if err := b.OPTResource(oh, dnsmessage.OPTResource{Options: opt}); err != nil {
				f.Fatal(err)
			}
		}
		m, err := b.Finish()
		if err != nil {
			f.Fatal(err)
		}
		return m
	}
	a := func(o string, x ...byte) rr { return rr{o, &dnsmessage.AResource{A: [4]byte(x)}} }
	cname := func(o, to string) rr { return rr{o, &dnsmessage.CNAMEResource{CNAME: name(to)}} }
	cookie := []dnsmessage.Option{{Code: 10, Data: []byte("01234567")}, {Code: 12, Data: make([]byte, 5)}}
	soa := rr{"example.com.", &dnsmessage.SOAResource{NS: name("ns.example.com."), MBox: name("h.example.com."), Serial: 1, MinTTL: 60}}

	qa := query("Example.COM.", dnsmessage.TypeA)
	chain := reply("www.example.com.", dnsmessage.TypeA, 0, true,
		[]rr{cname("www.example.com.", "a.example.net."), cname("a.example.net.", "b.example.org."), a("b.example.org.", 93, 184, 216, 34)}, nil, cookie)
	seeds := [][2][]byte{
		{qa, reply("example.com.", dnsmessage.TypeA, 0, true, []rr{a("example.com.", 93, 184, 216, 34), a("example.com.", 1, 1, 1, 1)}, nil, cookie)},
		{qa, reply("example.com.", dnsmessage.TypeA, 0, false, []rr{a("example.com.", 93, 184, 216, 34)}, nil, nil)},
		{query("example.com.", dnsmessage.TypeAAAA), reply("example.com.", dnsmessage.TypeAAAA, 0, true,
			[]rr{{"example.com.", &dnsmessage.AAAAResource{AAAA: [16]byte{0x26, 0x06, 15: 1}}}}, nil, []dnsmessage.Option{})},
		{query("WWW.example.com.", dnsmessage.TypeA), chain},
		{qa, reply("example.com.", dnsmessage.TypeA, dnsmessage.RCodeNameError, true, nil, []rr{soa}, []dnsmessage.Option{})},
		{qa, reply("example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, true, nil, []rr{soa}, nil)},
		// Cut inside the chain: the counts promise more than the bytes.
		{query("www.example.com.", dnsmessage.TypeA), chain[:len(chain)-30]},
	}
	// Truncated (TC) reply with no records.
	tc := reply("example.com.", dnsmessage.TypeA, 0, true, nil, nil, []dnsmessage.Option{})
	tc[2] |= 0x02
	seeds = append(seeds, [2][]byte{qa, tc})
	// A pointer loop: the answer owner points at itself.
	loop := bytes.Clone(reply("example.com.", dnsmessage.TypeA, 0, true, []rr{a("example.com.", 9, 9, 9, 9)}, nil, nil))
	qEnd, _ := questionEnd(loop)
	loop[qEnd], loop[qEnd+1] = 0xC0|byte(qEnd>>8), byte(qEnd)
	seeds = append(seeds, [2][]byte{qa, loop})
	return seeds
}
