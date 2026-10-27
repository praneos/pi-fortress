package dnsd

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// patchID returns a copy of msg with id. It makes a copy because the cache
// gives the same bytes to every caller. The id is the one field that is
// different between them.
func patchID(msg []byte, id uint16) []byte {
	if len(msg) < 12 {
		return nil
	}
	out := make([]byte, len(msg))
	copy(out, msg)
	setID(out, id)
	return out
}

// setID writes the id into a message that the caller already owns. It is
// for the paths that already made their own copy. Without it, these paths
// would make a second copy to change two bytes of it.
func setID(msg []byte, id uint16) {
	if len(msg) >= 12 {
		binary.BigEndian.PutUint16(msg[:2], id)
	}
}

// ednsOPT is the content of the OPT record of the client. It goes with a
// query because each answer that this resolver builds must use the dialect
// of the client question. A client that sent an OPT and got an answer
// without one learns that its resolver does not speak EDNS. That is not
// true. It also costs the client the larger datagram that it offered.
type ednsOPT struct {
	present bool
	size    int
	version uint8
	do      bool
}

// udpSize is the datagram the client will accept, clamped. No OPT
// record means the 512 bytes of RFC 1035.
func (e ednsOPT) udpSize() int {
	if !e.present || e.size < udpMin {
		return udpMin
	}
	if e.size > udpMax {
		return udpMax
	}
	return e.size
}

func newBuilder(hdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode) *dnsmessage.Builder {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		OpCode:             hdr.OpCode,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if b.StartQuestions() != nil {
		return nil
	}
	if b.Question(q) != nil {
		return nil
	}
	return &b
}

// finish closes a locally built message. A client that asked in EDNS gets
// its answer in EDNS. Its OPT record carries the extended rcode and the
// buffer size. An answer without an OPT record silently downgrades the
// conversation to RFC 1035.
func finish(b *dnsmessage.Builder, e ednsOPT, ext dnsmessage.RCode) []byte {
	if e.present {
		if b.StartAdditionals() != nil {
			return nil
		}
		var h dnsmessage.ResourceHeader
		if h.SetEDNS0(udpMax, ext, e.do) != nil {
			return nil
		}
		if b.OPTResource(h, dnsmessage.OPTResource{}) != nil {
			return nil
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// empty is a response with the question and no records. It is NODATA
// when the rcode is success, and NXDOMAIN when it is not.
func empty(hdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode, e ednsOPT) []byte {
	b := newBuilder(hdr, q, rcode)
	if b == nil {
		return nil
	}
	return finish(b, e, rcode)
}

// badVersion is BADVERS of RFC 6891: an rcode of 16. Its low four bits are
// in the header, and its top eight bits are in the OPT record. Thus only a
// client that sent its own OPT can get it. An ordinary answer to an EDNS
// version that we do not speak tells the client that we understood its
// options. But we skipped them.
func badVersion(hdr dnsmessage.Header, q dnsmessage.Question, e ednsOPT) []byte {
	const extBadVers = dnsmessage.RCode(16)
	b := newBuilder(hdr, q, extBadVers&0x0f)
	if b == nil {
		return nil
	}
	return finish(b, e, extBadVers)
}

// refuse answers a message that we will not process. It echoes the
// question when there was one to read.
func refuse(hdr dnsmessage.Header, rcode dnsmessage.RCode, q *dnsmessage.Question, e ednsOPT) []byte {
	if q != nil {
		return empty(hdr, *q, rcode, e)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, OpCode: hdr.OpCode,
		RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	})
	return finish(&b, e, rcode)
}

// truncated is the empty response with TC set. TC tells a client to ask
// the same question again over TCP.
func truncated(hdr dnsmessage.Header, q dnsmessage.Question, e ednsOPT) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, OpCode: hdr.OpCode, Truncated: true,
		RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true,
	})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	return finish(&b, e, dnsmessage.RCodeSuccess)
}

// clientEDNS reads the OPT record of the client: whether it sent one, the
// datagram it offered, the version it speaks, and whether it wants DNSSEC
// records. It reads all four, not only the size. The old reader discarded
// the other three, but an answer must echo them.
func clientEDNS(req []byte) ednsOPT {
	var p dnsmessage.Parser
	if _, err := p.Start(req); err != nil {
		return ednsOPT{}
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return ednsOPT{}
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return ednsOPT{}
		}
		if h.Type == dnsmessage.TypeOPT {
			// An OPT record keeps its version and flags in the field a
			// record of any other type uses for its TTL.
			return ednsOPT{present: true, size: int(h.Class), version: uint8(h.TTL >> 16), do: h.DNSSECAllowed()}
		}
		if p.SkipAdditional() != nil {
			return ednsOPT{}
		}
	}
}

func clientUDPSize(req []byte) int { return clientEDNS(req).udpSize() }

// aRecords collects the addresses for the nft set. It also collects the
// smallest TTL in the answer section, which is the maximum cache time of
// the full message. The TTL of a CNAME counts, because the chain is valid
// only while each link is valid. The bool is false when the answer section
// could not be read to its end. A partial walk would give the gate the
// addresses that it reached and hide all that came after them.
func aRecords(msg []byte) ([]netip.Addr, uint32, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, 0, false
	}
	if p.SkipAllQuestions() != nil {
		return nil, 0, false
	}
	var addrs []netip.Addr
	var ttl uint32
	// A record with a real TTL of zero is the ceiling of the full
	// message. Thus "no record seen yet" needs its own flag. When the
	// two shared the zero, the positive TTL of the next record raised it.
	// The cache then kept the answer for a lifetime that nothing granted.
	seen := false
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			if !errors.Is(err, dnsmessage.ErrSectionDone) {
				return nil, 0, false
			}
			break
		}
		if !seen || h.TTL < ttl {
			ttl, seen = h.TTL, true
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				return nil, 0, false
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
			continue
		}
		if p.SkipAnswer() != nil {
			return nil, 0, false
		}
	}
	return addrs, ttl, true
}

// maxNegTTL is the longest time that the cache keeps a negative answer.
const maxNegTTL = 300

// negTTL is the cache time of a negative answer: NXDOMAIN, or NODATA
// (success with no answer records). RFC 2308 section 5 gives it as the
// smaller of the SOA record TTL and the SOA MINIMUM field, from the
// authority section. negTTL caps it at maxNegTTL. The bool is false when
// msg is not a negative answer, has no SOA, or cannot be read to its end.
// Without an SOA, the reply gives no negative TTL, and the cache keeps
// nothing.
func negTTL(msg []byte) (uint32, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return 0, false
	}
	if hdr.RCode != dnsmessage.RCodeSuccess && hdr.RCode != dnsmessage.RCodeNameError {
		return 0, false
	}
	if p.SkipAllQuestions() != nil {
		return 0, false
	}
	if _, err := p.AnswerHeader(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return 0, false
	}
	ttl, seen := uint32(0), false
	for {
		h, err := p.AuthorityHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return 0, false
		}
		if h.Type != dnsmessage.TypeSOA {
			if p.SkipAuthority() != nil {
				return 0, false
			}
			continue
		}
		soa, err := p.SOAResource()
		if err != nil {
			return 0, false
		}
		t := min(h.TTL, soa.MinTTL)
		if !seen || t < ttl {
			ttl, seen = t, true
		}
	}
	// The top bits of the rcode are in the OPT record. A value there makes
	// the rcode a different one than the header shows.
	for {
		h, err := p.AdditionalHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return 0, false
		}
		if h.Type == dnsmessage.TypeOPT && h.TTL>>24 != 0 {
			return 0, false
		}
		if p.SkipAdditional() != nil {
			return 0, false
		}
	}
	if !seen {
		return 0, false
	}
	return min(ttl, maxNegTTL), true
}

// localV4 is what --stop-dns-rebind refused beyond what netip already
// names: this network, CGNAT, the benchmark range and class E.
var localV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// public drops each address that a gate set must not learn from an
// upstream: private, loopback, link-local, multicast, unspecified and the
// ranges in localV4. It filters the slice in place.
func public(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0]
next:
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		for _, p := range localV4 {
			if p.Contains(a) {
				continue next
			}
		}
		out = append(out, a)
	}
	return out
}

// maxGateA is the number of addresses that one answer can put in the gate
// set when the client gets the full answer: the house, and a type that
// dns_types.allow forwards. An address-only A answer uses maxFlatA, the
// number of addresses that the client gets. Each answer adds its
// addresses to a set with a size (render resolvedSetSize). Without a
// limit, one large answer over TCP (about 4000 A records) could use a
// large part of that size. 64 is four times maxFlatA. A client that
// connects to an address after the first 64 meets the gate drop, the same
// as for an address that this box did not resolve.
const maxGateA = 64

// gateAddrs returns the first n distinct addresses of addrs, in the order
// of the answer. An address that is in the answer two times goes to nft
// one time.
func gateAddrs(addrs []netip.Addr, n int) []netip.Addr {
	out := make([]netip.Addr, 0, min(len(addrs), n))
	for _, a := range addrs {
		if len(out) == n {
			break
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// rrTTLs is the offset of the TTL field of each ordinary resource record.
// It walks the message by hand, because the message must age in place. It
// does not unpack and repack the message. A repack rewrites compression
// pointers. It also drops record types that have no struct in this build.
// Then the client would get a message different from the upstream message.
//
// The walk is also the completeness check that the forwarder needs. Some
// replies have counts that promise records that the bytes do not carry.
// Such a reply parses far enough to look like an answer, and then stops.
// That is how a partial message gets gated and cached as a whole one.
//
// rrTTLs skips OPT. Its TTL field is not a lifetime. It is the extended
// rcode, the EDNS version and the flags. A countdown would corrupt all
// three.
func rrTTLs(msg []byte) ([]int, bool) {
	if len(msg) < 12 {
		return nil, false
	}
	counts := [4]int{
		int(msg[4])<<8 | int(msg[5]),
		int(msg[6])<<8 | int(msg[7]),
		int(msg[8])<<8 | int(msg[9]),
		int(msg[10])<<8 | int(msg[11]),
	}
	i, ok := 12, false
	for n := 0; n < counts[0]; n++ {
		if i, ok = skipName(msg, i); !ok {
			return nil, false
		}
		// QTYPE and QCLASS.
		if i += 4; i > len(msg) {
			return nil, false
		}
	}
	var out []int
	for s := 1; s < 4; s++ {
		for n := 0; n < counts[s]; n++ {
			if i, ok = skipName(msg, i); !ok {
				return nil, false
			}
			// TYPE, CLASS, TTL and RDLENGTH.
			if i+10 > len(msg) {
				return nil, false
			}
			if rrType := uint16(msg[i])<<8 | uint16(msg[i+1]); rrType != uint16(dnsmessage.TypeOPT) {
				out = append(out, i+4)
			}
			rdlen := int(msg[i+8])<<8 | int(msg[i+9])
			i += 10 + rdlen
			if i > len(msg) {
				return nil, false
			}
		}
	}
	return out, true
}

// skipName steps over one domain name and returns the offset immediately
// after it. A compression pointer ends the name at its position. The
// pointer must point backwards into the message. A pointer that goes
// forward or to itself is a loop or a path off the end of the buffer.
func skipName(msg []byte, i int) (int, bool) {
	for n := 0; n < 128; n++ {
		if i >= len(msg) {
			return 0, false
		}
		c := int(msg[i])
		switch {
		case c == 0:
			return i + 1, true
		case c&0xC0 == 0xC0:
			if i+2 > len(msg) {
				return 0, false
			}
			if p := (c&0x3F)<<8 | int(msg[i+1]); p < 12 || p >= i {
				return 0, false
			}
			return i + 2, true
		case c&0xC0 != 0:
			return 0, false
		default:
			i += c + 1
		}
	}
	return 0, false
}

// whole reports whether every record the header counts promises is
// present and fits inside the message.
func whole(msg []byte) bool {
	_, ok := rrTTLs(msg)
	return ok
}

// ageTTLs is a copy of msg. In the copy, the TTL of each record is
// decreased by the time that the cache held it. Without this, a hit gives
// the client the full original lifetime again, whatever the age of the
// entry. Then the cache is about to forget a name, but the client was
// told to keep it for another hour.
func ageTTLs(msg []byte, age time.Duration) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	secs := uint32(age / time.Second)
	if secs == 0 {
		return out
	}
	offs, ok := rrTTLs(out)
	if !ok {
		return out
	}
	for _, o := range offs {
		ttl := binary.BigEndian.Uint32(out[o : o+4])
		if ttl > secs {
			ttl -= secs
		} else {
			ttl = 0
		}
		binary.BigEndian.PutUint32(out[o:o+4], ttl)
	}
	return out
}

// capTTLs is msg with the TTL of each record lowered to max or less, in
// place. The bytes of the caller are the upstream reply, not a cache entry.
func capTTLs(msg []byte, max uint32) []byte {
	offs, ok := rrTTLs(msg)
	if !ok {
		return msg
	}
	for _, o := range offs {
		if binary.BigEndian.Uint32(msg[o:o+4]) > max {
			binary.BigEndian.PutUint32(msg[o:o+4], max)
		}
	}
	return msg
}

// askersCase changes the question name of msg, in place, to the spelling
// in req. Each is the first name of its message, so neither can be
// compressed. askersCase does the rewrite only when both are plain labels
// of one length that differ only in ASCII case. Records that point at the
// question name follow it.
func askersCase(msg, req []byte) {
	end, ok := plainName(req, 12)
	if !ok {
		return
	}
	if e, ok := plainName(msg, 12); !ok || e != end {
		return
	}
	for i := 12; i < end; i++ {
		a, b := msg[i], req[i]
		if a != b && (a|0x20 != b|0x20 || a|0x20 < 'a' || a|0x20 > 'z') {
			return
		}
	}
	copy(msg[12:end], req[12:end])
}

// plainName is the end of the uncompressed name at off, or false.
func plainName(msg []byte, off int) (int, bool) {
	for i := off; i < len(msg); {
		l := int(msg[i])
		if l == 0 {
			return i + 1, true
		}
		if l > 63 || i+1+l > len(msg) {
			return 0, false
		}
		i += 1 + l
	}
	return 0, false
}

// chainNames is each name that the answer section resolves through: the
// owner of each record and the target of each CNAME. A policy that sees
// only the queried name is one alias away from a bypass. An unlisted name
// with a CNAME to a listed name gets an ordinary answer. The address of
// the listed name then goes into the gate set under the innocent name.
// Thus the policy must see the full chain.
//
// Names can repeat here. chainNames does not remove duplicates, because a
// lookup is a walk down the labels of one name. That costs less than the
// scan that would find the duplicate. chainNames does not follow DNAME.
// An upstream that sends one also synthesises the CNAME that it implies,
// and that CNAME is here.
//
// The bool is false when the section could not be read to its end. A
// half-walked chain is worse than no chain. The policy would apply to the
// links that it read. The rest of the answer would never be judged. That
// is the part where an upstream would put a listed name, to get it past
// us.
func chainNames(msg []byte) ([]string, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, false
	}
	if p.SkipAllQuestions() != nil {
		return nil, false
	}
	var out []string
	add := func(n dnsmessage.Name) {
		if s := strings.TrimSuffix(n.String(), "."); s != "" {
			out = append(out, s)
		}
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			if !errors.Is(err, dnsmessage.ErrSectionDone) {
				return nil, false
			}
			break
		}
		add(h.Name)
		if h.Type == dnsmessage.TypeCNAME {
			r, err := p.CNAMEResource()
			if err != nil {
				return nil, false
			}
			add(r.CNAME)
			continue
		}
		if p.SkipAnswer() != nil {
			return nil, false
		}
	}
	return out, true
}

// answerOf is what the log line gives as the result of the name: the
// first address, or the condition when there is no address. dnsmasq logs
// one line per answer. One line per query is sufficient for the reader,
// which pairs by name.
func answerOf(msg []byte) string {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return ""
	}
	if p.SkipAllQuestions() != nil {
		return ""
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				break
			}
			return netip.AddrFrom4(r.A).String()
		}
		if p.SkipAnswer() != nil {
			break
		}
	}
	switch hdr.RCode {
	case dnsmessage.RCodeSuccess:
		return "NODATA"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	}
	// The package spells the rest "RCode6" or a bare number. A reader of
	// the log could think that this is an address or a name.
	return "RCODE" + strconv.Itoa(int(hdr.RCode))
}

func qtypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeSOA:
		return "SOA"
	case typeHTTPS:
		return "HTTPS"
	case typeSVCB:
		return "SVCB"
	}
	// dnsmasq writes the number in brackets for a type that it has no name
	// for. The pattern of the reader accepts [A-Z0-9]+ in both cases.
	return "TYPE" + strconv.Itoa(int(t))
}

// bogusPriv: this resolver answers a reverse lookup for a private address
// here and never forwards it. Thus the upstream does not learn the shape
// of the LAN.
func bogusPriv(name string, t dnsmessage.Type) bool {
	if t != dnsmessage.TypePTR {
		return false
	}
	rest, ok := strings.CutSuffix(strings.ToLower(name), ".in-addr.arpa")
	if !ok {
		return false
	}
	labels := strings.Split(rest, ".")
	if len(labels) != 4 {
		// A partial reverse zone is not a host lookup; leave it alone.
		return false
	}
	var b [4]byte
	for i, l := range labels {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		b[3-i] = byte(n)
	}
	a := netip.AddrFrom4(b)
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// canonicalQuery is the question that this resolver asks upstream: the
// name, type and class of the client, and nothing else from the client.
//
// Before, the request went out as the client wrote it. Thus the answer
// was also specific to the client. A client that asked with DO=1 got
// RRSIGs back. A client that asked with CD=1 got an answer that nobody had
// validated. The cache uses name and qtype as the key, because those are
// the fields of a question. The cache then served that answer to the next
// caller on the segment, who had asked for neither. That was harmless
// while each client was a dnsmasq with uniform flags. It was not harmless
// after dnsmasq went to port=0. Then the agent VMs and house devices
// became ordinary OS resolvers that query this daemon directly.
//
// The buffer size here is ours, not the size of the client. A 512-byte
// client must not reduce the answer that the rest of the segment gets from
// the cache. reply truncates per caller after this.
func canonicalQuery(q dnsmessage.Question, id uint16) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	if b.StartAdditionals() != nil {
		return nil
	}
	var h dnsmessage.ResourceHeader
	if h.SetEDNS0(udpMax, dnsmessage.RCodeSuccess, false) != nil {
		return nil
	}
	if b.OPTResource(h, dnsmessage.OPTResource{}) != nil {
		return nil
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// stripOPT returns msg without its OPT record, with ARCOUNT set to the
// count of the remaining records. Thus the cache holds the answer, not the
// exchange that brought it. An OPT belongs to one hop. A client that asked
// without EDNS must not get one back. A client that asked with EDNS must
// get the buffer of this resolver, not the buffer of the upstream.
//
// It refuses, and does not guess, when the OPT is not the last record in
// the message. A removal of bytes from the middle shifts each offset after
// them. A compression pointer in a later record still points where the
// name was before. Every resolver puts OPT last. If one does not, its
// answer passes through and is not cached. That costs a lookup and
// nothing else.
func stripOPT(msg []byte) ([]byte, bool) {
	if len(msg) < 12 {
		return msg, false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	mid := int(binary.BigEndian.Uint16(msg[6:8])) + int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	i := 12
	for range qd {
		var ok bool
		if i, ok = skipName(msg, i); !ok {
			return msg, false
		}
		i += 4
		if i > len(msg) {
			return msg, false
		}
	}
	for range mid {
		var ok bool
		if i, ok = skipRR(msg, i); !ok {
			return msg, false
		}
	}
	for range ar {
		start := i
		j, ok := skipName(msg, start)
		if !ok || j+2 > len(msg) {
			return msg, false
		}
		typ := binary.BigEndian.Uint16(msg[j : j+2])
		if i, ok = skipRR(msg, start); !ok {
			return msg, false
		}
		if typ != optType {
			continue
		}
		if i != len(msg) {
			return msg, false
		}
		out := make([]byte, start)
		copy(out, msg[:start])
		binary.BigEndian.PutUint16(out[10:12], uint16(ar-1))
		// A name in the rdata of an earlier record can read into the OPT
		// bytes: a compression pointer to them, or a label that runs past
		// its rdlength. After the cut, no client can read that name. Refuse
		// such a message, as when the OPT is not last.
		if !readable(out) {
			return msg, false
		}
		return out, true
	}
	return msg, true
}

// readable reports whether a parser reads each record that the header of
// msg counts, with the rdata of each type that it knows.
func readable(msg []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false
	}
	if _, err := p.AllQuestions(); err != nil {
		return false
	}
	if _, err := p.AllAnswers(); err != nil {
		return false
	}
	if _, err := p.AllAuthorities(); err != nil {
		return false
	}
	_, err := p.AllAdditionals()
	return err == nil
}

// withCallerOPT returns msg with an OPT record for a caller that asked in
// EDNS. A caller that did not ask in EDNS gets msg with no change. The
// client has no reason to read an OPT in a response to a query without
// one.
//
// DO is off because that is true. This resolver asks upstream without DO,
// so the message has no RRSIGs to flag.
//
// A message with no room for the 11 bytes of the OPT goes with no change.
// Over TCP, the length prefix cannot count more than maxMsg bytes.
//
// A compression pointer into the header reads ARCOUNT as part of a name.
// The new count changes that name, and the name can stop parsing. Such a
// message also goes with no change, as stripOPT does when its cut breaks
// a name.
func withCallerOPT(msg []byte, e ednsOPT) []byte {
	if !e.present || len(msg) < 12 || len(msg)+11 > maxMsg {
		return msg
	}
	ar := binary.BigEndian.Uint16(msg[10:12])
	if ar == ^uint16(0) {
		return msg
	}
	out := make([]byte, 0, len(msg)+11)
	out = append(out, msg...)
	var rr [11]byte
	// NAME is the root label; then TYPE, CLASS as the buffer we accept,
	// TTL as extended rcode 0 / version 0 / DO off, and no rdata.
	binary.BigEndian.PutUint16(rr[1:3], optType)
	binary.BigEndian.PutUint16(rr[3:5], udpMax)
	out = append(out, rr[:]...)
	binary.BigEndian.PutUint16(out[10:12], ar+1)
	if mayPointIntoHeader(msg) && !readable(out) {
		return msg
	}
	return out
}

// mayPointIntoHeader is true if two bytes after the header can be a
// compression pointer to an offset in the header. It can be true for a
// message with no such pointer. It is never false for a message with one.
// Thus only the few messages where it is true need a full parse.
func mayPointIntoHeader(msg []byte) bool {
	for i := 12; i+1 < len(msg); i++ {
		if msg[i] == 0xc0 && msg[i+1] < 12 {
			return true
		}
	}
	return false
}

// skipRR advances past one resource record: its name, the ten bytes of
// fixed header, and the rdata its rdlength claims.
func skipRR(msg []byte, i int) (int, bool) {
	j, ok := skipName(msg, i)
	if !ok || j+10 > len(msg) {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(msg[j+8 : j+10]))
	j += 10 + n
	if j > len(msg) {
		return 0, false
	}
	return j, true
}
