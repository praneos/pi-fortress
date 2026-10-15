package dnsd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// maxFlatA is the number of addresses that an address-only segment gives
// for one name. Of the developer hosts measured on the Pi through the
// agent resolver, registry.npmjs.org is the widest, with 12. 16 leaves
// space for a CDN on a busy day. It also caps at 64 bytes the address data
// that one lookup can bring back in. That cap is the purpose: an upstream
// that the agent chose can still select the addresses. Each address that
// it selects is four bytes of payload that the strip never reads.
const maxFlatA = 16

// An address-only segment (Segment.AddressOnly, the agent segment) exists
// because a resolver that forwards any type also forwards a channel back in.
// The agent reaches only HTTPS through the gateway. Thus the only answer
// that the agent can use is an address. A TXT answer is up to a couple of
// kilobytes of free text. An LLM over DNS (<question>.ch.at TXT) fills that
// text with the response to its question. A CNAME target is 253 characters
// of the same text, next to an ordinary A record. Thus the segment answers
// each type except A with an empty answer. It gives an A answer as
// addresses under the queried name, and nothing else.
//
// None of this changes exfil in query names: the name still gets to the
// servers of the zone. The key-shape check narrows that channel. Paranoid
// mode closes it.

// typeAllow is dns_types.allow: the name and type pairs that an
// address-only segment forwards as if it were not address-only. An exact
// name matches only itself. A "*.name" entry matches only the names under
// it. The fence reads a core.hosts host in the same way, and so does the
// deny oracle of corepolicy.Forward. This package parses the file, not
// corepolicy.Load. corepolicy.Load reads a missing file as empty and drops
// an unknown token with no message. But a pair that the operator wrote and
// the resolver did not accept must be reported somewhere.
//
// The parser skips and reports a line that does not parse (bad). It is not
// fatal. To skip the line can only filter more, never forward more. To
// refuse the file would stop the one daemon that runs DNS for every
// segment, the house included. This would occur at the next boot, because
// of a typo in an agent override.
type typeAllow struct {
	exact  map[typeKey]struct{}
	suffix map[typeKey]struct{}
	bad    []string
}

type typeKey struct {
	name  string
	qtype uint16
}

// loadTypeAllow reads dns_types.allow. Each line is "name TYPE [TYPE...]",
// with "#" comments. A type has the spelling of the query log (TXT, MX,
// SRV, ...), or TYPE<n> for all other types. The log writes TYPE<n> for a
// type that has no name. Thus an operator can copy the qtype of a filtered
// row directly into the file.
func loadTypeAllow(path string) (*typeAllow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ta := &typeAllow{exact: map[typeKey]struct{}{}, suffix: map[typeKey]struct{}{}}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		bits := strings.Fields(line)
		if len(bits) == 0 {
			continue
		}
		if why := ta.line(bits); why != "" {
			ta.bad = append(ta.bad, fmt.Sprintf("%s:%d: %s; line ignored", path, n, why))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ta, nil
}

// line returns the pairs of one line, all of them or none. If none, it
// gives the reason.
func (ta *typeAllow) line(bits []string) string {
	if len(bits) < 2 {
		return fmt.Sprintf("%q names no type", bits[0])
	}
	table := ta.exact
	name := bits[0]
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		table, name = ta.suffix, rest
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || strings.Contains(name, "*") {
		return fmt.Sprintf("%q is not a name", bits[0])
	}
	ts := make([]uint16, 0, len(bits)-1)
	for _, tok := range bits[1:] {
		t, ok := parseQType(tok)
		if !ok {
			return fmt.Sprintf("%q is not a record type", tok)
		}
		ts = append(ts, t)
	}
	for _, t := range ts {
		table[typeKey{name, t}] = struct{}{}
	}
	return ""
}

// namedTypes is each type that qtypeName has a name for, as a reverse map.
// ANY, NULL and CAA are not in it. Their form is TYPE255, TYPE10 and
// TYPE257, the same as the log writes them.
var namedTypes = []dnsmessage.Type{
	dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME, dnsmessage.TypeMX,
	dnsmessage.TypeNS, dnsmessage.TypePTR, dnsmessage.TypeSRV, dnsmessage.TypeTXT,
	dnsmessage.TypeSOA, typeHTTPS, typeSVCB,
}

func parseQType(tok string) (uint16, bool) {
	tok = strings.ToUpper(tok)
	for _, t := range namedTypes {
		if qtypeName(t) == tok {
			return uint16(t), true
		}
	}
	if num, ok := strings.CutPrefix(tok, "TYPE"); ok {
		v, err := strconv.ParseUint(num, 10, 16)
		return uint16(v), err == nil
	}
	return 0, false
}

// allows reports whether name may be asked for as type t. A nil table
// allows nothing. A segment without overrides has a nil table.
func (ta *typeAllow) allows(name string, t dnsmessage.Type) bool {
	if ta == nil {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if _, ok := ta.exact[typeKey{name, uint16(t)}]; ok {
		return true
	}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
		if _, ok := ta.suffix[typeKey{name, uint16(t)}]; ok {
			return true
		}
	}
}

func (ta *typeAllow) Len() int {
	if ta == nil {
		return 0
	}
	return len(ta.exact) + len(ta.suffix)
}

// flattenA returns an A answer in the form that an address-only segment
// gives: the question, the rcode, and up to maxFlatA A records. The queried
// name owns each record. Each record has the smallest TTL in the answer
// section, CNAMEs included, because the addresses are valid only while each
// link of the chain to them is valid. flattenA does not keep CNAMEs,
// authority records or additional records. The caller adds the OPT, as for
// each answer that this resolver builds itself (finish).
//
// It runs after all checks of the full message (the chain against the
// blocklist, the gate set write). It also runs on the cached bytes when
// they go out. Thus the cache still holds what the upstream sent, and a
// policy that reads the chain still has a chain to read.
//
// NXDOMAIN, SERVFAIL and an empty NOERROR do not change. A truncated stub
// stays truncated, so the client still retries over TCP. It returns nil
// when msg cannot be read. This does not occur for a message that gets
// this far: aRecords read the same section before the gate took its
// addresses.
func flattenA(hdr dnsmessage.Header, q dnsmessage.Question, msg []byte, e ednsOPT) []byte {
	var p dnsmessage.Parser
	up, err := p.Start(msg)
	if err != nil {
		return nil
	}
	addrs, ttl, ok := aRecords(msg)
	if !ok {
		return nil
	}
	b := newBuilder(hdr, q, up.RCode)
	if b == nil {
		return nil
	}
	if len(addrs) > 0 {
		if b.StartAnswers() != nil {
			return nil
		}
		if len(addrs) > maxFlatA {
			addrs = addrs[:maxFlatA]
		}
		for _, a := range addrs {
			err := b.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
				dnsmessage.AResource{A: a.As4()},
			)
			if err != nil {
				return nil
			}
		}
	}
	out := finish(b, e, up.RCode)
	if out != nil && up.Truncated {
		out[2] |= 0x02
	}
	return out
}
