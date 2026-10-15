package admin

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DNSTypesList is dns_types.allow: the name and type pairs that the
// address-only resolver of the agent forwards anyway
// (internal/dnsd/addronly.go). It is operator state beside allow.domains.
// It is a list screen here, so the seat refuses a typo. If not, pf dns
// skips the typo with a journal line that nobody reads.
const DNSTypesList = "dns_types.allow"

// dnsTypeNames are the words by which pf dns reads a type, as the query log
// writes them (dnsd namedTypes and qtypeName). All other types are TYPE<n>.
// This is a copy, not an import, because dnsd keeps its parser private.
// TestDNSTypesLineMatchesPfDNS gives both the same lines. Thus a drift is a
// failed test, not a line that the TUI writes and pf dns skips.
var dnsTypeNames = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
	"AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65,
}

// dnsTypesInert are the types that pf dns filters before the list on all
// segments. pf dns accepts a line with these types and changes nothing.
// This screen exists to end that silent no-op, so the seat refuses them.
var dnsTypesInert = map[uint16]string{28: "AAAA", 64: "SVCB", 65: "HTTPS"}

// CheckDNSTypesLine is one dns_types.allow line, "name TYPE [TYPE...]"
// or "*.name TYPE [TYPE...]", with no comment. It returns the line as the
// code writes it to the file: single spaces, the name in lowercase without
// a trailing dot, and the types in uppercase.
//
// pf dns accepts all lines that this function accepts. This function is
// stricter in two places, and both refuse more. A name must be DNS labels
// (letters, digits, '-', and '_' for SRV-style names). pf dns accepts any
// name without a '*'. Also, this function refuses the three types that pf
// dns filters before the list. pf dns accepts them and ignores them.
func CheckDNSTypesLine(v string) (string, error) {
	bits := strings.Fields(v)
	if len(bits) == 0 {
		return "", errors.New("empty line")
	}
	if len(bits) < 2 {
		return "", fmt.Errorf("%q names no type; want name TYPE [TYPE...]", bits[0])
	}
	wild, name := "", bits[0]
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		wild, name = "*.", rest
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !dnsTypesName(name) {
		return "", fmt.Errorf("%q is not a name", bits[0])
	}
	out := []string{wild + name}
	for _, tok := range bits[1:] {
		up := strings.ToUpper(tok)
		t, ok := dnsTypeNames[up]
		if !ok {
			num, isNum := strings.CutPrefix(up, "TYPE")
			n, err := strconv.ParseUint(num, 10, 16)
			if !isNum || err != nil {
				return "", fmt.Errorf("%q is not a record type; want TXT, MX, SRV, NS, SOA, PTR, CNAME or TYPE<n>", tok)
			}
			t = uint16(n)
		}
		if w, inert := dnsTypesInert[t]; inert {
			return "", fmt.Errorf("%s is filtered on every segment before this list; a line naming it changes nothing", w)
		}
		out = append(out, up)
	}
	return strings.Join(out, " "), nil
}

// dnsTypesName is a name of DNS labels, 1-63 bytes each and 253 in all.
func dnsTypesName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}
