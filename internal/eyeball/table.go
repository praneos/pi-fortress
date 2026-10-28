// Package eyeball is the table of the IPv4 ranges of eyeball networks, and
// the check of an address against it. pf fetch builds the table from the
// feeds of the eyeball section of sources.json (internal/fetch). The broker
// loads it and checks each address that it dials for the agent network
// (internal/broker/eyeball.go).
package eyeball

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TableFile is the name of the table in the generated directory and in
// /etc/pi-fortress.
const TableFile = "eyeball.table"

// Magic is the first line of each table. A file without it is not a
// table, for example a different list at the wrong path.
const Magic = "# pf eyeball v1"

const builtPrefix = "# built "

// MaxRanges is the maximum number of ranges in one table. The full IPv4
// routing table has about 550,000 ranges, and the eyeball part has less
// than half of that. Thus the limit is far above a real table. It stops a
// damaged or hostile file before it uses the memory of the broker.
const MaxRanges = 2_000_000

// Range is one IPv4 range, first and last address included, and the ASN
// that announces it. The table keeps the addresses as uint32: 12 bytes for
// each range, not the 48 bytes of two netip.Addr values and an ASN.
type Range struct {
	First, Last uint32
	ASN         uint32
}

// Table is a sorted list of ranges that do not overlap.
type Table struct {
	// Built is the time of the oldest feed data in the table. A table
	// from a cached copy of a feed has the time of that copy.
	Built  time.Time
	ranges []Range
}

// Len is the number of ranges.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.ranges)
}

// Lookup gives the ASN of the range that holds a, and true. It gives false
// for an address in no range, an IPv6 address, or a nil table.
func (t *Table) Lookup(a netip.Addr) (uint32, bool) {
	a = a.Unmap()
	if t == nil || !a.Is4() {
		return 0, false
	}
	v := addrU32(a)
	i := sort.Search(len(t.ranges), func(i int) bool { return t.ranges[i].Last >= v })
	if i < len(t.ranges) && t.ranges[i].First <= v {
		return t.ranges[i].ASN, true
	}
	return 0, false
}

func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32Addr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ParseASN reads "AS64496", "as64496" or "64496". ASN 0 is not an ASN: it
// marks a range that nobody announces.
func ParseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	if s == "" || s[0] == '+' || s[0] == '-' {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// ParseRange reads the three fields of a range: first address, last
// address, ASN. Both addresses are IPv4 in dotted form.
func ParseRange(first, last, asn string) (Range, bool) {
	a, err := netip.ParseAddr(first)
	if err != nil || !a.Is4() {
		return Range{}, false
	}
	b, err := netip.ParseAddr(last)
	if err != nil || !b.Is4() {
		return Range{}, false
	}
	n, ok := ParseASN(asn)
	if !ok {
		return Range{}, false
	}
	r := Range{First: addrU32(a), Last: addrU32(b), ASN: n}
	if r.First > r.Last {
		return Range{}, false
	}
	return r, true
}

// String is the line of the range in a table: "first last asn".
func (r Range) String() string {
	return u32Addr(r.First).String() + " " + u32Addr(r.Last).String() + " " + strconv.FormatUint(uint64(r.ASN), 10)
}

// Normalize sorts ranges by first address, and drops each range that
// overlaps a range before it. It joins two ranges that are adjacent and
// have the same ASN. The result is a valid table body.
func Normalize(rs []Range) []Range {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].First < rs[j].First })
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			if r.First <= prev.Last {
				continue
			}
			if prev.ASN == r.ASN && prev.Last+1 == r.First {
				prev.Last = r.Last
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Select keeps the ranges whose ASN is in keep, and joins the adjacent
// ranges that remain (Normalize).
func Select(rs []Range, keep func(asn uint32) bool) []Range {
	var out []Range
	for _, r := range rs {
		if keep(r.ASN) {
			out = append(out, r)
		}
	}
	return Normalize(out)
}

// Write writes a table. rs must be the output of Normalize or Select. The
// built time is to the second: Write drops a fraction of a second, and
// Parse refuses one.
func Write(w io.Writer, built time.Time, rs []Range) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "%s\n%s%s\n", Magic, builtPrefix, built.UTC().Format(time.RFC3339))
	for _, r := range rs {
		bw.WriteString(r.String())
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

var (
	errMagic = errors.New("eyeball table: first line is not " + Magic)
	errBuilt = errors.New("eyeball table: no '# built' line")
)

// Parse reads a table. It refuses the full file for one bad line. A table
// with a wrong line is not a table to trust in part: the line can be the
// first sign of a file that is cut or changed.
func Parse(r io.Reader) (*Table, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 4096)
	t := &Table{}
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if line == 1 {
			if s != Magic {
				return nil, errMagic
			}
			continue
		}
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "#") {
			if v, ok := strings.CutPrefix(s, builtPrefix); ok {
				when, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("eyeball table: line %d: %w", line, err)
				}
				// Write keeps the time to the second, and pf fetch never
				// writes a fraction. Parse refuses a fraction of a second.
				// Thus a table that Parse accepts gives the same Built time
				// after Write.
				if when.Nanosecond() != 0 {
					return nil, fmt.Errorf("eyeball table: line %d: built time has a fraction of a second", line)
				}
				t.Built = when.UTC()
			}
			continue
		}
		f := strings.Fields(s)
		if len(f) != 3 {
			return nil, fmt.Errorf("eyeball table: line %d: want first, last, asn", line)
		}
		rg, ok := ParseRange(f[0], f[1], f[2])
		if !ok {
			return nil, fmt.Errorf("eyeball table: line %d: not a range", line)
		}
		if n := len(t.ranges); n > 0 && rg.First <= t.ranges[n-1].Last {
			return nil, fmt.Errorf("eyeball table: line %d: not sorted, or overlaps the line before", line)
		}
		if len(t.ranges) == MaxRanges {
			return nil, fmt.Errorf("eyeball table: more than %d ranges", MaxRanges)
		}
		t.ranges = append(t.ranges, rg)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("eyeball table: line %d: %w", line+1, err)
	}
	if line == 0 {
		return nil, errMagic
	}
	if t.Built.IsZero() {
		return nil, errBuilt
	}
	// The growth of append leaves up to a quarter of the array unused. The
	// table stays in memory for the life of the broker, so it gets an
	// array of its exact size.
	t.ranges = append(make([]Range, 0, len(t.ranges)), t.ranges...)
	return t, nil
}
