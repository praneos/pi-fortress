package eyeball

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The fixtures use the documentation ASNs (RFC 5398: 64496-64511) and
// the TEST-NET ranges (RFC 5737).
var built = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func mustRange(t *testing.T, first, last, asn string) Range {
	t.Helper()
	r, ok := ParseRange(first, last, asn)
	if !ok {
		t.Fatalf("ParseRange(%s, %s, %s) failed", first, last, asn)
	}
	return r
}

func testTable(t *testing.T) *Table {
	t.Helper()
	rs := []Range{
		mustRange(t, "203.0.113.0", "203.0.113.127", "64497"),
		mustRange(t, "192.0.2.0", "192.0.2.255", "64496"),
		mustRange(t, "198.51.100.0", "198.51.100.0", "64498"),
	}
	var b bytes.Buffer
	if err := Write(&b, built, Normalize(rs)); err != nil {
		t.Fatal(err)
	}
	tab, err := Parse(&b)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestTableLookupEdges(t *testing.T) {
	tab := testTable(t)
	if tab.Len() != 3 || !tab.Built.Equal(built) {
		t.Fatalf("len %d built %v", tab.Len(), tab.Built)
	}
	for _, c := range []struct {
		addr string
		asn  uint32
		ok   bool
	}{
		{"192.0.2.0", 64496, true},
		{"192.0.2.255", 64496, true},
		{"192.0.1.255", 0, false},
		{"192.0.3.0", 0, false},
		{"198.51.100.0", 64498, true},
		{"198.51.100.1", 0, false},
		{"198.51.99.255", 0, false},
		{"203.0.113.127", 64497, true},
		{"203.0.113.128", 0, false},
		{"0.0.0.0", 0, false},
		{"255.255.255.255", 0, false},
		{"::ffff:192.0.2.7", 64496, true},
		{"2001:db8::1", 0, false},
	} {
		asn, ok := tab.Lookup(netip.MustParseAddr(c.addr))
		if asn != c.asn || ok != c.ok {
			t.Errorf("Lookup(%s) = %d, %v; want %d, %v", c.addr, asn, ok, c.asn, c.ok)
		}
	}
	var nilTable *Table
	if _, ok := nilTable.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("a nil table matched")
	}
}

func TestNormalizeJoinsAndDropsOverlap(t *testing.T) {
	rs := Normalize([]Range{
		mustRange(t, "192.0.2.128", "192.0.2.255", "64496"),
		mustRange(t, "192.0.2.0", "192.0.2.127", "64496"),
		// Overlaps the joined range: dropped.
		mustRange(t, "192.0.2.100", "192.0.2.200", "64499"),
		// Adjacent, but a different ASN: kept apart.
		mustRange(t, "192.0.3.0", "192.0.3.255", "64497"),
		mustRange(t, "255.255.255.0", "255.255.255.255", "64500"),
	})
	want := []string{"192.0.2.0 192.0.2.255 64496", "192.0.3.0 192.0.3.255 64497", "255.255.255.0 255.255.255.255 64500"}
	if len(rs) != len(want) {
		t.Fatalf("got %v", rs)
	}
	for i := range want {
		if rs[i].String() != want[i] {
			t.Errorf("range %d = %s, want %s", i, rs[i], want[i])
		}
	}
}

func TestSelectUnknownASNNotInTable(t *testing.T) {
	rs := []Range{
		mustRange(t, "192.0.2.0", "192.0.2.255", "64496"),
		mustRange(t, "198.51.100.0", "198.51.100.255", "64511"),
	}
	got := Select(rs, func(asn uint32) bool { return asn == 64496 })
	if len(got) != 1 || got[0].ASN != 64496 {
		t.Fatalf("got %v", got)
	}
}

func TestParseRefuses(t *testing.T) {
	head := Magic + "\n# built 2026-10-01T00:00:00Z\n"
	for name, body := range map[string]string{
		"empty":       "",
		"no magic":    "# built 2026-10-01T00:00:00Z\n192.0.2.0 192.0.2.255 64496\n",
		"no built":    Magic + "\n192.0.2.0 192.0.2.255 64496\n",
		"bad built":   Magic + "\n# built yesterday\n",
		"reversed":    head + "192.0.2.255 192.0.2.0 64496\n",
		"asn zero":    head + "192.0.2.0 192.0.2.255 0\n",
		"asn text":    head + "192.0.2.0 192.0.2.255 x\n",
		"ipv6":        head + "2001:db8:: 2001:db8::ff 64496\n",
		"two fields":  head + "192.0.2.0 64496\n",
		"unsorted":    head + "198.51.100.0 198.51.100.255 64496\n192.0.2.0 192.0.2.255 64496\n",
		"overlap":     head + "192.0.2.0 192.0.2.255 64496\n192.0.2.255 192.0.3.0 64497\n",
		"long line":   head + strings.Repeat("1", 5000) + "\n",
		"asn too big": head + "192.0.2.0 192.0.2.255 4294967296\n",
	} {
		if _, err := Parse(strings.NewReader(body)); err == nil {
			t.Errorf("%s: Parse accepted %q", name, body)
		}
	}
	ok := head + "\n# a note\n192.0.2.0 192.0.2.255 AS64496\n"
	tab, err := Parse(strings.NewReader(ok))
	if err != nil || tab.Len() != 1 {
		t.Fatalf("Parse(%q) = %v, %v", ok, tab, err)
	}
}

// A '# built' time with a fraction of a second is refused. Write keeps
// the time to the second, so the fraction would not survive a round
// trip. pf fetch never writes one. A fraction of zero is the same time
// as none.
func TestParseRefusesAFractionOfASecond(t *testing.T) {
	for _, stamp := range []string{"2026-10-01T00:00:00.5Z", "2026-10-01T00:00:00.999999999Z", "2026-10-01T02:00:00.25+02:00"} {
		in := Magic + "\n# built " + stamp + "\n192.0.2.0 192.0.2.255 64496\n"
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", stamp)
		}
	}
	in := Magic + "\n# built 2026-10-01T00:00:00.000Z\n192.0.2.0 192.0.2.255 64496\n"
	tab, err := Parse(strings.NewReader(in))
	if err != nil || !tab.Built.Equal(built) {
		t.Fatalf("a fraction of zero: %v, %v", tab, err)
	}
	var b bytes.Buffer
	if err := Write(&b, tab.Built, tab.ranges); err != nil {
		t.Fatal(err)
	}
	again, err := Parse(&b)
	if err != nil || !again.Built.Equal(tab.Built) || again.Len() != tab.Len() {
		t.Fatalf("round trip: %v, %v", again, err)
	}
}

func TestParseASN(t *testing.T) {
	for in, want := range map[string]uint32{"AS64496": 64496, "as64511": 64511, "64496": 64496, " 64500 ": 64500} {
		if got, ok := ParseASN(in); !ok || got != want {
			t.Errorf("ParseASN(%q) = %d, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "AS", "AS0", "0", "-1", "+5", "AS-1", "4294967296", "AS64496x"} {
		if _, ok := ParseASN(in); ok {
			t.Errorf("ParseASN(%q) accepted", in)
		}
	}
}

// A range of more than one /8 is not in a table. Select drops it, also
// when it is the join of smaller ranges, and Parse refuses a table with
// it. One /8 is the limit, and it stays.
func TestRangeWiderThanSlash8IsDropped(t *testing.T) {
	rs := []Range{
		mustRange(t, "0.0.0.0", "255.255.255.255", "64497"),
		mustRange(t, "20.0.0.0", "20.127.255.255", "64496"),
		mustRange(t, "20.128.0.0", "20.255.255.255", "64496"),
		mustRange(t, "21.0.0.0", "21.0.0.255", "64496"),
		mustRange(t, "73.0.0.0", "73.255.255.255", "64498"),
	}
	got := Select(rs[1:], func(uint32) bool { return true })
	if len(got) != 1 || got[0].String() != "73.0.0.0 73.255.255.255 64498" {
		t.Fatalf("Select: %v", got)
	}
	got = Select(rs[:1], func(uint32) bool { return true })
	if len(got) != 0 {
		t.Fatalf("Select kept %v", got)
	}
	head := Magic + "\n# built 2026-10-01T00:00:00Z\n"
	for _, body := range []string{
		head + "0.0.0.0 255.255.255.255 64497\n",
		head + "20.0.0.0 21.0.0.0 64496\n",
	} {
		if _, err := Parse(strings.NewReader(body)); err == nil {
			t.Errorf("Parse accepted %q", body)
		}
	}
	if tab, err := Parse(strings.NewReader(head + "73.0.0.0 73.255.255.255 64498\n")); err != nil || tab.Len() != 1 {
		t.Fatalf("one /8: %v, %v", tab, err)
	}
}
