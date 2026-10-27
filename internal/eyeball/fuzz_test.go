package eyeball

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// FuzzParse: Parse never panics, and a table that it accepts holds its
// invariants. The ranges are sorted and do not overlap, each lookup of
// the first and last address of a range gives its ASN, and Write gives a
// file that Parse reads back the same.
func FuzzParse(f *testing.F) {
	f.Add(Magic + "\n# built 2026-10-01T00:00:00Z\n192.0.2.0 192.0.2.255 64496\n198.51.100.0 198.51.100.0 64511\n")
	f.Add(Magic + "\n# built 2026-10-01T00:00:00Z\n0.0.0.0 255.255.255.255 4294967295\n")
	f.Add(Magic + "\n# built 2026-10-01T00:00:00Z\n192.0.2.0 192.0.2.255 AS64496\n192.0.2.255 192.0.3.0 64497\n")
	f.Add(Magic + "\n# built x\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		tab, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		for i, r := range tab.ranges {
			if r.First > r.Last || r.ASN == 0 {
				t.Fatalf("range %d %v", i, r)
			}
			if i > 0 && r.First <= tab.ranges[i-1].Last {
				t.Fatalf("range %d %v overlaps %v", i, r, tab.ranges[i-1])
			}
			for _, v := range []uint32{r.First, r.Last} {
				if asn, ok := tab.Lookup(u32Addr(v)); !ok || asn != r.ASN {
					t.Fatalf("Lookup(%v) = %d, %v in %v", u32Addr(v), asn, ok, r)
				}
			}
		}
		var b bytes.Buffer
		if err := Write(&b, tab.Built, tab.ranges); err != nil {
			t.Fatal(err)
		}
		again, err := Parse(&b)
		if err != nil {
			t.Fatalf("Parse of Write output: %v", err)
		}
		if again.Len() != tab.Len() || !again.Built.Equal(tab.Built) {
			t.Fatalf("round trip: %d %v, want %d %v", again.Len(), again.Built, tab.Len(), tab.Built)
		}
		_, _ = tab.Lookup(netip.MustParseAddr("192.0.2.1"))
	})
}

// FuzzParseAllow: the allow list parser never panics, and each name that
// it keeps exempts itself.
func FuzzParseAllow(f *testing.F) {
	f.Add("AS64496\nhome.example.com\n# note\n")
	f.Add("as1\n.\n..\nexample.\n")
	f.Fuzz(func(t *testing.T, in string) {
		a, _, err := ParseAllow(strings.NewReader(in))
		if err != nil {
			return
		}
		for n := range a.names {
			if !a.Exempt(n, 0) {
				t.Fatalf("name %q does not exempt itself", n)
			}
		}
	})
}
