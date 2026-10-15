package policycompile

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzCoalesceIPv4: an output prefix covers each valid input prefix. The
// outputs are valid and pairwise disjoint.
func FuzzCoalesceIPv4(f *testing.F) {
	f.Add("1.2.3.0/24 1.2.2.0/24 1.2.3.4 9.9.9.9/32")
	f.Add("10.0.0.0/7 8.0.0.0/7 junk 1.1.1.1/33")
	f.Fuzz(func(t *testing.T, list string) {
		items := strings.Fields(list)
		out := CoalesceIPv4(items)
		var outs []netip.Prefix
		for _, o := range out {
			p, ok := parsePrefix4(o)
			if !ok {
				t.Fatalf("output %q is not a v4 prefix", o)
			}
			outs = append(outs, p)
		}
		for i := range outs {
			for j := range outs {
				if i != j && outs[i].Overlaps(outs[j]) {
					t.Fatalf("outputs overlap: %v %v (from %q)", outs[i], outs[j], list)
				}
			}
		}
		for _, it := range items {
			in, ok := parsePrefix4(it)
			if !ok {
				continue
			}
			covered := false
			for _, o := range outs {
				if prefixContains(o, in) {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("input %v not covered by %v", in, outs)
			}
		}
	})
}
