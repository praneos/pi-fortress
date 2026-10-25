package policycompile

import (
	"slices"
	"strings"
	"testing"
)

// DNSInputs names the operator block lists of both segments and no file
// that pf fetch writes. A feed refresh must not flush the resolved sets.
func TestDNSInputsAreOperatorListsOnly(t *testing.T) {
	in := DNSInputs()
	for _, want := range []string{"blacklist.domains", "house.domains", "never_block.domains", "house_never_block.domains", "doh.domains.local"} {
		if !slices.Contains(in, want) {
			t.Errorf("DNSInputs %v has no %s", in, want)
		}
	}
	for _, s := range Segments {
		if slices.Contains(in, s.Generated("domains")) {
			t.Errorf("DNSInputs has the feed list %s", s.Generated("domains"))
		}
	}
	for _, f := range in {
		if strings.HasPrefix(f, "generated/") || f == HouseVPNFile {
			t.Errorf("DNSInputs has the feed file %s", f)
		}
	}
}
