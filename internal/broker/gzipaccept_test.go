package broker

import "testing"

// Accept-Encoding carries qvalues. q=0 is not a preference. It is a
// prohibition (RFC 9110 12.5.3): the coding is not acceptable at all. A
// client that sends "*, gzip;q=0" excludes gzip by name. The wildcard next
// to it does not put gzip back: the more specific entry decides. Before,
// acceptsGzip cut each entry at the semicolon and returned true on the
// first gzip, x-gzip or *. Thus it read the one form that says "not this
// one" as the form that says "any".
func TestAcceptsGzipHonoursQZero(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"gzip;q=1", true},
		{"gzip;q=0.5", true},
		{"gzip;q=0", false},
		{"gzip;q=0.000", false},
		{"x-gzip;q=0", false},
		{"*", true},
		{"*;q=0", false},
		// The wildcard must not override an explicit exclusion, in either
		// order of appearance.
		{"*, gzip;q=0", false},
		{"gzip;q=0, *", false},
		{"*;q=0, gzip", true},
		{"gzip, *;q=0", true},
		{"deflate, br", false},
		{"deflate, gzip;q=0", false},
		// Parameters beside q, and whitespace, are ordinary syntax.
		{"gzip ; q=0 ", false},
		{"gzip;a=b;q=0", false},
		{"identity;q=1, gzip;q=0", false},
	} {
		if got := acceptsGzip(tc.accept); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}
