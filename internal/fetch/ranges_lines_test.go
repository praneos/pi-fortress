package fetch

import (
	"strings"
	"testing"
	"time"
)

// A ranges feed with many lines that are not rows is refused. The read
// stops at the first line over the cap, so a small gzip of many such lines
// uses little time and little memory. Before the cap, 128 MiB of empty
// lines took some seconds and 2 GiB of allocations.
func TestParseRangesRefusesManyLinesThatAreNotRows(t *testing.T) {
	for name, body := range map[string]string{
		"gzip, empty lines":        string(gzipped(t, strings.Repeat("\n", 8<<20))),
		"gzip, short lines":        string(gzipped(t, strings.Repeat("x\ty\tz\n", 1<<20))),
		"gzip, blank lines":        string(gzipped(t, strings.Repeat(" \r\n", 2<<20))),
		"plain, lines with no tab": strings.Repeat("1.2.3.4 5.6.7.8 64496\n", 1<<16),
	} {
		var err error
		start := time.Now()
		allocs := testing.AllocsPerRun(1, func() {
			_, _, err = parseRanges(body, 1_000_000)
		})
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: parseRanges took %v", name, d)
		}
		if err == nil || !strings.Contains(err.Error(), "not rows") {
			t.Errorf("%s: err %v, want a refusal", name, err)
		}
		// One string and two parse errors for each line that is not a
		// row, and some for the gzip reader and the scanner.
		if max := float64(4*maxRangesBadLines + 1000); allocs > max {
			t.Errorf("%s: %.0f allocations, want at most %.0f", name, allocs, max)
		}
	}
}

// A row with ASN 0 and an IPv6 row are rows: the table does not use them,
// but they do not count against the cap. Lines that are not rows up to the
// cap are skipped; one more line refuses the feed.
func TestParseRangesBadLineCap(t *testing.T) {
	// eyeRanges has one line that is not a row.
	atCap := eyeRanges +
		strings.Repeat("\n", maxRangesBadLines-1) +
		strings.Repeat("192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n", 3*maxRangesBadLines) +
		strings.Repeat("2001:db8::\t2001:db8::ffff\t64496\tZZ\tV6\n", 3*maxRangesBadLines)
	for _, body := range []string{atCap, string(gzipped(t, atCap))} {
		items, _, err := parseRanges(body, 100)
		if err != nil || len(items) != 6 {
			t.Fatalf("at the cap: %d items, %v; want 6 items", len(items), err)
		}
	}
	over := atCap + "not a row\n"
	for _, body := range []string{over, string(gzipped(t, over))} {
		if _, _, err := parseRanges(body, 100); err == nil {
			t.Error("a feed with one line over the cap was read")
		}
	}
}
