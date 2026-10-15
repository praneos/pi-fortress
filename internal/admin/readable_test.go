package admin

import (
	"reflect"
	"testing"

	"pi-fortress/internal/dnslog"
)

// The house log screen shows raw log text to a person, but a row is for a
// parser. Thus the code unpacks it here. The dnsmasq lines that are still on
// disk from before the cutover pass through unchanged. Nothing reads them
// now, but a person can still look at them on the screen.
func TestReadableDNSUnpacksRowsAndLeavesLinesAlone(t *testing.T) {
	text := "Sep 18 10:00:00 dnsmasq[9]: query[A] a.test from 10.78.0.5"
	in := []string{
		text,
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:00Z", Src: "10.78.0.5", Name: "b.test", QType: "A", Act: dnslog.ActResolved, Answer: "1.2.3.4"}),
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:01Z", Src: "10.78.0.5", Name: "ads.test", QType: "A", Act: dnslog.ActBlocked, Answer: "0.0.0.0"}),
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:02Z", Src: "10.78.0.5", Name: "x.test", QType: "AAAA", Act: dnslog.ActFiltered}),
		dnslog.EventLine(dnslog.Event{T: "2026-09-18T10:00:03Z", Src: "10.78.0.5", Act: dnslog.ActSuppressed, N: 12, Listed: true}),
	}
	want := []string{
		text,
		"2026-09-18T10:00:00Z 10.78.0.5 A b.test resolved 1.2.3.4",
		"2026-09-18T10:00:01Z 10.78.0.5 A ads.test blocked 0.0.0.0",
		"2026-09-18T10:00:02Z 10.78.0.5 AAAA x.test filtered",
		"2026-09-18T10:00:03Z 10.78.0.5 suppressed 12 config queries",
	}
	if got := readableDNS(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}
