package dnslog

import (
	"reflect"
	"testing"
)

func TestEventLineRoundTrips(t *testing.T) {
	for _, ev := range []Event{
		{T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Name: "example.com", QType: "A", Act: ActResolved, Answer: "93.184.216.34"},
		{T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Name: "ads.example", QType: "A", Act: ActBlocked, Answer: "0.0.0.0"},
		{T: "2026-09-18T10:00:00Z", Src: "10.78.0.5", Name: "x.test", QType: "AAAA", Act: ActFiltered, Seg: "house"},
		{T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Act: ActSuppressed, N: 42, Listed: true},
		{T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Name: "gone.test", QType: "A", Act: ActDropped},
	} {
		got, ok := ParseEvent(EventLine(ev))
		if !ok {
			t.Fatalf("%s did not parse back", EventLine(ev))
		}
		if !reflect.DeepEqual(got, ev) {
			t.Fatalf("round trip changed the event:\n got %+v\nwant %+v", got, ev)
		}
	}
}

// Before, the code discarded a name with whitespace or quotes in it.
// The text format used whitespace as the separator. Thus the code never
// wrote a record that it could not read back the same. JSON quotes and
// escapes, so a hostile name logs with no change.
func TestEventCarriesWhatTheTextFormatDropped(t *testing.T) {
	hostile := "a b\tc\"d\\e"
	ev := Event{T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Name: hostile, QType: "A", Act: ActResolved, Answer: "1.2.3.4"}
	got, ok := ParseEvent(EventLine(ev))
	if !ok || got.Name != hostile {
		t.Fatalf("JSONL lost %q: %+v ok=%v", hostile, got, ok)
	}
}

func TestParseEventRefusesARowWithNoVerdict(t *testing.T) {
	for _, line := range []string{
		`{"t":"2026-09-18T10:00:00Z","src":"10.77.0.10","name":"x.test"}`,
		`{"act":`,
		``,
		`not json at all`,
	} {
		if ev, ok := ParseEvent(line); ok {
			t.Fatalf("%q parsed as %+v", line, ev)
		}
	}
}

// A rate-limit summary is a row like all other rows (same file, same
// parser). It is not a third line shape with its own grammar.
func TestSuppressedIsARowLikeAnyOther(t *testing.T) {
	var r Reader
	want := []Event{{Src: "10.77.0.10", Act: ActSuppressed, N: 9, Listed: true}}
	if got := r.Feed(EventLine(want[0])); !reflect.DeepEqual(got, want) {
		t.Fatalf("\n got %+v\nwant %+v", got, want)
	}
	if got := r.Flush(); len(got) != 0 {
		t.Fatalf("the reader held something back: %+v", got)
	}
}

// The code discards all lines that are not rows. The two dnsmasq lines
// come here on a box with a log from before the cutover. A half-written
// line comes here when a pass reads while the writer is in the middle of
// a row. Neither can become a transaction or be held for a later line.
func TestTheReaderDropsWhatIsNotARow(t *testing.T) {
	var r Reader
	for _, line := range []string{
		"Sep  5 10:00:00 dnsmasq[1]: query[A] example.com from 10.77.0.10",
		"reply example.com is 93.184.216.34",
		"suppressed 5 queries from 10.77.0.10",
		`{"t":"2026-09-18T10:00:00Z","src":"10.77.0.10","na`,
		"",
	} {
		if evs := r.Feed(line); len(evs) != 0 {
			t.Fatalf("%q became %+v", line, evs)
		}
	}
	if evs := r.Flush(); len(evs) != 0 {
		t.Fatalf("the reader held state across lines: %+v", evs)
	}
}

func FuzzEventRoundTrip(f *testing.F) {
	f.Add("10.77.0.10", "example.com", "A", ActResolved, "1.2.3.4", "house", 0, false)
	f.Add("10.77.0.10", "", "", ActSuppressed, "", "", 5, true)
	f.Add("", "a b\tc", "TYPE65", ActBlocked, "0.0.0.0", "", 0, false)
	f.Fuzz(func(t *testing.T, src, name, qtype, a, answer, seg string, n int, listed bool) {
		if a == "" {
			t.Skip("a row with no verdict is not an event")
		}
		ev := Event{T: "2026-09-18T10:00:00Z", Src: src, Name: name, QType: qtype, Act: a, Answer: answer, Seg: seg, N: n, Listed: listed}
		line := EventLine(ev)
		got, ok := ParseEvent(line)
		if !ok {
			t.Fatalf("%q did not parse back", line)
		}
		// The important invariant is write, read and write again. The
		// first write can change invalid UTF-8. After that, the row is a
		// fixed point. This test excludes the failure where a reader sees
		// an event that is different from the one on disk.
		if again := EventLine(got); again != line {
			t.Fatalf("round trip changed the line:\n got %s\nwant %s", again, line)
		}
		// For all field values, one event is one line.
		for i := 0; i < len(line); i++ {
			if line[i] == '\n' {
				t.Fatalf("a newline survived into the line: %q", line)
			}
		}
	})
}

// An upstream failure rcode is never a resolution. Before, the resolver
// wrote "RCODESERVERFAILURE" and this mapped it to resolved.
func TestActOfFailureRcodes(t *testing.T) {
	for answer, want := range map[string]string{
		"SERVFAIL": ActServfail, "FORMERR": ActServfail, "NOTIMP": ActServfail,
		"RCODE6": ActServfail, "RCODE23": ActServfail, "REFUSED": ActRefused,
		"NXDOMAIN": ActNXDomain, "NODATA": ActNodata, "0.0.0.0": ActBlocked,
		"192.0.2.1": ActResolved,
	} {
		if got := ActOf(answer); got != want {
			t.Errorf("%s: %s, want %s", answer, got, want)
		}
	}
}
