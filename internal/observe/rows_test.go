package observe

import (
	"strings"

	"pi-fortress/internal/dnslog"
)

// rows renders transactions as the resolver writes them. Thus a test
// fixture says what occurred, not how it was spelt before. The old
// fixtures were the two lines of dnsmasq -- a query line and a reply line
// per transaction. This package no longer reads that format.
func rows(evs ...dnslog.Event) string {
	var b strings.Builder
	for _, ev := range evs {
		b.WriteString(dnslog.EventLine(ev) + "\n")
	}
	return b.String()
}

// resolved, blocked and filtered name the three verdicts the fixtures
// reach for, short enough to keep a table readable.
func resolved(src, name, answer string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: "A", Act: dnslog.ActResolved, Answer: answer}
}

func blocked(src, name string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: "A", Act: dnslog.ActBlocked, Answer: "0.0.0.0"}
}

func filtered(src, name, qtype string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: qtype, Act: dnslog.ActFiltered}
}

func nodata(src, name, qtype string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: qtype, Act: dnslog.ActNodata}
}

func nxdomain(src, name string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: "A", Act: dnslog.ActNXDomain}
}

// dropped is a query that left no response at all. The text log could not
// say so -- it used a query line and then nothing. Thus a reader had to
// infer it from a pair that never completed.
func dropped(src, name, qtype string) dnslog.Event {
	return dnslog.Event{Src: src, Name: name, QType: qtype, Act: dnslog.ActDropped}
}

// suppressed is the summary of the resolver itself for queries that it
// answered with nothing, because a client was over budget. listed picks
// the bucket reserved for names on the sinkhole list.
func suppressed(src string, n int, listed bool) dnslog.Event {
	return dnslog.Event{Src: src, Act: dnslog.ActSuppressed, N: n, Listed: listed}
}
