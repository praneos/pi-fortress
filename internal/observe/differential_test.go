package observe

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/dnslog"
)

// The corpus test for log ingestion. One table of transactions, with all
// verdicts, several clients and qtypes, folded into a ledger that must
// hold exactly what the table says.
//
// It started as a differential test: the same table rendered into the
// two lines of dnsmasq and into rows, and a compare of the two ledgers.
// This showed that they agreed where the old format could express a
// transaction, and that the rows were correct where it could not. The old
// format is gone. Thus only the half that still has a meaning stays -- the counts.

const diffNet = "10.77.0.0/24"

// ingest writes body to a log and folds it into a fresh ledger.
func ingest(t *testing.T, now time.Time, body string) *State {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(log, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), diffNet, "")
	return st
}

// diffTable is the corpus: all verdicts, several clients, several qtypes,
// and names long enough to exercise the pending table.
func diffTable() []dnslog.Event {
	acts := []string{
		dnslog.ActResolved, dnslog.ActBlocked, dnslog.ActFiltered, dnslog.ActNodata,
		dnslog.ActNXDomain, dnslog.ActServfail, dnslog.ActDropped, dnslog.ActRefused,
	}
	// 7 clients and 3 qtypes against 8 verdicts: the counts are coprime,
	// so each client sees each verdict. With 6 clients they were not, and
	// half the verdicts of the table never got to half its clients.
	qtypes := []string{"A", "AAAA", "TYPE65"}
	var out []dnslog.Event
	for i := 0; i < 224; i++ {
		a := acts[i%len(acts)]
		ev := dnslog.Event{
			Src:   "10.77.0." + strconv.Itoa(10+i%7),
			Name:  "n" + strconv.Itoa(i) + ".test",
			QType: qtypes[i%len(qtypes)],
			Act:   a,
		}
		if a == dnslog.ActResolved {
			ev.Answer = "93.184.216." + strconv.Itoa(i%250+1)
		}
		out = append(out, ev)
	}
	// The budget summaries of the resolver itself, which both formats carry.
	out = append(out,
		dnslog.Event{Src: "10.77.0.11", Act: dnslog.ActSuppressed, N: 17, Listed: false},
		dnslog.Event{Src: "10.77.0.12", Act: dnslog.ActSuppressed, N: 5, Listed: true},
		dnslog.Event{Src: "untracked", Act: dnslog.ActSuppressed, N: 9, Listed: true},
	)
	return out
}

// The ledger holds what the rows say: every verdict, per client and in
// total.
func TestTheLedgerHoldsWhatTheRowsSay(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	table := diffTable()

	var jsonl strings.Builder
	for _, ev := range table {
		jsonl.WriteString(dnslog.EventLine(ev) + "\n")
	}
	expectCounts(t, ingest(t, now, jsonl.String()), table)
}

// expectCounts asserts that the ledger holds what the table says, per
// client and in total, independent of either log format.
func expectCounts(t *testing.T, st *State, table []dnslog.Event) {
	t.Helper()
	type want struct{ queries, blocked, filtered uint32 }
	per := map[string]*want{}
	names := map[string]bool{}
	at := func(src string) *want {
		if per[src] == nil {
			per[src] = &want{}
		}
		return per[src]
	}
	for _, ev := range table {
		if ev.Act == dnslog.ActSuppressed {
			// "untracked" is not an address, so it counts only to the
			// hourly series and never creates a client.
			if ev.Src == "untracked" {
				continue
			}
			w := at(ev.Src)
			w.queries += uint32(ev.N)
			if ev.Listed {
				w.blocked += uint32(ev.N)
			}
			continue
		}
		w := at(ev.Src)
		w.queries++
		names[strings.ToLower(ev.Name)] = true
		switch ev.Act {
		case dnslog.ActBlocked:
			w.blocked++
		case dnslog.ActFiltered:
			w.filtered++
		}
	}
	if len(st.DNS) != len(names) {
		t.Fatalf("%d names in the ledger, want %d", len(st.DNS), len(names))
	}
	if len(st.Clients) != len(per) {
		t.Fatalf("%d clients in the ledger, want %d: %v", len(st.Clients), len(per), st.Clients)
	}
	for src, w := range per {
		c := st.Clients["agent/"+src]
		if c == nil {
			t.Fatalf("no client for %s: %v", src, st.Clients)
		}
		if c.Queries != w.queries || c.Blocked != w.blocked || c.Filtered != w.filtered {
			t.Fatalf("%s: queries=%d blocked=%d filtered=%d, want %d/%d/%d",
				src, c.Queries, c.Blocked, c.Filtered, w.queries, w.blocked, w.filtered)
		}
	}
}

// This was two defects in one. A reader that paired a reply to a query by
// name attributed interleaved traffic incorrectly. Past its limit, it
// emptied the pending table into rows that said the queries went
// unresolved. Now there is no limit to reach, because nothing is held
// between lines. This test proves it -- six thousand transactions, each one counted.
func TestTheReaderHoldsNoPendingState(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	var jsonl strings.Builder
	const n = 6000
	for i := 0; i < n; i++ {
		jsonl.WriteString(dnslog.EventLine(dnslog.Event{
			Src: "10.77.0.10", Name: "n" + strconv.Itoa(i) + ".test", QType: "A",
			Act: dnslog.ActResolved, Answer: "1.2.3.4",
		}) + "\n")
	}
	st := ingest(t, now, jsonl.String())
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Queries != n {
		t.Fatalf("want all %d queries counted: %+v", n, c)
	}
}
