package dnsd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
)

// jsonHarness is newAliasHarness with the transaction log instead of
// dnsmasq's two lines. Everything else is the same box.
func jsonHarness(t *testing.T, sinkholed []string, table map[string][4]byte) *harness {
	t.Helper()
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "blocked-domains.conf")
	var lines []string
	for _, n := range sinkholed {
		lines = append(lines, "address=/"+n+"/0.0.0.0")
	}
	if err := os.WriteFile(sinkPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, table, nil, 60)
	nft := &fakeNFT{}
	logPath := filepath.Join(dir, "dns.jsonl")
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   0,
		NFT:      nft,
		Now:      func() time.Time { return now },
		Segments: []Segment{{
			Iface:         "lo",
			IP:            netip.MustParseAddr("127.0.0.1"),
			Upstream:      up.addr(),
			SinkholeFiles: []string{sinkPath},
			NFTSet:        "resolved_v4",
			LogPath:       logPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	return &harness{srv: srv, nft: nft, up: up, log: logPath, now: func() time.Time { return now }}
}

// events reads the log back as transactions.
func (h *harness) events(t *testing.T) []dnslog.Event {
	t.Helper()
	b, err := os.ReadFile(h.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []dnslog.Event
	for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if ln == "" {
			continue
		}
		ev, ok := dnslog.ParseEvent(ln)
		if !ok {
			t.Fatalf("log line is not an event: %s", ln)
		}
		out = append(out, ev)
	}
	return out
}

// One query is one row. The row names the asker. The asker is all that
// the reply line could not say.
func TestOneQueryIsOneRowNamingTheAsker(t *testing.T) {
	h := jsonHarness(t, []string{"ads.test"}, map[string][4]byte{"good.test": {1, 2, 3, 4}})
	h.ask(t, "good.test", dnsmessage.TypeA)

	evs := h.events(t)
	if len(evs) != 1 {
		t.Fatalf("%d rows for one query, want 1: %+v", len(evs), evs)
	}
	want := dnslog.Event{
		T: "2026-09-18T10:00:00Z", Src: "10.77.0.10", Name: "good.test",
		QType: "A", Act: dnslog.ActResolved, Answer: "1.2.3.4",
	}
	if evs[0] != want {
		t.Fatalf("row:\n got %+v\nwant %+v", evs[0], want)
	}
}

func TestVerdictsTheTextFormatCouldNotSay(t *testing.T) {
	h := jsonHarness(t, nil, map[string][4]byte{"good.test": {1, 2, 3, 4}})

	// filter-AAAA: policy suppression, not an absent record.
	h.ask(t, "good.test", dnsmessage.TypeAAAA)
	// domain-needed: a bare name never leaves the box.
	h.ask(t, "bare", dnsmessage.TypeA)
	// A name the upstream does not have.
	h.ask(t, "missing.test", dnsmessage.TypeA)

	evs := h.events(t)
	want := []string{dnslog.ActFiltered, dnslog.ActNXDomain, dnslog.ActNXDomain}
	if len(evs) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(evs), len(want), evs)
	}
	for i, a := range want {
		if evs[i].Act != a {
			t.Fatalf("row %d act=%q, want %q: %+v", i, evs[i].Act, a, evs[i])
		}
	}
	// A filtered row carries no address, because none was returned.
	if evs[0].Answer != "" {
		t.Fatalf("a filtered row carries an address: %+v", evs[0])
	}
}

// Before, a query that this resolver does not implement had no reply
// line, because the text format has no word for a refusal. The query line
// was alone, and it looked like an answer that had not arrived. Now the
// row shows the refusal.
func TestARefusedQueryIsNowOnTheRecord(t *testing.T) {
	h := jsonHarness(t, nil, map[string][4]byte{"good.test": {1, 2, 3, 4}})

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("good.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassCHAOS}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp := h.srv.answer(ctx, h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0); resp == nil {
		t.Fatal("no reply to a CHAOS query")
	}

	evs := h.events(t)
	if len(evs) != 1 || evs[0].Act != dnslog.ActRefused {
		t.Fatalf("want one refused row: %+v", evs)
	}
	if evs[0].Src != "10.77.0.10" {
		t.Fatalf("a refused row must still name the asker: %+v", evs[0])
	}
}

// The daemon must refuse a log_format that stays in dns.json. It must not
// ignore it. "text" was the two-line format of dnsmasq. An operator who
// writes it wants the old shape back. A box that accepted the key and
// wrote transactions anyway would tell the operator nothing.
func TestARetiredLogFormatIsRefused(t *testing.T) {
	for _, c := range []struct {
		format string
		ok     bool
	}{{"", true}, {"jsonl", true}, {"text", false}, {"json", false}, {"JSONL", false}} {
		body := `{"listen":53,"nft_table":"inet fortress","log_format":"` + c.format + `",
		  "segments":[{"iface":"lo","ip":"127.0.0.1","upstream":"9.9.9.9:53","nft_set":"resolved_v4"}]}`
		_, err := ParseConfig(strings.NewReader(body))
		if c.ok && err != nil {
			t.Fatalf("log_format %q: %v", c.format, err)
		}
		if c.ok {
			continue
		}
		if err == nil {
			t.Fatalf("log_format %q was accepted", c.format)
		}
		// The message must name the key. If not, an operator must read the whole
		// file to find what it meant.
		if !strings.Contains(err.Error(), "log_format") {
			t.Fatalf("error does not name the key: %v", err)
		}
	}
}
