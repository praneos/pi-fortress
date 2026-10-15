package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/dnslog"
)

func TestRegistrableDomain(t *testing.T) {
	cases := []struct{ name, want string }{
		{"example.com", "example.com"},
		{"example.com.", "example.com"},
		{"a.example.com", "example.com"},
		{"deadbeef.tun.example.com", "example.com"},
		{"co.uk", "co.uk"},
		{"evil.co.uk", "evil.co.uk"},
		{"a.b.evil.co.uk", "evil.co.uk"},
		{"shop.com.au", "shop.com.au"},
		{"a.b.shop.com.au", "shop.com.au"},
		{"bank.co.in", "bank.co.in"},
		{"pf-open-echo.test", "pf-open-echo.test"},
		{"q1-abc.pf-open-echo.test", "pf-open-echo.test"},
		// co.ve is a two-level suffix that the table does not carry. Thus
		// the approximation names the registry and folds all registrants
		// under it together. The comment on twoLevelSuffixes says that the
		// miss can only over-count. This pins what the miss looks like.
		{"a.b.example.co.ve", "co.ve"},
		{"localhost", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := registrableDomain(c.name); got != c.want {
			t.Errorf("%q: %q, want %q", c.name, got, c.want)
		}
	}
}

// b32Label is a 40-character label of the alphabet that a tunnel encodes
// with, distinct for each i under a thousand.
func b32Label(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 40)
	for j := range b {
		b[j] = alphabet[(j*11+7)%32]
	}
	b[0], b[1] = alphabet[i%32], alphabet[(i/32)%32]
	return string(b)
}

func newTunObserver(names int) (*Observer, *volClock, *State) {
	c := &volClock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	o := &Observer{TunnelNames: names, Now: c.now}
	return o, c, o.empty()
}

// feed sends n queries of one shape at the clock's current minute.
func feed(o *Observer, st *State, src string, n int, qtype string, name func(i int) string) {
	for i := range n {
		o.trackTunnel(st, "", name(i), src, qtype)
	}
}

// TestTunnelFiresOnEachRule and TestTunnelStaysSilent are the two halves
// of the heuristic: what it is for, and what it must not call a tunnel.
func TestTunnelFiresOnEachRule(t *testing.T) {
	cases := []struct {
		name       string
		queries    int
		qtype      string
		label      func(i int) string
		wantDetail string
	}{
		{
			// A hundred and twenty short names is the distinct-name
			// rule by itself: nothing about one of them is odd.
			"a hundred and twenty names in a minute",
			120, "A", func(i int) string { return fmt.Sprintf("d%d.tun.example", i) },
			"120 names/min, labels avg 3 max 4",
		},
		{
			// A hundred and fifty base32 labels, the shape of a real
			// tunnel. It does not wait for the hundred and fifty: on the
			// agent segment, three of those labels are already the sign
			// (the house needs twenty, TestTunnelHouseFloors). The event
			// fires as soon as a rule is met, not at the end of the
			// minute.
			"a hundred and fifty base32 names in a minute",
			150, "A", func(i int) string { return b32Label(i) + ".tun.example" },
			"3 names/min, labels avg 40 max 40",
		},
		{
			"short names, but they all ask for TXT",
			20, "TXT", func(i int) string { return fmt.Sprintf("d%d.tun.example", i) },
			"20 names/min, labels avg 2 max 3, txt 100%",
		},
		{
			"NULL comes through as its number and counts the same",
			20, "TYPE10", func(i int) string { return fmt.Sprintf("d%d.tun.example", i) },
			"20 names/min, labels avg 2 max 3, txt 100%",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, clk, st := newTunObserver(120)
			feed(o, st, "10.77.0.10", c.queries, c.qtype, c.label)
			if len(st.Events) != 1 {
				t.Fatalf("events %+v", st.Events)
			}
			e := st.Events[0]
			if e.Threat != "dns_tunnel" || e.Segment != "agent" || e.Src != "10.77.0.10" || e.Dst != "tun.example" {
				t.Fatalf("event %+v", e)
			}
			if e.Detail != c.wantDetail {
				t.Fatalf("detail %q, want %q", e.Detail, c.wantDetail)
			}
			if !e.T.Equal(clk.t) || !e.Alert() {
				t.Fatalf("a tunnel row is noticed, never stopped: %+v", e)
			}
		})
	}
}

// TestTunnelStaysSilent is the false-positive list. Each of these is
// traffic that a working box makes. Each one is silent on its numbers
// alone -- the heuristic has no name that any of them match.
func TestTunnelStaysSilent(t *testing.T) {
	cases := []struct {
		name    string
		queries int
		qtype   string
		label   func(i int) string
	}{
		{
			// Machine-generated, long-ish, and there are only ever a
			// handful of them in a minute.
			"CDN shards with generated labels",
			25, "A", func(i int) string { return fmt.Sprintf("r%d---sn-abc123def456.googlevideo.com", i) },
		},
		{
			// One name per address by construction: a sweep would beat
			// all distinct-name thresholds and mean nothing.
			"a reverse-lookup sweep",
			200, "PTR", func(i int) string { return fmt.Sprintf("%d.0.78.10.in-addr.arpa", i) },
		},
		{
			// The DNS itest of this repo, which digs fifteen nonced
			// names at the Pi. Nothing in the product knows that name.
			// It is silent because fifteen is not twenty.
			"the segment DNS itest's fifteen nonced names",
			15, "A", func(i int) string { return fmt.Sprintf("m%d-9f3c21.pf-open-echo.test", i) },
		},
		{
			// The flood itests send one name again and again. That is a
			// rate-limit test, not a payload.
			"a flood of one repeated name",
			500, "A", func(i int) string { return "example.com" },
		},
		{
			// A browser that opens a busy page: many names, all typed by
			// somebody, spread over several domains.
			"an ordinary page load",
			60, "A", func(i int) string { return fmt.Sprintf("cdn%d.site%d.example", i%3, i) },
		},
		{
			"a handful of TXT lookups is not a TXT tunnel",
			19, "TXT", func(i int) string { return fmt.Sprintf("d%d.tun.example", i) },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, _, st := newTunObserver(120)
			feed(o, st, "10.77.0.10", c.queries, c.qtype, c.label)
			if len(st.Events) != 0 {
				t.Fatalf("events %+v", st.Events)
			}
		})
	}
}

// TestTunnelWindowAndDebounce holds the minute arithmetic, and the ten
// minutes that one (client, domain) pair waits before it reports again.
func TestTunnelWindowAndDebounce(t *testing.T) {
	name := func(i int) string { return b32Label(i) + ".tun.example" }
	t.Run("a minute's counts do not carry into the next", func(t *testing.T) {
		o, clk, st := newTunObserver(120)
		base := clk.t
		// Two hundred names, but never more than a hundred in a minute,
		// and the labels are too short for the label rule.
		short := func(i int) string { return fmt.Sprintf("d%d.tun.example", i) }
		feed(o, st, "10.77.0.10", 100, "A", short)
		clk.t = base.Add(time.Minute)
		feed(o, st, "10.77.0.10", 100, "A", func(i int) string { return short(i + 100) })
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("one pair speaks once in ten minutes", func(t *testing.T) {
		o, clk, st := newTunObserver(120)
		base := clk.t
		feed(o, st, "10.77.0.10", 150, "A", name)
		for _, m := range []int{1, 5, 9} {
			clk.t = base.Add(time.Duration(m) * time.Minute)
			feed(o, st, "10.77.0.10", 150, "A", name)
			if len(st.Events) != 1 {
				t.Fatalf("minute %d: events %+v", m, st.Events)
			}
		}
		clk.t = base.Add(10 * time.Minute)
		feed(o, st, "10.77.0.10", 150, "A", name)
		if len(st.Events) != 2 {
			t.Fatalf("after ten minutes: events %+v", st.Events)
		}
	})
	t.Run("the debounce is per client and per domain", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		feed(o, st, "10.77.0.10", 150, "A", name)
		feed(o, st, "10.77.0.11", 150, "A", name)
		feed(o, st, "10.77.0.10", 150, "A", func(i int) string { return b32Label(i) + ".other.example" })
		if len(st.Events) != 3 {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("zero turns the signal off", func(t *testing.T) {
		o, _, st := newTunObserver(0)
		feed(o, st, "10.77.0.10", 300, "TXT", name)
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
}

// TestTunnelTableEvictsTheColdestWindows holds the memory bound.
func TestTunnelTableEvictsTheColdestWindows(t *testing.T) {
	o, clk, st := newTunObserver(120)
	base := clk.t
	for i := range maxTunnelDomains {
		clk.t = base.Add(time.Duration(i) * time.Minute)
		o.trackTunnel(st, "", fmt.Sprintf("a.d%d.example", i), "10.77.0.10", "A")
	}
	if len(o.tun) != maxTunnelDomains {
		t.Fatalf("table %d, want %d", len(o.tun), maxTunnelDomains)
	}
	clk.t = base.Add(time.Duration(maxTunnelDomains) * time.Minute)
	o.trackTunnel(st, "", "a.newcomer.example", "10.77.0.10", "A")
	if want := maxTunnelDomains - tunnelEvict + 1; len(o.tun) != want {
		t.Fatalf("after eviction %d, want %d", len(o.tun), want)
	}
	if _, ok := o.tun["agent/10.77.0.10/d0.example"]; ok {
		t.Fatal("the least recently active window survived")
	}
	if _, ok := o.tun["agent/10.77.0.10/newcomer.example"]; !ok {
		t.Fatal("the window that forced the eviction was not kept")
	}
	if len(st.Events) != 0 {
		t.Fatalf("one name a domain is nobody's tunnel: %+v", st.Events)
	}
}

// TestTunnelFromTheQueryLog runs the signal as it runs on the Pi: over
// the rows that the resolver wrote, with the sinkhole and NXDOMAIN
// verdicts that the zone of a tunnel can really get, and with the
// rate-limit summary of the resolver itself next to them.
func TestTunnelFromTheQueryLog(t *testing.T) {
	dir := t.TempDir()
	evs := make([]dnslog.Event, 0, 152)
	evs = append(evs, suppressed("10.78.0.20", 340, false))
	for i := range 150 {
		name := b32Label(i) + ".tun.example"
		ev := resolved("10.78.0.20", name, "203.0.113.5")
		if i%3 == 0 {
			ev = nxdomain("10.78.0.20", name)
		}
		evs = append(evs, ev)
	}
	// Another client, ordinary traffic, in the same log.
	evs = append(evs, resolved("10.78.0.21", "www.example.com", "93.184.216.34"))
	log := filepath.Join(dir, "dns-house.jsonl")
	if err := os.WriteFile(log, []byte(rows(evs...)), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	o := &Observer{TunnelNames: 120, Now: func() time.Time { return now }}
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), "10.78.0.0/24", "house")
	var tun []Event
	for _, e := range st.Events {
		if e.Threat == "dns_tunnel" {
			tun = append(tun, e)
		}
	}
	if len(tun) != 1 {
		t.Fatalf("dns_tunnel events %+v (all: %+v)", tun, st.Events)
	}
	e := tun[0]
	if e.Segment != "house" || e.Src != "10.78.0.20" || e.Dst != "tun.example" {
		t.Fatalf("event %+v", e)
	}
	// The suppression is not evidence and fires nothing. But for a client
	// that the resolver already throttled, the same line says so.
	if want := "20 names/min, labels avg 40 max 40, 340 suppressed"; e.Detail != want {
		t.Fatalf("detail %q, want %q", e.Detail, want)
	}
}

func TestTunnelShowsUnderAlerts(t *testing.T) {
	var out strings.Builder
	o, _, st := newTunObserver(120)
	o.Stdout = &out
	feed(o, st, "10.77.0.10", 150, "A", func(i int) string { return b32Label(i) + ".tun.example" })
	o.Show(st)
	text := out.String()
	alerts := strings.Index(text, "ALERTS (1)")
	if !strings.Contains(text, "BLOCKED (0)") || alerts < 0 {
		t.Fatalf("headings:\n%s", text)
	}
	if !strings.Contains(text[alerts:], "dns_tunnel 3 names/min, labels avg 40 max 40") {
		t.Fatalf("no dns_tunnel row under ALERTS:\n%s", text)
	}
}

// The agent segment asks for addresses. One TXT question with a sentence
// in front of the zone is the form of a question to an LLM over DNS, and a
// question needs only one. Thus on the agent segment, one is enough by
// itself. The house makes the same query for its own reasons, and keeps
// the minimums of the minute.
func TestTunnelAgentTXTQuestion(t *testing.T) {
	const q = "what-is-the-capital-of-france.llm.example"
	t.Run("agent", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		o.trackTunnel(st, "", q, "10.77.0.10", "TXT")
		if len(st.Events) != 1 {
			t.Fatalf("events %+v", st.Events)
		}
		e := st.Events[0]
		if e.Threat != "dns_tunnel" || e.Dst != "llm.example" || !strings.Contains(e.Detail, "TXT with a 29-character label") {
			t.Fatalf("event %+v", e)
		}
	})
	t.Run("house", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		o.trackTunnel(st, "house", q, "10.78.0.20", "TXT")
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("a service label is short", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		o.trackTunnel(st, "", "_acme-challenge.example.com", "10.77.0.10", "TXT")
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
}

// TestTunnelHouseFloors pins that the three long names of the agent apply
// only to the agent: the house still needs the twenty of the minute.
func TestTunnelHouseFloors(t *testing.T) {
	o, _, st := newTunObserver(120)
	for i := range 19 {
		o.trackTunnel(st, "house", b32Label(i)+".tun.example", "10.78.0.20", "A")
	}
	if len(st.Events) != 0 {
		t.Fatalf("house fired under its floor: %+v", st.Events)
	}
	o.trackTunnel(st, "house", b32Label(19)+".tun.example", "10.78.0.20", "A")
	if len(st.Events) != 1 || st.Events[0].Detail != "20 names/min, labels avg 40 max 40" {
		t.Fatalf("events %+v", st.Events)
	}
}

// A name that the resolver refused because it carried a key is a block,
// not a notice. The operator gets one message per client, zone and rule in
// the debounce: an injected agent that retries in a loop is one message.
func TestKeyInDNSNameAlerts(t *testing.T) {
	dir := t.TempDir()
	o, clk, st := newTunObserver(120)
	o.NoticePath = filepath.Join(dir, "notice.jsonl")
	ev := dnslog.Event{Src: "10.77.0.10", Name: "evil.example", QType: "A", Act: dnslog.ActRefused, Rule: "anthropic_oat"}
	o.record(st, "", "10.77.0.0/24", ev)
	o.record(st, "", "10.77.0.0/24", ev)
	var keys []Event
	for _, e := range st.Events {
		if e.Threat == "dns_key" {
			keys = append(keys, e)
		}
	}
	if len(keys) != 1 {
		t.Fatalf("dns_key events %+v", st.Events)
	}
	e := keys[0]
	if e.Segment != "agent" || e.Dst != "evil.example" || e.Detail != "refused, rule anthropic_oat" || e.Alert() {
		t.Fatalf("event %+v", e)
	}
	raw, err := os.ReadFile(o.NoticePath)
	if err != nil || strings.Count(string(raw), "\n") != 1 || !strings.Contains(string(raw), `"threat":"dns_key"`) {
		t.Fatalf("notice %q %v", raw, err)
	}
	clk.t = clk.t.Add(tunnelDebounce)
	o.record(st, "", "10.77.0.0/24", ev)
	raw, _ = os.ReadFile(o.NoticePath)
	if strings.Count(string(raw), "\n") != 2 {
		t.Fatalf("after the debounce: %q", raw)
	}
}

// b32 is n characters of the alphabet of a tunnel, distinct for each i
// under a thousand.
func b32(i, n int) string {
	l := b32Label(i)
	for len(l) < n {
		l += b32Label(i + 1)
	}
	return l[:n]
}

// Before, the heuristic measured only the leftmost label. Thus a payload
// in the labels behind a one-character label never counted: for the
// heuristic, a.<52>.<52>.evil was a name of one-character labels. Now it
// measures the longest label to the left of the registrable domain, and
// the bytes of all of them.
func TestTunnelMeasuresThePayloadWhereverItSits(t *testing.T) {
	t.Run("an inner-label payload alerts", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		feed(o, st, "10.77.0.10", 3, "A", func(i int) string { return "a." + b32(i, 52) + "." + b32(i+500, 52) + ".evil.example" })
		if len(st.Events) != 1 || st.Events[0].Dst != "evil.example" {
			t.Fatalf("events %+v", st.Events)
		}
		if want := "3 names/min, labels avg 52 max 52, payload avg 105 max 105"; st.Events[0].Detail != want {
			t.Fatalf("detail %q, want %q", st.Events[0].Detail, want)
		}
	})
	t.Run("labels a character under the label rule are caught by their bytes", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		feed(o, st, "10.77.0.10", 3, "A", func(i int) string { return b32(i, 29) + "." + b32(i+500, 29) + ".evil.example" })
		if len(st.Events) != 1 {
			t.Fatalf("two 29-character labels a name: events %+v", st.Events)
		}
		o2, _, st2 := newTunObserver(120)
		for i := range 20 {
			o2.trackTunnel(st2, "house", b32(i, 29)+"."+b32(i+500, 29)+".evil.example", "10.78.0.20", "A")
		}
		if len(st2.Events) != 1 || !strings.Contains(st2.Events[0].Detail, "payload avg 58") {
			t.Fatalf("house, twenty names of two 29-character labels: %+v", st2.Events)
		}
	})
	t.Run("one 29-character label is under the label rule, as documented", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		feed(o, st, "10.77.0.10", 3, "A", func(i int) string { return b32(i, 29) + ".evil.example" })
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
		o, _, st = newTunObserver(120)
		feed(o, st, "10.77.0.10", 3, "A", func(i int) string { return b32(i, 30) + ".evil.example" })
		if len(st.Events) != 1 {
			t.Fatalf("30 characters: events %+v", st.Events)
		}
	})
	t.Run("benign CDN and cloud names stay silent", func(t *testing.T) {
		names := []string{
			"e1234.dscb.akamaiedge.net", "dualstack.reddit.map.fastly.net",
			"my-load-balancer-1234567890.us-west-2.elb.amazonaws.com",
			"ec2-54-12-34-56.us-west-2.compute.amazonaws.com",
			"rr3---sn-q4fl6n7s.googlevideo.com", "d111111abcdef8.cloudfront.net",
		}
		o, _, st := newTunObserver(120)
		for i := range 30 {
			o.trackTunnel(st, "", strings.Replace(names[i%len(names)], "1234", fmt.Sprintf("%04d", i), 1), "10.77.0.10", "A")
		}
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("a TXT question cut into short labels", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		o.trackTunnel(st, "", "what.is.the.capital.city.of.france.today.llm.example", "10.77.0.10", "TXT")
		if len(st.Events) != 1 {
			t.Fatalf("events %+v", st.Events)
		}
		o, _, st = newTunObserver(120)
		o.trackTunnel(st, "", "_acme-challenge.www.example.com", "10.77.0.10", "TXT")
		if len(st.Events) != 0 {
			t.Fatalf("acme: events %+v", st.Events)
		}
	})
}

// Before, rows read again after a restart, or a backlog read late, went
// into buckets by the clock that read them. Thus an hour of ordinary names
// went into one minute and made a tunnel. Now the buckets use the stamp of each row.
func TestTunnelBucketsRowsByTheirOwnTime(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	var evs []dnslog.Event
	for m := range 10 {
		for i := range 15 {
			ev := resolved("10.78.0.20", b32Label(m*15+i)+".tun.example", "203.0.113.5")
			ev.T = t0.Add(time.Duration(m)*time.Minute + time.Duration(i)*time.Second).Format(base.ISO)
			evs = append(evs, ev)
		}
	}
	log := filepath.Join(dir, "dns-house.jsonl")
	if err := os.WriteFile(log, []byte(rows(evs...)), 0644); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(2 * time.Hour)
	o := &Observer{TunnelNames: 120, Now: func() time.Time { return now }}
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), "10.78.0.0/24", "house")
	for _, e := range st.Events {
		if e.Threat == "dns_tunnel" {
			t.Fatalf("fifteen names a minute for ten minutes read as one minute: %+v", e)
		}
	}
	// The same rows inside one minute are the tunnel, stamped at the time
	// that the rows give.
	for i := range evs {
		evs[i].T = t0.Add(time.Duration(i%60) * time.Second).Format(base.ISO)
	}
	if err := os.WriteFile(log+"2", []byte(rows(evs...)), 0644); err != nil {
		t.Fatal(err)
	}
	o = &Observer{TunnelNames: 120, Now: func() time.Time { return now }}
	st = o.empty()
	o.ingestDNSLog(st, log+"2", filepath.Join(dir, "off2"), "10.78.0.0/24", "house")
	var tun []Event
	for _, e := range st.Events {
		if e.Threat == "dns_tunnel" {
			tun = append(tun, e)
		}
	}
	if len(tun) != 1 || tun[0].T.Before(t0) || tun[0].T.After(t0.Add(time.Minute)) {
		t.Fatalf("dns_tunnel events %+v", tun)
	}
}

// The zone that a dns_key alert names came from the query, and went into
// notice.jsonl raw. Control bytes (an escape sequence, a C1 CSI) got to
// pf alert and to each terminal that showed the row. Now each string that
// observe writes into a notice row, and the zone in the ring, is printable
// ASCII.
func TestNoticeRowsArePrintableASCII(t *testing.T) {
	dir := t.TempDir()
	o, _, st := newTunObserver(120)
	o.NoticePath = filepath.Join(dir, "notice.jsonl")
	zone := "ev\x1b[31mil.\u009b2Jexample"
	o.record(st, "", "10.77.0.0/24", dnslog.Event{Src: "10.77.0.10", Name: zone, QType: "A", Act: dnslog.ActRefused, Rule: "anthropic_oat\x07"})
	raw, err := os.ReadFile(o.NoticePath)
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]string
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	for k, v := range row {
		for _, c := range []byte(v) {
			if c < ' ' || c > '~' {
				t.Fatalf("notice %s = %q carries byte %#x", k, v, c)
			}
		}
	}
	if row["host"] != "ev?[31mil.??2Jexample" {
		t.Fatalf("host %q", row["host"])
	}
	for _, e := range st.Events {
		if strings.ContainsAny(e.Dst+e.Detail, "\x1b\x07\u009b") {
			t.Fatalf("the ring kept a control byte: %+v", e)
		}
	}
}
