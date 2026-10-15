package observe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/dnslog"
)

const (
	deskNet = "10.79.0.0/24"
	deskIP  = "10.79.0.1"
	deskSrc = "10.79.0.2"
)

// ctLinePort is ctLine with the ports and protocol the case needs.
func ctLinePort(proto, src, dst string, sport, dport int) string {
	num := map[string]string{"tcp": "6", "udp": "17"}[proto]
	return fmt.Sprintf("ipv4     2 %s      %s 431999 ESTABLISHED src=%s dst=%s sport=%d dport=%d packets=9 bytes=900 src=%s dst=%s sport=%d dport=%d packets=9 bytes=900 [ASSURED] mark=0 zone=0 use=2",
		proto, num, src, dst, sport, dport, dst, src, dport, sport)
}

// poll is the conntrack of one Snapshot for one segment: the seen set
// rolls over as Snapshot rolls it.
func poll(o *Observer, st *State, segment, net, self string, lines ...string) {
	seen := map[string]int64{}
	o.ingestCT(st, strings.Join(lines, "\n"), segment, net, self, nil, seen)
	o.seenCT = seen
}

// destRows is the "dest" rows the first-seen log holds so far.
func destRows(t *testing.T, o *Observer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range bytes.Split(o.rows.Bytes(), []byte("\n")) {
		if len(ln) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(ln, &m); err != nil {
			t.Fatalf("row %q: %v", ln, err)
		}
		if m["kind"] == "dest" {
			out = append(out, m)
		}
	}
	return out
}

func newDestObserver(t *testing.T) (*Observer, *volClock, *State) {
	c := &volClock{t: time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)}
	o := &Observer{Now: c.now, JSONLPath: filepath.Join(t.TempDir(), "observe.jsonl"), FlushBytes: 1 << 30}
	return o, c, o.empty()
}

// The first contact of a plain segment with a destination is one row,
// named by what the resolver of the segment answered. The same destination
// again -- the next poll, a new connection, a different address of the
// same name -- gives no row.
func TestPlainSegmentFirstSeenDest(t *testing.T) {
	o, clk, st := newDestObserver(t)
	o.record(st, "desk", deskNet, dnslog.Event{Src: deskSrc, Name: "API.Example.com.", QType: "A", Act: dnslog.ActResolved, Answer: "93.184.216.34"})
	o.record(st, "desk", deskNet, dnslog.Event{Src: deskSrc, Name: "api.example.com", QType: "A", Act: dnslog.ActResolved, Answer: "93.184.216.35"})
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.34", 40000, 443))
	rows := destRows(t, o)
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	r := rows[0]
	if r["segment"] != "desk" || r["src"] != deskSrc || r["dst"] != "93.184.216.34" || r["name"] != "api.example.com" || r["dport"] != float64(443) || r["proto"] != "tcp" {
		t.Fatalf("row %v", r)
	}
	clk.t = clk.t.Add(time.Minute)
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.34", 40000, 443))
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.34", 40001, 443))
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.35", 40002, 443))
	if rows := destRows(t, o); len(rows) != 1 {
		t.Fatalf("a known destination wrote again: %v", rows)
	}
	if rec := st.Dests["desk"]["api.example.com:443/tcp"]; rec == nil || rec.LastSeen != "2026-10-04T10:01:00Z" || rec.FirstSeen != "2026-10-04T10:00:00Z" {
		t.Fatalf("rec %+v", rec)
	}
	// A different port, a different protocol, and an address that nothing
	// resolved are each new.
	poll(o, st, "desk", deskNet, deskIP,
		ctLinePort("tcp", deskSrc, "93.184.216.34", 40003, 8443),
		ctLinePort("udp", deskSrc, "93.184.216.34", 40004, 443),
		ctLinePort("tcp", deskSrc, "203.0.113.9", 40005, 22))
	rows = destRows(t, o)
	if len(rows) != 4 {
		t.Fatalf("rows %v", rows)
	}
	if _, named := rows[3]["name"]; named || rows[3]["dst"] != "203.0.113.9" {
		t.Fatalf("an unresolved address carries a name: %v", rows[3])
	}
}

// The name comes from the resolver of the desk. When the house resolves
// the same address, that says nothing about what the desk wanted to reach.
func TestPlainSegmentDestNameIsItsOwn(t *testing.T) {
	o, _, st := newDestObserver(t)
	o.record(st, "house", "10.78.0.0/24", dnslog.Event{Src: "10.78.0.20", Name: "video.example", QType: "A", Act: dnslog.ActResolved, Answer: "198.51.100.7"})
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "198.51.100.7", 40000, 443))
	rows := destRows(t, o)
	if len(rows) != 1 || rows[0]["name"] != nil {
		t.Fatalf("rows %v", rows)
	}
}

// The agent and the house have no dest table: the agent has the broker,
// and the house is the browsing of a household.
func TestDestIsPlainSegmentsOnly(t *testing.T) {
	o, _, st := newDestObserver(t)
	poll(o, st, "", "10.77.0.0/24", "10.77.0.1", ctLinePort("tcp", "10.77.0.10", "93.184.216.34", 40000, 443))
	poll(o, st, "house", "10.78.0.0/24", "10.78.0.1", ctLinePort("tcp", "10.78.0.20", "93.184.216.34", 40000, 443))
	if len(st.Dests) != 0 || len(destRows(t, o)) != 0 {
		t.Fatalf("dests %v", st.Dests)
	}
	if len(st.Flows) != 2 {
		t.Fatalf("the flow ledger changed: %v", st.Flows)
	}
}

// The table has a limit per segment and keeps the newest entries. The
// evicted entries are the coldest.
func TestPlainSegmentDestCap(t *testing.T) {
	o, clk, st := newDestObserver(t)
	for i := range maxSegDests + 1 {
		clk.t = clk.t.Add(time.Second)
		poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, fmt.Sprintf("203.0.%d.%d", 113+i/250, i%250+1), 40000, 443))
	}
	tab := st.Dests["desk"]
	if len(tab) > maxSegDests || len(tab) < maxSegDests-segDestEvict {
		t.Fatalf("%d entries", len(tab))
	}
	newest := fmt.Sprintf("203.0.%d.%d:443/tcp", 113+maxSegDests/250, maxSegDests%250+1)
	if tab[newest] == nil {
		t.Fatalf("the newest destination was evicted")
	}
	if tab["203.0.113.1:443/tcp"] != nil {
		t.Fatal("the coldest destination survived the eviction")
	}
	if n := len(destRows(t, o)); n != maxSegDests+1 {
		t.Fatalf("%d rows", n)
	}
}

// The table is ledger, not working memory: a restart reads it back and
// does not report each open connection again.
func TestPlainSegmentDestSurvivesRestart(t *testing.T) {
	o, _, st := newDestObserver(t)
	o.StatePath = filepath.Join(t.TempDir(), "observe.json")
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.34", 40000, 443))
	if err := o.Save(st); err != nil {
		t.Fatal(err)
	}
	o2, _, _ := newDestObserver(t)
	o2.StatePath = o.StatePath
	st2 := o2.Load()
	poll(o2, st2, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "93.184.216.34", 40000, 443))
	if rows := destRows(t, o2); len(rows) != 0 {
		t.Fatalf("rows after a restart %v", rows)
	}
	// A month idle and it is forgotten, segment table and all.
	expireDests(st2, time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC).Add(clientIdle+time.Hour))
	if len(st2.Dests) != 0 {
		t.Fatalf("dests %v", st2.Dests)
	}
}

func keyRules(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skip("no policy rules in this tree")
	}
	return p
}

const oatKey = "sk-ant-oat01-abcdefghijklmnopqrstuvwx"

// The resolver of a plain segment has no key rules. Thus a key in a query
// name goes out and gets an answer. Observe reports it as an alert, and
// keeps the key out of each copy that it makes.
func TestPlainSegmentKeyInDNSName(t *testing.T) {
	dir := t.TempDir()
	o, clk, st := newDestObserver(t)
	o.NoticePath = filepath.Join(dir, "notice.jsonl")
	o.KeyRulesPath = keyRules(t)
	o.loadKeyRules()
	if o.segKeys == nil {
		t.Fatal("rules did not load")
	}
	ev := dnslog.Event{Src: deskSrc, Name: oatKey + ".evil.example", QType: "A", Act: dnslog.ActResolved, Answer: "203.0.113.50"}
	o.record(st, "desk", deskNet, ev)
	o.record(st, "desk", deskNet, ev)
	var keys []Event
	for _, e := range st.Events {
		if e.Threat == "dns_key" {
			keys = append(keys, e)
		}
	}
	if len(keys) != 1 {
		t.Fatalf("events %+v", st.Events)
	}
	e := keys[0]
	if e.Segment != "desk" || e.Src != deskSrc || e.Dst != "evil.example" || e.Detail != "resolved, rule anthropic_oat" || !e.Alert() {
		t.Fatalf("event %+v", e)
	}
	raw, err := os.ReadFile(o.NoticePath)
	if err != nil || strings.Count(string(raw), "\n") != 1 || !strings.Contains(string(raw), `"where":"desk"`) {
		t.Fatalf("notice %q %v", raw, err)
	}
	poll(o, st, "desk", deskNet, deskIP, ctLinePort("tcp", deskSrc, "203.0.113.50", 40000, 443))
	state, _ := json.Marshal(st)
	for _, where := range []string{string(raw), string(state), o.rows.String()} {
		if strings.Contains(strings.ToLower(where), "sk-ant-oat01") {
			t.Fatalf("the key was copied: %s", where)
		}
	}
	if st.DNS["desk/evil.example"] == nil {
		t.Fatalf("the zone is not in the ledger: %v", st.DNS)
	}
	clk.t = clk.t.Add(tunnelDebounce)
	o.record(st, "desk", deskNet, ev)
	raw, _ = os.ReadFile(o.NoticePath)
	if strings.Count(string(raw), "\n") != 2 {
		t.Fatalf("after the debounce: %q", raw)
	}
	// A sinkholed name never left the box: it is a block, not an alert.
	o.record(st, "desk", deskNet, dnslog.Event{Src: deskSrc, Name: oatKey + ".other.example", QType: "A", Act: dnslog.ActBlocked})
	var sunk *Event
	for i := range st.Events {
		if e := &st.Events[i]; e.Threat == "dns_key" && e.Dst == "other.example" {
			sunk = e
		}
	}
	if sunk == nil || sunk.Detail != "blocked, rule anthropic_oat" || sunk.Alert() {
		t.Fatalf("sinkholed key %+v in %+v", sunk, st.Events)
	}
}

// The agent check is the check of its resolver: observe does not run its
// own check over agent or house rows, so nothing about those rows changes.
func TestKeyCheckLeavesAgentAndHouseAlone(t *testing.T) {
	o, _, st := newDestObserver(t)
	o.KeyRulesPath = keyRules(t)
	o.loadKeyRules()
	o.record(st, "", "10.77.0.0/24", dnslog.Event{Src: "10.77.0.10", Name: oatKey + ".evil.example", QType: "A", Act: dnslog.ActResolved})
	o.record(st, "house", "10.78.0.0/24", dnslog.Event{Src: "10.78.0.20", Name: oatKey + ".evil.example", QType: "A", Act: dnslog.ActResolved})
	if len(st.Events) != 0 {
		t.Fatalf("events %+v", st.Events)
	}
	if st.DNS[oatKey+".evil.example"] == nil {
		t.Fatalf("the agent row was rewritten: %v", st.DNS)
	}
}

// No rules file, no check, and one line saying so.
func TestKeyRulesMissing(t *testing.T) {
	var errs bytes.Buffer
	o := &Observer{KeyRulesPath: filepath.Join(t.TempDir(), "none"), Stderr: &errs}
	o.loadKeyRules()
	bad := filepath.Join(t.TempDir(), "empty.rules")
	if err := os.WriteFile(bad, nil, 0644); err != nil {
		t.Fatal(err)
	}
	o.KeyRulesPath = bad
	o.loadKeyRules()
	o.loadKeyRules()
	if o.segKeys != nil || strings.Count(errs.String(), "\n") != 1 {
		t.Fatalf("keys %v, stderr %q", o.segKeys, errs.String())
	}
}

// A plain segment gets the two extra tunnel rules of the agent: one TXT
// question with a sentence in front of the zone, and three long labels.
func TestTunnelPlainSegmentIsStrict(t *testing.T) {
	t.Run("txt", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		o.trackTunnel(st, "desk", "what-is-the-admin-password.llm.example", deskSrc, "TXT")
		if len(st.Events) != 1 || st.Events[0].Segment != "desk" || !strings.Contains(st.Events[0].Detail, "TXT with a 26-character label") {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("long labels", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		for i := range agentLongNames {
			o.trackTunnel(st, "desk", b32Label(i)+".tun.example", deskSrc, "A")
		}
		if len(st.Events) != 1 || st.Events[0].Threat != "dns_tunnel" || st.Events[0].Dst != "tun.example" {
			t.Fatalf("events %+v", st.Events)
		}
	})
	t.Run("house stays loose", func(t *testing.T) {
		o, _, st := newTunObserver(120)
		for i := range agentLongNames {
			o.trackTunnel(st, "house", b32Label(i)+".tun.example", "10.78.0.20", "A")
		}
		if len(st.Events) != 0 {
			t.Fatalf("events %+v", st.Events)
		}
	})
}

// The volume threshold is one number for all segments. A desk that crosses
// it is named as the desk.
func TestVolumePlainSegment(t *testing.T) {
	o, _, st := newVolObserver(500)
	o.ingestCT(st, ctLine(deskSrc, "93.184.216.34", 600*mib, 0), "desk", deskNet, deskIP, nil, map[string]int64{})
	if len(st.Events) != 1 || st.Events[0].Threat != "volume" || st.Events[0].Segment != "desk" || st.Events[0].Src != deskSrc {
		t.Fatalf("events %+v", st.Events)
	}
}

// The backstop sees what the resolver refuses. A key that is the last
// label, or that continues into a label that is not a TLD, matches. A real
// name whose TLD completes a shape does not.
func TestSegKeysReachTheLastLabel(t *testing.T) {
	k, err := loadSegKeys(keyRules(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, hit := range map[string]bool{
		"x." + oatKey: true,
		"tun." + oatKey[:30] + "." + oatKey[30:] + "9": true,
		"asiakuecheerlangen.de":                        false,
		"www.example.com":                              false,
	} {
		if got := k.match(name) != ""; got != hit {
			t.Errorf("%s: matched %v, want %v", name, got, hit)
		}
	}
	if z := k.zone("x." + oatKey); z != "" {
		t.Errorf("zone kept the key: %q", z)
	}
}
