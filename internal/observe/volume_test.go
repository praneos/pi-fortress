package observe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// volClock is the injected clock for the window arithmetic. Each case
// below moves it by whole minutes, and does not sleep.
type volClock struct{ t time.Time }

func (c *volClock) now() time.Time { return c.t }

func newVolObserver(mb int) (*Observer, *volClock, *State) {
	c := &volClock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	o := &Observer{VolumeMB: mb, Now: c.now}
	return o, c, o.empty()
}

// ctLine is one conntrack entry in the layout that `conntrack -L -o
// extended` and /proc/net/nf_conntrack both print: the counters of each
// direction come after the tuple of that direction, original direction first.
func ctLine(src, dst string, sent, reply int64) string {
	return "ipv4     2 tcp      6 431999 ESTABLISHED " +
		"src=" + src + " dst=" + dst + " sport=45678 dport=443 packets=900 bytes=" + strconv.FormatInt(sent, 10) + " " +
		"src=" + dst + " dst=" + src + " sport=443 dport=45678 packets=20 bytes=" + strconv.FormatInt(reply, 10) + " " +
		"[ASSURED] mark=0 zone=0 use=2"
}

const mib = int64(1) << 20

// TestVolumeCountsTheSentDirectionOnly pins which conntrack counter the
// signal reads. The reply case is the important one: 600 MB that comes
// back is an ordinary download. A signal that added both directions would
// call each large fetch an upload.
func TestVolumeCountsTheSentDirectionOnly(t *testing.T) {
	cases := []struct {
		name         string
		sent, reply  int64
		wantEvents   int
		wantDetail   string
		wantFlowByte int
	}{
		{"the client sent it", 600 * mib, 4096, 1, "600 MB in 1h", 600*1048576 + 4096},
		{"the client received it", 1 * mib, 600 * mib, 0, "", 601 * 1048576},
		{"neither direction is over", 10 * mib, 10 * mib, 0, "", 20 * 1048576},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, _, st := newVolObserver(500)
			o.ingestCT(st, ctLine("10.77.0.10", "93.184.216.34", c.sent, c.reply), "", "10.77.0.0/24", "10.77.0.1", nil, map[string]int64{})
			if len(st.Events) != c.wantEvents {
				t.Fatalf("events %+v, want %d", st.Events, c.wantEvents)
			}
			if c.wantEvents == 1 {
				e := st.Events[0]
				if e.Threat != "volume" || e.Segment != "agent" || e.Src != "10.77.0.10" || e.Dst != "93.184.216.34" || e.Detail != c.wantDetail {
					t.Fatalf("event %+v", e)
				}
				if !e.Alert() {
					t.Fatal("a volume row is something the Pi saw, not something it stopped")
				}
			}
			// The flow ledger still carries both directions. The split
			// belongs to the volume signal, not to the ledger.
			if f := st.Flows["10.77.0.10>93.184.216.34:443/tcp"]; f == nil || f.Bytes != c.wantFlowByte {
				t.Fatalf("flow %+v", f)
			}
		})
	}
}

// TestVolumeCountsOnlyTheGrowthBetweenPolls guards the delta: conntrack
// byte counters are cumulative for the life of the entry. Thus a flow
// still open on the next poll must not count from zero again.
func TestVolumeCountsOnlyTheGrowthBetweenPolls(t *testing.T) {
	o, _, st := newVolObserver(500)
	seen := map[string]int64{}
	o.ingestCT(st, ctLine("10.77.0.10", "93.184.216.34", 400*mib, 0), "", "10.77.0.0/24", "10.77.0.1", nil, seen)
	o.seenCT = seen
	if len(st.Events) != 0 {
		t.Fatalf("events after the first poll: %+v", st.Events)
	}
	// The same entry, 150 MB further. A full count again would give 800
	// and alert. A count of the growth gives 550, which also alerts. Thus
	// poll a third time, at a total that only the double count could
	// push over.
	seen = map[string]int64{}
	o.ingestCT(st, ctLine("10.77.0.10", "93.184.216.34", 450*mib, 0), "", "10.77.0.0/24", "10.77.0.1", nil, seen)
	o.seenCT = seen
	if len(st.Events) != 0 {
		t.Fatalf("450 MB cumulative is 450 MB sent, not 850: %+v", st.Events)
	}
	seen = map[string]int64{}
	o.ingestCT(st, ctLine("10.77.0.10", "93.184.216.34", 500*mib, 0), "", "10.77.0.0/24", "10.77.0.1", nil, seen)
	o.seenCT = seen
	if len(st.Events) != 1 || st.Events[0].Detail != "500 MB in 1h" {
		t.Fatalf("events %+v", st.Events)
	}
}

// TestVolumeWindowAndDebounce moves the clock through each rule: the
// hour slides, one crossing is one event, and a pair that stays over
// waits an hour before it reports again.
func TestVolumeWindowAndDebounce(t *testing.T) {
	type step struct {
		min, mb, wantEvents int
		wantDetail          string
	}
	cases := []struct {
		name  string
		mb    int
		steps []step
	}{
		{"one event for one crossing", 500, []step{
			{0, 200, 0, ""},
			{1, 200, 0, ""},
			{2, 200, 1, "600 MB in 1h"},
			{3, 200, 1, ""},
		}},
		{"minutes older than the hour fall out", 500, []step{
			{0, 400, 0, ""},
			{60, 400, 0, ""},
			{61, 200, 1, "600 MB in 1h"},
		}},
		{"a pair that stays over repeats once an hour", 500, []step{
			{0, 600, 1, "600 MB in 1h"},
			{30, 300, 1, ""},
			{59, 300, 1, ""},
			{60, 100, 2, "700 MB in 1h"},
			{61, 100, 2, ""},
		}},
		{"a crossing after it went quiet is its own event", 500, []step{
			{0, 600, 1, "600 MB in 1h"},
			{61, 100, 1, ""},
			{62, 600, 2, "700 MB in 1h"},
		}},
		{"zero turns the signal off", 0, []step{
			{0, 5000, 0, ""},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, clk, st := newVolObserver(c.mb)
			base := clk.t
			for _, s := range c.steps {
				clk.t = base.Add(time.Duration(s.min) * time.Minute)
				o.trackVolume(st, "", "10.77.0.10", "93.184.216.34", int64(s.mb)*mib)
				if len(st.Events) != s.wantEvents {
					t.Fatalf("minute %d: events %+v, want %d", s.min, st.Events, s.wantEvents)
				}
				if s.wantDetail != "" {
					e := st.Events[len(st.Events)-1]
					if e.Detail != s.wantDetail || !e.T.Equal(clk.t) {
						t.Fatalf("minute %d: %+v, want detail %q", s.min, e, s.wantDetail)
					}
				}
			}
		})
	}
}

// TestVolumeTableEvictsTheColdestPairs holds the memory limit: the table
// stops at maxVolPairs and makes room in batches, oldest activity first.
func TestVolumeTableEvictsTheColdestPairs(t *testing.T) {
	o, clk, st := newVolObserver(1 << 20) // far too high to ever alert
	base := clk.t
	for i := 0; i < maxVolPairs; i++ {
		clk.t = base.Add(time.Duration(i) * time.Minute)
		o.trackVolume(st, "", "10.77.0.10", "198.51.100."+strconv.Itoa(i), 1)
	}
	if len(o.vol) != maxVolPairs {
		t.Fatalf("table %d, want %d", len(o.vol), maxVolPairs)
	}
	clk.t = base.Add(time.Duration(maxVolPairs) * time.Minute)
	o.trackVolume(st, "", "10.77.0.10", "198.51.100.newcomer", 1)
	if want := maxVolPairs - volumeEvict + 1; len(o.vol) != want {
		t.Fatalf("after eviction %d, want %d", len(o.vol), want)
	}
	// The coldest went, the warmest and the newcomer stayed.
	if _, ok := o.vol["agent/10.77.0.10>198.51.100.0"]; ok {
		t.Fatal("the least recently active pair survived")
	}
	if _, ok := o.vol["agent/10.77.0.10>198.51.100."+strconv.Itoa(maxVolPairs-1)]; !ok {
		t.Fatal("the most recently active pair was evicted")
	}
	if _, ok := o.vol["agent/10.77.0.10>198.51.100.newcomer"]; !ok {
		t.Fatal("the pair that forced the eviction was not kept")
	}
}

// TestVolumeNamesTheDestination checks that the operator reads a bucket
// and not only a number, and that an address that no query answered for
// stands alone.
func TestVolumeNamesTheDestination(t *testing.T) {
	o, _, st := newVolObserver(500)
	o.noteAnswer("Gist.GitHub.com.", "140.82.113.4")
	o.noteAnswer("blocked.example", "0.0.0.0")
	o.noteAnswer("bad.example", "not-an-address")
	o.trackVolume(st, "house", "10.78.0.20", "140.82.113.4", 600*mib)
	o.trackVolume(st, "house", "10.78.0.20", "203.0.113.9", 600*mib)
	if len(st.Events) != 2 {
		t.Fatalf("events %+v", st.Events)
	}
	if got := st.Events[0].Dst; got != "gist.github.com (140.82.113.4)" {
		t.Fatalf("named dst %q", got)
	}
	if got := st.Events[1].Dst; got != "203.0.113.9" {
		t.Fatalf("unnamed dst %q", got)
	}
	if st.Events[0].Segment != "house" {
		t.Fatalf("the signal runs on every segment: %+v", st.Events[0])
	}
	if len(o.dstNames) != 1 {
		t.Fatalf("only a real answer is worth remembering: %v", o.dstNames)
	}
}

// TestVolumeAlertsShowUnderTheirOwnHeading: pf observe show must not
// print a volume row under BLOCKED, because nothing was blocked.
func TestVolumeShowsUnderAlerts(t *testing.T) {
	var out strings.Builder
	o, _, st := newVolObserver(500)
	o.Stdout = &out
	o.trackVolume(st, "", "10.77.0.10", "93.184.216.34", 600*mib)
	o.Show(st)
	text := out.String()
	blocked := strings.Index(text, "BLOCKED (0)")
	alerts := strings.Index(text, "ALERTS (1)")
	if blocked < 0 || alerts < 0 || alerts < blocked {
		t.Fatalf("headings:\n%s", text)
	}
	if !strings.Contains(text[alerts:], "volume 600 MB in 1h") {
		t.Fatalf("no volume row under ALERTS:\n%s", text)
	}
}

// The webhook belongs to pf alert, and pf alert reads a file. A volume or
// dns_tunnel alert is a row there as soon as it fires. An arp_ alert is
// not.
func TestNoticeRowsAreWrittenForTheWebhook(t *testing.T) {
	o, _, st := newVolObserver(500)
	o.NoticePath = filepath.Join(t.TempDir(), "notice.jsonl")
	o.alert(st, Event{T: o.Now(), Segment: "house", Src: "10.78.0.9", Dst: "10.78.0.1", Threat: "arp_conflict"})
	if _, err := os.Stat(o.NoticePath); err == nil {
		t.Fatal("an arp alert reached the notice file")
	}
	o.trackVolume(st, "", "10.77.0.10", "93.184.216.34", 600*mib)
	raw, err := os.ReadFile(o.NoticePath)
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &row); err != nil {
		t.Fatalf("%v: %q", err, raw)
	}
	for k, want := range map[string]string{"threat": "volume", "client_ip": "10.77.0.10", "host": "93.184.216.34", "detail": "600 MB in 1h"} {
		if row[k] != want {
			t.Fatalf("%s = %v, want %s: %s", k, row[k], want, raw)
		}
	}
}

// A restart starts with no previous poll. Thus each flow still open
// counted as new, and its full lifetime of bytes went into the first
// minute: a long-lived upload that had sent 600 MB over a day alerted as
// soon as observe came back. The first poll after start only learns the
// counters. The growth after that is what counts. A flow that first shows
// on a later poll still counts in full.
func TestTheFirstPollAfterStartOnlySeeds(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ct := filepath.Join(dir, "ct")
	write := func(lines ...string) {
		t.Helper()
		if err := os.WriteFile(ct, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	c := &volClock{t: time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)}
	newObs := func() *Observer {
		return &Observer{
			StatePath: filepath.Join(dir, "observe.json"), DNSLog: filepath.Join(dir, "none.log"),
			OffsetPath: filepath.Join(dir, "off"), CTPath: ct, NetEnvPath: []string{env},
			VolumeMB: 500, Now: c.now,
		}
	}
	volume := func(st *State) int {
		n := 0
		for _, e := range st.Events {
			if e.Threat == "volume" {
				n++
			}
		}
		return n
	}
	long := ctLine("10.77.0.10", "93.184.216.34", 600*mib, 0)
	write(long)
	o := newObs()
	if st := o.Snapshot(); volume(st) != 0 {
		t.Fatalf("the first poll counted a flow's lifetime: %+v", st.Events)
	}
	c.t = c.t.Add(10 * time.Second)
	write(ctLine("10.77.0.10", "93.184.216.34", 650*mib, 0))
	if st := o.Snapshot(); volume(st) != 0 {
		t.Fatalf("50 MB of growth alerted: %+v", st.Events)
	}
	c.t = c.t.Add(10 * time.Second)
	write(ctLine("10.77.0.10", "93.184.216.34", 650*mib, 0), ctLine("10.77.0.11", "93.184.216.35", 600*mib, 0))
	if st := o.Snapshot(); volume(st) != 1 {
		t.Fatalf("a flow new on a later poll did not count whole: %+v", st.Events)
	}
}
