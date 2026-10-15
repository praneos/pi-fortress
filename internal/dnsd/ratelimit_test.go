package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/observe"
)

type emitted struct {
	src    string
	n      int
	listed bool
}

var (
	t0   = time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	src1 = netip.MustParseAddr("10.77.0.10")
)

func testLimiter(rate float64, burst, max int) (*limiter, *[]emitted) {
	var out []emitted
	l := newLimiter(rate, burst, max, func(_ time.Time, src string, n int, listed bool) {
		out = append(out, emitted{src, n, listed})
	})
	return l, &out
}

func TestLimiterBucketMath(t *testing.T) {
	l, _ := testLimiter(10, 5, 16)
	for i := range 5 {
		if !l.take(t0, src1, false) {
			t.Fatalf("take %d refused inside the burst", i)
		}
	}
	if l.take(t0, src1, false) {
		t.Fatal("a sixth take at the same instant was admitted")
	}
	if !l.take(t0.Add(100*time.Millisecond), src1, false) {
		t.Fatal("a tenth of a second at 10/s did not refill a token")
	}
	if l.take(t0.Add(150*time.Millisecond), src1, false) {
		t.Fatal("half a token was admitted")
	}
	if !l.take(t0.Add(150*time.Millisecond), src1, true) {
		t.Fatal("a listed name spent the ordinary budget")
	}
	if l.take(t0, src1, false) {
		t.Fatal("a clock stepped backwards refilled the bucket")
	}
	n := 0
	for l.take(t0.Add(9*time.Second), src1, false) {
		n++
	}
	if n != 5 {
		t.Fatalf("a long idle refilled %d tokens, want the burst of 5", n)
	}
}

// The plan's accept: a 200/s single-source flood logs a bounded number of
// queries per interval and one summary. A client at a few queries each
// second logs everything with no summary.
func TestLimiterFloodIsOneSummaryPerSweep(t *testing.T) {
	l, out := testLimiter(defaultLogRate, defaultLogBurst, logSources)
	admitted := 0
	for i := range 2000 {
		if l.take(t0.Add(time.Duration(i)*5*time.Millisecond), src1, false) {
			admitted++
		}
	}
	if admitted < 295 || admitted > 300 {
		t.Fatalf("admitted %d of a 10 s flood, want burst plus 20/s", admitted)
	}
	if len(*out) != 0 {
		t.Fatalf("summaries before the sweep: %v", *out)
	}
	l.take(t0.Add(logSweep), src1, false)
	if want := []emitted{{src1.String(), 2000 - admitted, false}}; len(*out) != 1 || (*out)[0] != want[0] {
		t.Fatalf("sweep wrote %v, want %v", *out, want)
	}

	calm := netip.MustParseAddr("10.77.0.11")
	l2, out2 := testLimiter(defaultLogRate, defaultLogBurst, logSources)
	for i := range 300 {
		if !l2.take(t0.Add(time.Duration(i)*200*time.Millisecond), calm, false) {
			t.Fatalf("query %d from a 5/s client was refused", i)
		}
	}
	l2.flush(t0.Add(time.Minute))
	if len(*out2) != 0 {
		t.Fatalf("a calm client got summaries: %v", *out2)
	}
}

func TestLimiterSweepEvictsIdle(t *testing.T) {
	l, out := testLimiter(10, 5, 16)
	for i := range 3 {
		l.take(t0, netip.AddrFrom4([4]byte{10, 77, 0, byte(20 + i)}), false)
	}
	for range 8 {
		l.take(t0, src1, false)
	}
	if l.len() != 4 {
		t.Fatalf("tracking %d, want 4", l.len())
	}
	l.flush(t0.Add(logSweep))
	if len(*out) != 1 || (*out)[0] != (emitted{src1.String(), 3, false}) {
		t.Fatalf("sweep wrote %v", *out)
	}
	if l.len() != 1 {
		t.Fatalf("tracking %d after the sweep, want only the source that dropped", l.len())
	}
	l.flush(t0.Add(2 * logSweep))
	if l.len() != 0 || len(*out) != 1 {
		t.Fatalf("tracking %d, summaries %v after an idle sweep", l.len(), *out)
	}
}

func TestLimiterCapCountsUntracked(t *testing.T) {
	l, out := testLimiter(10, 5, 4)
	for i := range 10000 {
		l.take(t0, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), i%2 == 0)
		if l.len() > 4 {
			t.Fatalf("table grew to %d past its cap", l.len())
		}
	}
	l.flush(t0)
	want := []emitted{{untracked, 4998, false}, {untracked, 4998, true}}
	if len(*out) != 2 || (*out)[0] != want[0] || (*out)[1] != want[1] {
		t.Fatalf("summaries %v, want %v", *out, want)
	}
	late := netip.MustParseAddr("10.77.0.99")
	if l.take(t0, late, false) {
		t.Fatal("a new source was admitted into a full table")
	}
	l.flush(t0.Add(logSweep))
	if !l.take(t0.Add(logSweep), late, false) {
		t.Fatal("a new source was refused after idle sources were evicted")
	}
}

// Every query is either logged or counted, whatever the interleaving.
func TestLimiterHammer(t *testing.T) {
	l, out := testLimiter(1000, 50, 64)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				src := netip.AddrFrom4([4]byte{10, 77, 0, byte((g + i) % 32)})
				if l.take(time.Now(), src, i%3 == 0) {
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	l.flush(time.Now())
	total := admitted.Load()
	for _, e := range *out {
		total += int64(e.n)
	}
	if total != 16*2000 {
		t.Fatalf("logged plus counted is %d, want %d", total, 16*2000)
	}
}

// Through the server: answers do not change. A listed name keeps its lines
// while ordinary chatter from the same source is over budget. The count
// is written on close. observe reads the log as before.
func TestFloodLogIsBoundedAndObserveReadsIt(t *testing.T) {
	h := newHarness(t, []string{"webhook.site"}, map[string][4]byte{"example.com": {93, 184, 216, 34}}, 300)
	for range defaultLogBurst + 50 {
		if _, ans := h.ask(t, "example.com", dnsmessage.TypeA); firstA(t, ans) != "93.184.216.34" {
			t.Fatal("an over-budget query lost its answer")
		}
	}
	for range 10 {
		h.ask(t, "webhook.site", dnsmessage.TypeA)
	}
	h.srv.CloseLogs()

	var resolved, blocked int
	var summaries []dnslog.Event
	for _, r := range h.logLines(t) {
		switch r.Act {
		case dnslog.ActResolved:
			resolved++
		case dnslog.ActBlocked:
			blocked++
		case dnslog.ActSuppressed:
			summaries = append(summaries, r)
		}
	}
	// The blocked name keeps all ten of its rows. The sinkhole budget is
	// reserved, so a flood of ordinary chatter cannot hide the lines that
	// show a policy action.
	if resolved != defaultLogBurst || blocked != 10 {
		t.Fatalf("resolved %d blocked %d", resolved, blocked)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries %+v, want one", summaries)
	}
	if got := summaries[0]; got.Src != "10.77.0.10" || got.N != 50 || got.Name != "" {
		t.Fatalf("summary %+v, want 50 counted from 10.77.0.10 and no name", got)
	}

	dir := filepath.Dir(h.log)
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &observe.Observer{
		StatePath:    filepath.Join(dir, "observe.json"),
		JSONLPath:    filepath.Join(dir, "observe.jsonl"),
		DNSLog:       h.log,
		OffsetPath:   filepath.Join(dir, "dns.offset"),
		CTPath:       filepath.Join(dir, "no-conntrack"),
		CTCmd:        []string{"true"},
		NetEnvPath:   []string{netEnv},
		HouseEnvPath: []string{filepath.Join(dir, "no-house.env")},
		Now:          time.Now,
	}
	st := o.Snapshot()
	if rec, ok := st.DNS["example.com"]; !ok || rec.Src != "10.77.0.10" || rec.Sinkholed {
		t.Fatalf("forwarded record %+v %v", rec, ok)
	}
	if rec, ok := st.DNS["webhook.site"]; !ok || !rec.Sinkholed {
		t.Fatalf("sinkholed record %+v %v", rec, ok)
	}
	if len(st.DNS) != 2 {
		t.Fatalf("observe holds %d names, want 2", len(st.DNS))
	}
}

func TestNegativeLogRateLogsEverything(t *testing.T) {
	s, err := New(Config{
		NFTTable: "inet fortress", NFT: discardNFT{}, LogRate: -1,
		Segments: []Segment{{
			IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo", Upstream: "127.0.0.1:1",
			NFTSet: "resolved_v4", LogPath: filepath.Join(t.TempDir(), "dns.jsonl"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	defer s.CloseLogs()
	if s.segs[0].log.Load().lim != nil {
		t.Fatal("a negative rate built a limiter")
	}
}

// Before, a client that emptied its ordinary budget with short names
// bought silence for all that followed. The long labels and TXT questions
// of a tunnel were forwarded without a log line. The tunnel heuristic of
// observe never saw them. Now they pay from their own budget, as listed
// names do. That budget is the same size, so it is not a new way to fill
// the disk.
func TestTunnelShapedQueriesKeepTheirRowsThroughAFlood(t *testing.T) {
	h := newHarness(t, nil, map[string][4]byte{"example.com": {93, 184, 216, 34}}, 300)
	for range defaultLogBurst + 50 {
		h.ask(t, "example.com", dnsmessage.TypeA)
	}
	long := "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiqgc3dfmrsw.tun.example"
	for range 10 {
		h.ask(t, long, dnsmessage.TypeA)
		h.ask(t, "d1.tun.example", dnsmessage.TypeTXT)
	}
	for range 10 {
		h.ask(t, "short.tun.example", dnsmessage.TypeA)
	}
	h.srv.CloseLogs()
	var longRows, txtRows, shortRows int
	var sums []dnslog.Event
	for _, r := range h.logLines(t) {
		switch {
		case r.Act == dnslog.ActSuppressed:
			sums = append(sums, r)
		case r.Name == long:
			longRows++
		case r.QType == "TXT":
			txtRows++
		case r.Name == "short.tun.example":
			shortRows++
		}
	}
	if longRows != 10 || txtRows != 10 {
		t.Fatalf("long-label rows %d, TXT rows %d: want every one of the ten", longRows, txtRows)
	}
	if shortRows != 0 {
		t.Fatalf("a short name over the ordinary budget was logged %d times", shortRows)
	}
	if len(sums) != 1 || sums[0].N != 60 || sums[0].Candidate || sums[0].Listed {
		t.Fatalf("summaries %+v, want one ordinary count of 60", sums)
	}
}

// The candidate bucket has a limit, as the others do. A flood of only
// candidates is counted after its burst, under a summary that tells which
// bucket it was.
func TestTheCandidateBudgetIsBounded(t *testing.T) {
	l, _ := testLimiter(20, 100, 16)
	var n int
	for range 300 {
		if l.takeClass(t0, src1, logCandidate) {
			n++
		}
	}
	if n != 100 {
		t.Fatalf("candidates admitted %d at once, want the burst of 100", n)
	}
	if !l.take(t0, src1, false) || !l.take(t0, src1, true) {
		t.Fatal("the candidate flood spent another bucket")
	}
	got := map[logClass]int{}
	cl := newClassLimiter(20, 100, 16, func(_ time.Time, _ string, n int, c logClass) { got[c] += n })
	for range 150 {
		cl.takeClass(t0, src1, logCandidate)
	}
	cl.flush(t0)
	if got[logCandidate] != 50 || len(got) != 1 {
		t.Fatalf("class summary %v, want 50 candidates", got)
	}
	for name, want := range map[string]bool{
		"www.example.com": false, "_acme-challenge.example.com": false,
		"r3---sn-abc123def456.googlevideo.com": true, "averyveryverylongname.example": true,
	} {
		if got := tunnelCandidate(name, 1); got != want {
			t.Errorf("%s: candidate %v, want %v", name, got, want)
		}
	}
	if !tunnelCandidate("a.example", 16) || !tunnelCandidate("a.example", 10) {
		t.Error("TXT and NULL are candidates whatever the name")
	}
}
