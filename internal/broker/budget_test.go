package broker

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

const budgetSlot = "a1b2c3d4e5f67890"

// budgetBroker is a broker with a clock that the test drives, and an
// origin that answers all requests. Thus an hour of agent traffic costs
// no wall time.
func budgetBroker(t *testing.T, lim SlotBudget) (*Broker, *atomic.Int64, string) {
	t.Helper()
	b, _ := testBroker(t)
	dir := t.TempDir()
	strip := dir + "/strip.jsonl"
	b.Logs = &jsonl.Writer{StripPath: strip, UsePath: dir + "/use.jsonl"}
	b.Budget = lim
	var clock atomic.Int64
	clock.Store(time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC).Unix())
	b.Now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	b.DialTLS = dialTLSTo(srv)
	return b, &clock, strip
}

var budgetPreamble = preamble.Preamble{SNI: "api.github.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}

// spend sends one substituting request and returns the response body.
func spend(t *testing.T, b *Broker, slot string) string {
	t.Helper()
	raw := "GET /user HTTP/1.1\r\nHost: api.github.com\r\n" +
		"Authorization: Bearer " + secrets.Placeholder(slot, "GITHUB_TOKEN") + "\r\n\r\n"
	return roundtrip(t, b, budgetPreamble, raw)
}

// spendBody sends one substituting request with a body of n bytes,
// framed by Content-Length so the fence buffers or streams it by size.
func spendBody(t *testing.T, b *Broker, slot string, n int) {
	t.Helper()
	body := strings.Repeat("x", n)
	raw := "POST /user HTTP/1.1\r\nHost: api.github.com\r\n" +
		"Authorization: Bearer " + secrets.Placeholder(slot, "GITHUB_TOKEN") + "\r\n" +
		"Content-Length: " + strconv.Itoa(n) + "\r\n\r\n" + body
	roundtripStream(t, b, budgetPreamble, raw)
}

// budgetRows are the slot_budget rows the strip log has collected.
func budgetRows(t *testing.T, path string) []jsonl.Strip {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	defer f.Close()
	var out []jsonl.Strip
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var row jsonl.Strip
		if json.Unmarshal(sc.Bytes(), &row) != nil {
			continue
		}
		if row.Threat == threatSlotBudget {
			out = append(out, row)
		}
	}
	return out
}

// The window is sixty minute buckets, so minute 0 and minute 60 go in
// the same bucket. The older count must leave when the newer count
// arrives. If not, the hour would include a request from one hour and
// one minute ago.
func TestBudgetWindowDropsTheBucketItReuses(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 1000}
	for i := range 60 {
		bg.charge("s", 0, 1, 10, lim, base.Add(time.Duration(i)*time.Minute))
	}
	if got := bg.hour(base.Add(59 * time.Minute)); got["s"] != [2]int64{60, 600} {
		t.Fatalf("an hour of one a minute: %v", got["s"])
	}
	// Minute 60 reuses bucket 0. The hour is now minutes 1..60.
	bg.charge("s", 0, 1, 10, lim, base.Add(60*time.Minute))
	if got := bg.hour(base.Add(60 * time.Minute)); got["s"] != [2]int64{60, 600} {
		t.Fatalf("after the wrap: %v", got["s"])
	}
	// Two hours later, the window contains nothing.
	if got := bg.hour(base.Add(120 * time.Minute)); len(got) != 0 {
		t.Fatalf("a window that should be empty: %v", got)
	}
}

// A gap longer than the window must not bring back the buckets that it
// skipped. Those buckets have a minute far outside the hour, and totals
// must read that minute, not only their index.
func TestBudgetWindowIgnoresStaleBuckets(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 1000}
	bg.charge("s", 0, 5, 0, lim, base)
	bg.charge("s", 0, 1, 0, lim, base.Add(3*time.Hour))
	if got := bg.hour(base.Add(3 * time.Hour)); got["s"] != [2]int64{1, 0} {
		t.Fatalf("three hours later: %v", got["s"])
	}
}

// One warn per crossing. A total that stays above the line is not a new
// event. A drop below the line and a return above it is a new event.
func TestBudgetWarnFiresOnceAndRearms(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 3}
	if h := bg.charge("s", 0, 3, 0, lim, base); len(h) != 1 || h[0].count != 3 || h[0].limit != 3 {
		t.Fatalf("the crossing: %v", h)
	}
	for i := 1; i < 10; i++ {
		if h := bg.charge("s", 0, 1, 0, lim, base.Add(time.Duration(i)*time.Minute)); len(h) != 0 {
			t.Fatalf("still above the line at minute %d: %v", i, h)
		}
	}
	// The window has emptied; the next crossing is a new event.
	at := base.Add(70 * time.Minute)
	if h := bg.charge("s", 0, 3, 0, lim, at); len(h) != 1 {
		t.Fatalf("re-armed after the window emptied: %v", h)
	}
}

// A drop back below the line re-arms the warn immediately. It does not
// wait for the repeat interval. Two excursions one hour apart are two
// incidents, and the operator must get an alert for both. Here, the
// second crossing is 56 minutes after the first alert. Thus the
// once-an-hour repeat cannot cause it.
func TestBudgetWarnRearmsWhenTheWindowDropsUnder(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 3}
	bg.charge("s", 0, 2, 0, lim, base)
	if h := bg.charge("s", 0, 1, 0, lim, base.Add(5*time.Minute)); len(h) != 1 {
		t.Fatalf("the first crossing: %v", h)
	}
	// At minute 61 the two from minute 0 have left the window.
	if h := bg.charge("s", 0, 0, 0, lim, base.Add(61*time.Minute)); len(h) != 0 {
		t.Fatalf("under the line again: %v", h)
	}
	if h := bg.charge("s", 0, 2, 0, lim, base.Add(61*time.Minute)); len(h) != 1 {
		t.Fatalf("the second crossing: %v", h)
	}
}

// A condition that never clears must still repeat. If not, the broker
// reports an agent that stays just above the line one time, and then
// never again while it runs.
func TestBudgetWarnRepeatsAfterAnHourAboveTheLine(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 10}
	said := 0
	for i := range 130 {
		said += len(bg.charge("s", 0, 1, 0, lim, base.Add(time.Duration(i)*time.Minute)))
	}
	if said != 3 {
		t.Fatalf("over two hours above the line: %d alerts, want 3", said)
	}
}

func TestBudgetZeroThresholdsCountNothing(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	var lim SlotBudget
	if h := bg.charge("s", 0, 1_000_000, 1<<40, lim, base); len(h) != 0 {
		t.Fatalf("a threshold of zero fired: %v", h)
	}
	// One armed threshold does not arm the other three.
	var only budget
	lim = SlotBudget{WarnBytes: 100}
	if h := only.charge("s", 0, 1_000_000, 50, lim, base); len(h) != 0 {
		t.Fatalf("requests fired with no request threshold: %v", h)
	}
	if h := only.charge("s", 0, 0, 50, lim, base); len(h) != 1 || h[0].where() != whereUpload {
		t.Fatalf("the bytes threshold: %v", h)
	}
}

func TestBudgetSlotsAreIndependent(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{WarnRequests: 5}
	for range 5 {
		bg.charge("one", 0, 1, 7, lim, base)
	}
	if h := bg.charge("two", 0, 1, 7, lim, base); len(h) != 0 {
		t.Fatalf("the second slot inherited the first's hour: %v", h)
	}
	got := bg.hour(base)
	if got["one"] != [2]int64{5, 35} || got["two"] != [2]int64{1, 7} {
		t.Fatalf("two hours: %v", got)
	}
}

// A stop that the broker could not apply must not be recorded as
// applied. The next request must try again and report again. If not,
// the agent continues against a limit that nothing enforces.
func TestBudgetStopNotAppliedIsRetried(t *testing.T) {
	var bg budget
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	lim := SlotBudget{StopRequests: 2}
	h := bg.charge("s", 0, 2, 0, lim, base)
	if len(h) != 1 || !h[0].stop() {
		t.Fatalf("the stop: %v", h)
	}
	bg.quarantined(h[0], false)
	again := bg.charge("s", 0, 1, 0, lim, base)
	if len(again) != 1 || !again[0].stop() {
		t.Fatalf("a stop that did not land was not retried: %v", again)
	}
	bg.quarantined(again[0], true)
	// When the stop is applied, the broker drops the window at the next
	// substitution from a later snapshot. That can occur only after an
	// operator restored the slot.
	if third := bg.charge("s", bg.stopsLanded(), 1, 0, lim, base); len(third) != 0 {
		t.Fatalf("a restored slot was stopped again at once: %v", third)
	}
	if got := bg.hour(base); got["s"] != [2]int64{1, 0} {
		t.Fatalf("the restore did not drop the hour: %v", got["s"])
	}
}

// End to end: the warn row reaches strip.jsonl one time, in the shape
// that the alerter and observe read. The slot continues to work.
func TestBudgetWarnRowReachesTheStripLog(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{WarnRequests: 3})
	for range 5 {
		if body := spend(t, b, budgetSlot); body != "ok" {
			t.Fatalf("the request was not served: %q", body)
		}
	}
	rows := budgetRows(t, strip)
	if len(rows) != 1 {
		t.Fatalf("%d budget rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Rule != "slot_budget_warn:"+budgetSlot || r.Where != whereRequests ||
		r.Slot != budgetSlot || r.Count != 3 || r.Limit != 3 || r.Host != "api.github.com" {
		t.Fatalf("the row: %+v", r)
	}
}

// The stop goes through the quarantine sidecar. Thus the next request
// that carries that placeholder gets the same refusal as each disabled
// slot, byte for byte, through no new code path.
func TestBudgetStopQuarantinesAndTheNextRequestIsRefused(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{StopRequests: 2})
	for range 2 {
		if body := spend(t, b, budgetSlot); body != "ok" {
			t.Fatalf("the request was not served: %q", body)
		}
	}
	off, err := b.Store.Disabled()
	if err != nil {
		t.Fatal(err)
	}
	if off[budgetSlot] == 0 {
		t.Fatalf("the slot was not quarantined: %v", off)
	}
	if body := spend(t, b, budgetSlot); body != RefusedBody {
		t.Fatalf("the next request got %q, want the uniform refusal", body)
	}
	rows := budgetRows(t, strip)
	if len(rows) != 1 || rows[0].Rule != "slot_budget_stop:"+budgetSlot {
		t.Fatalf("the rows: %+v", rows)
	}
	// The refused request substituted nothing, so it spent no budget.
	if h := b.budget.hour(b.now()); h[budgetSlot][0] != 2 {
		t.Fatalf("the refused request was counted: %v", h)
	}
}

// The request that crosses the stop line then charges its body. That
// request took its snapshot before the stop. Thus its second charge is
// not a restore, and the hour that stopped the slot must stay. Only a
// request after the restore of the operator drops the hour.
func TestBudgetStopKeepsTheHourUntilARestore(t *testing.T) {
	b, _, _ := budgetBroker(t, SlotBudget{StopRequests: 1})
	spendBody(t, b, budgetSlot, 100)
	off, err := b.Store.Disabled()
	if err != nil {
		t.Fatal(err)
	}
	if off[budgetSlot] == 0 {
		t.Fatalf("the slot was not quarantined: %v", off)
	}
	if h := b.budget.hour(b.now()); h[budgetSlot][0] != 1 || h[budgetSlot][1] < 100 {
		t.Fatalf("the hour that stopped the slot was lost: %v", h)
	}
	if err := b.Store.Restore(budgetSlot); err != nil {
		t.Fatal(err)
	}
	b.Budget = SlotBudget{}
	if body := spend(t, b, budgetSlot); body != "ok" {
		t.Fatalf("the restored slot was not served: %q", body)
	}
	if h := b.budget.hour(b.now()); h[budgetSlot] != [2]int64{1, 0} {
		t.Fatalf("the restore did not drop the hour: %v", h)
	}
}

// The broker counts a body under the buffer limit from the length that
// the fence put in its frame, after substitution.
func TestBudgetCountsABufferedBody(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{WarnBytes: 4096})
	spendBody(t, b, budgetSlot, 5000)
	rows := budgetRows(t, strip)
	if len(rows) != 1 || rows[0].Where != whereUpload || rows[0].Count < 5000 {
		t.Fatalf("a buffered body of 5000 bytes: %+v", rows)
	}
}

// A body past the buffer limit never stays in memory. Thus the broker
// counts its bytes when the copy puts them on the origin leg.
func TestBudgetCountsAStreamedBody(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{WarnBytes: 2 << 20})
	spendBody(t, b, budgetSlot, (2<<20)+1024)
	rows := budgetRows(t, strip)
	if len(rows) != 1 || rows[0].Where != whereUpload || rows[0].Count < 2<<20 {
		t.Fatalf("a streamed body of just over 2 MiB: %+v", rows)
	}
}

// A chunked body announces no length at all. Thus only the copy can tell
// how much it uploaded.
func TestBudgetCountsAChunkedBody(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{WarnBytes: 1024})
	raw := "POST /user HTTP/1.1\r\nHost: api.github.com\r\n" +
		"Authorization: Bearer " + secrets.Placeholder(budgetSlot, "GITHUB_TOKEN") + "\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" + chunkWire(strings.Repeat("y", 4096))
	roundtripStream(t, b, budgetPreamble, raw)
	rows := budgetRows(t, strip)
	if len(rows) != 1 || rows[0].Where != whereUpload || rows[0].Count != 4096 {
		t.Fatalf("a chunked body of 4096 bytes: %+v", rows)
	}
}

// With no armed threshold, the broker writes nothing. That is the
// shipped default for the two stop lines. But the broker still counts
// the hour. The hour is a read-out and also a trigger. An operator who
// disabled the alerts so that the alerts do not wake them must not
// lose, because of this, the number that would tell the operator why
// the alerts woke them.
func TestBudgetOffStillCounts(t *testing.T) {
	b, _, strip := budgetBroker(t, SlotBudget{})
	for range 20 {
		if body := spend(t, b, budgetSlot); body != "ok" {
			t.Fatalf("the request was not served: %q", body)
		}
	}
	if rows := budgetRows(t, strip); len(rows) != 0 {
		t.Fatalf("a budget with no threshold armed wrote rows: %+v", rows)
	}
	if h := b.budget.hour(b.now()); h[budgetSlot][0] != 20 {
		t.Fatalf("the hour was not counted: %v", h)
	}
}
