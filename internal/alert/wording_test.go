package alert

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/jsonl"
)

// The strip_suppressed row of the writer counts the strip and refusal rows
// that it dropped for one client, over the log budget of that client. It
// used to post as "STRIP suppressed in suppressed -> *", a strip that never
// occurred. Now it says what it is: how many rows, from which client, and
// the budget, read from the constants of the writer.
func TestStripSuppressedHasItsOwnWording(t *testing.T) {
	row := map[string]any{
		"t": "2026-10-05T12:01:01Z", "ev": jsonl.StripSuppressedEv, "host": "*", "where": "suppressed",
		"rule": "suppressed", "src": "split", "count": float64(101), "client_ip": "10.77.0.10",
	}
	got := Summarize(row)
	if strings.HasPrefix(got, "STRIP ") || strings.Contains(got, "-> *") {
		t.Fatalf("reads as a strip: %q", got)
	}
	rate := strconv.FormatFloat(jsonl.StripRowRate, 'f', -1, 64)
	for _, want := range []string{
		"101", "10.77.0.10",
		rate + " a second", strconv.Itoa(jsonl.StripRowBurst) + " at once",
		"still stripped or refused",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not say %q", got, want)
		}
	}
	if k := kindOf(row); k != jsonl.StripSuppressedEv {
		t.Fatalf("held back by the webhook cap it counts as %q, not as a strip", k)
	}
	if keyAlert(row) {
		t.Fatal("a count of dropped rows took a credential post")
	}
}

// The hourly summary names both budgets, each read from the cap in force.
// So it cannot continue to say "30 an hour" when the webhook takes 30 and
// another 30.
func TestCapSummaryNamesBothBudgets(t *testing.T) {
	for _, capPosts := range []int{0, 7} {
		a := &Alerter{CapPosts: capPosts}
		a.cap = webhookCap{suppressed: 3, by: map[string]int{"strip": 2, "refused": 1}}
		got := a.summary()
		n := strconv.Itoa(a.capPosts())
		if capPosts == 0 && n != strconv.Itoa(defaultCapPosts) {
			t.Fatalf("default cap %s, want %d", n, defaultCapPosts)
		}
		want := "at most " + n + " ordinary posts and " + n + " credential or key posts an hour"
		if !strings.Contains(got, want) || !strings.HasPrefix(got, "3 alerts suppressed in the last hour (strip 2, refused 1)") {
			t.Fatalf("cap %d: %q, want it to say %q", capPosts, got, want)
		}
		if !strings.Contains(got, "canary") {
			t.Fatalf("cap %d: %q does not say a canary is never held back", capPosts, got)
		}
	}
}

// One sweep writes a summary row per client, all at once and all with
// host "*". So a debounce keyed on the host posted the row of the first
// client, and suppressed the rest. The client is what tells them apart.
func TestStripSuppressedRowsForTwoClientsBothPost(t *testing.T) {
	r := newCapRig(t)
	f, err := os.OpenFile(r.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.77.0.10", "10.77.0.11"} {
		fmt.Fprintf(f, `{"ev":%q,"host":"*","where":"suppressed","rule":"suppressed","count":5,"client_ip":%q}`+"\n", jsonl.StripSuppressedEv, ip)
	}
	f.Close()
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 2 || !strings.Contains(posts[0], "10.77.0.10") || !strings.Contains(posts[1], "10.77.0.11") {
		t.Fatalf("posts %q", posts)
	}
}
