package alert

import (
	"encoding/json"
	"testing"
)

// The summary lines come from a row as the tailer parses it, not from a
// struct. So the fixtures go through encoding/json, which changes each
// number into a float64. A direct print of a float64 would put scientific
// notation in a webhook.
func budgetRow(t *testing.T, raw string) map[string]any {
	t.Helper()
	var row map[string]any
	if err := json.Unmarshal([]byte(raw), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestSummarizeSlotBudget(t *testing.T) {
	warn := budgetRow(t, `{"t":"2026-09-21T15:12:41Z","host":"api.anthropic.com","where":"requests","rule":"slot_budget_warn:a1b2","threat":"slot_budget","slot":"a1b2","count":3001,"limit":3000}`)
	if got, want := Summarize(warn), "SLOT BUDGET WARN slot a1b2: 3001 requests in the last hour, limit 3000 -> api.anthropic.com"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	stop := budgetRow(t, `{"t":"2026-09-21T15:12:41Z","host":"api.anthropic.com","where":"upload_bytes","rule":"slot_budget_stop:a1b2","threat":"slot_budget","slot":"a1b2","count":524288000,"limit":524288000}`)
	if got, want := Summarize(stop), "SLOT BUDGET STOP slot a1b2: 524288000 upload_bytes in the last hour, limit 524288000 -> api.anthropic.com"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	// A stop that the broker could not apply is the loudest line on the list.
	// To read "stop" and believe that the spend ended is the worse mistake, so
	// it does not summarise as a stop.
	failed := budgetRow(t, `{"host":"api.anthropic.com","where":"requests","rule":"slot_budget_stop_failed:a1b2","threat":"slot_budget","slot":"a1b2","count":9,"limit":5}`)
	if got, want := Summarize(failed), "SLOT BUDGET STOP FAILED slot a1b2: 9 requests in the last hour, limit 5 -> api.anthropic.com"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

func TestSummarizeSlotExpiry(t *testing.T) {
	soon := budgetRow(t, `{"host":"-","where":"CLAUDE_OAT,CLAUDE_ORT","rule":"slot_expiring:a1b2","threat":"slot_expiry","slot":"a1b2","count":5}`)
	if got, want := Summarize(soon), "SLOT EXPIRES in 5 days: slot a1b2 (CLAUDE_OAT,CLAUDE_ORT). Renew: sudo pf enroll renew --slot a1b2 --expires 90d"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	gone := budgetRow(t, `{"host":"-","where":"GITHUB_TOKEN","rule":"slot_expired:a1b2","threat":"slot_expiry","slot":"a1b2"}`)
	if got, want := Summarize(gone), "SLOT EXPIRED, placeholder now refused: slot a1b2 (GITHUB_TOKEN). Renew: sudo pf enroll renew --slot a1b2 --expires 90d"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if !postable(gone) {
		t.Fatal("an expiry row would not be posted")
	}
}

// Each budget row reaches the webhook. It has no ev, so it is not a
// refusal that waits for a mark. The broker writes one only on a crossing,
// and it does its own debounce.
func TestSlotBudgetIsPostable(t *testing.T) {
	row := budgetRow(t, `{"host":"api.anthropic.com","where":"requests","rule":"slot_budget_warn:a1b2","threat":"slot_budget","slot":"a1b2","count":3001,"limit":3000}`)
	if !postable(row) {
		t.Fatal("a budget row would not be posted")
	}
}

// Two slots that cross the same threshold against the same host are two
// incidents. The debounce keys on the rule, and the rule names the slot.
func TestSlotBudgetDebounceIsPerSlot(t *testing.T) {
	d := &Debounce{}
	if !d.OK("slot_budget", "slot_budget_warn:a1b2", "requests", "api.anthropic.com") {
		t.Fatal("the first slot was held back")
	}
	if !d.OK("slot_budget", "slot_budget_warn:c3d4", "requests", "api.anthropic.com") {
		t.Fatal("the second slot was folded into the first")
	}
	if d.OK("slot_budget", "slot_budget_warn:a1b2", "requests", "api.anthropic.com") {
		t.Fatal("the same slot posted twice inside the window")
	}
}
