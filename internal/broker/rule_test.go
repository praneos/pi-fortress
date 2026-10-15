package broker

import (
	"testing"

	"pi-fortress/internal/secrets"
)

// The alert debounce keys on Rule. Thus whether the cause gets to that
// field decides whether two refusals with different causes on one host can
// suppress each other. logRefusals never sets the field, and that looks
// like the bug. The assignment is one layer down, in
// jsonl.Writer.Refused, which derives it from Cause. A later edit is likely
// to remove such a split as untidy. That edit would silently put each
// cause on a host into one debounce slot. Thus this test pins the contract
// here, so that nobody must discover it again from the alert side.
func TestRefusalRowCarriesTheCauseAsRule(t *testing.T) {
	_, rows := refuseCase(t, "pf-open-echo.test",
		secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN"), nil)
	if len(rows) == 0 {
		t.Fatal("no refusal was logged")
	}
	for _, r := range rows {
		if r.Cause == "" {
			t.Fatalf("refusal logged with no cause: %+v", r)
		}
		if r.Rule != "refused:"+r.Cause {
			t.Fatalf("Rule=%q Cause=%q: the cause must reach the field the alert debounce keys on", r.Rule, r.Cause)
		}
	}
}
