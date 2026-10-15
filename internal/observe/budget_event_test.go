package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stripObserver reads one strip log and nothing else.
func stripObserver(t *testing.T, rows string, now time.Time) *State {
	t.Helper()
	dir := t.TempDir()
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	strip := filepath.Join(dir, "strip.jsonl")
	if err := os.WriteFile(strip, []byte(rows), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:       filepath.Join(dir, "observe.json"),
		DNSLog:          filepath.Join(dir, "missing.log"),
		OffsetPath:      filepath.Join(dir, "off"),
		CTPath:          filepath.Join(dir, "missing-ct"),
		NetEnvPath:      []string{env},
		StripLog:        strip,
		StripOffsetPath: filepath.Join(dir, "strip.offset"),
		Now:             func() time.Time { return now },
	}
	return o.Snapshot()
}

// A slot_budget row is the fence that reports a rate. It is not a strip and
// not a refusal, so it keeps its own threat name. It is an alert, not a
// block, even when it names a stop: the request that crossed the line was
// served, and the stop applies to all requests after it.
func TestSlotBudgetRowsKeepTheirThreat(t *testing.T) {
	rows := `{"t":"2026-09-21T15:12:41Z","host":"api.anthropic.com","where":"requests","rule":"slot_budget_warn:a1b2","client_ip":"10.77.0.10","threat":"slot_budget","slot":"a1b2","count":3001,"limit":3000}` + "\n" +
		`{"t":"2026-09-21T15:13:41Z","host":"api.anthropic.com","where":"upload_bytes","rule":"slot_budget_stop:a1b2","client_ip":"10.77.0.10","threat":"slot_budget","slot":"a1b2","count":600,"limit":500}` + "\n"
	st := stripObserver(t, rows, time.Date(2026, 9, 21, 16, 0, 0, 0, time.UTC))
	want := []Event{
		{T: time.Date(2026, 9, 21, 15, 12, 41, 0, time.UTC), Segment: "agent", Src: "10.77.0.10", Dst: "api.anthropic.com", Threat: "slot_budget", Detail: "slot_budget_warn:a1b2"},
		{T: time.Date(2026, 9, 21, 15, 13, 41, 0, time.UTC), Segment: "agent", Src: "10.77.0.10", Dst: "api.anthropic.com", Threat: "slot_budget", Detail: "slot_budget_stop:a1b2"},
	}
	if len(st.Events) != len(want) {
		t.Fatalf("events: %+v", st.Events)
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
		if !st.Events[i].Alert() {
			t.Fatalf("event %d is not an alert: %+v", i, st.Events[i])
		}
	}
}

// A threat name from a producer that this reader does not know must not
// become its own event type: the row is still the strip that it was. Thus
// a screen that groups by threat still shows it somewhere.
func TestUnknownThreatStaysAStrip(t *testing.T) {
	row := `{"t":"2026-09-21T15:12:41Z","host":"api.github.com","where":"header","rule":"github_classic","threat":"from_the_future"}` + "\n"
	st := stripObserver(t, row, time.Date(2026, 9, 21, 16, 0, 0, 0, time.UTC))
	if len(st.Events) != 1 || st.Events[0].Threat != "credential_strip" {
		t.Fatalf("events: %+v", st.Events)
	}
}
