package admin

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func unitsAsked(t *testing.T, c *Config) []string {
	t.Helper()
	var argv []string
	c.Exec = func(_ context.Context, a []string) ([]byte, error) {
		argv = append([]string{}, a...)
		return nil, nil
	}
	c.UnitsHealth()
	if len(argv) < 2 {
		t.Fatalf("systemctl was not asked anything: %v", argv)
	}
	return argv[2:]
}

// The unit list was fixed, but the box is not. The list never included the
// DoT stubs that apply installs under the resolver. Thus a dead stub was not
// visible on the screen that an operator opens to find why DNS stopped.
func TestUnitsHealthAsksAboutTheResolverThisBoxRuns(t *testing.T) {
	c := testConfig(t)
	got := unitsAsked(t, c)
	if !slices.Contains(got, AgentDNSUnit) {
		t.Errorf("the resolver that serves is never queried: %v", got)
	}
	if slices.Contains(got, "pi-fortress-dns-agent") {
		t.Errorf("still asks about the dnsmasq unit apply removes: %v", got)
	}
	for _, stub := range []string{"main", "house"} {
		if slices.Contains(got, "pi-fortress-dns-stub@"+stub) {
			t.Errorf("asked about a stub this box has not configured: %v", got)
		}
	}

	// apply writes one config file for each configured stub instance. That file
	// says that the instance exists.
	etc := filepath.Dir(c.HouseEnv)
	for _, stub := range []string{"main", "house"} {
		if err := os.WriteFile(filepath.Join(etc, "dns-stub-"+stub+".json"), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got = unitsAsked(t, c)
	for _, stub := range []string{"main", "house"} {
		if !slices.Contains(got, "pi-fortress-dns-stub@"+stub) {
			t.Errorf("a configured DoT stub is never queried: %v", got)
		}
	}
	// And each unit in the query comes back with a state.
	c.Exec = func(_ context.Context, _ []string) ([]byte, error) { return []byte("active\n"), nil }
	if st := c.UnitsHealth(); len(st) != len(got) {
		t.Fatalf("%d states for %d units", len(st), len(got))
	}
}

// The code rotates the ledger at 2 MiB, and reads only the last 1 MiB of
// the current generation. Thus the issued and redeemed counts are a tail
// that shows as a total. They decrease after a rotation. An enrolment older
// than the window looks like one that never occurred. The numbers are
// correct. What was missing was a way for the screen to say that they are
// partial.
func TestEnrollStatsSaysWhenTheLedgerIsATail(t *testing.T) {
	c := testConfig(t)
	c.WWWDir = filepath.Join(t.TempDir(), "www")
	if err := os.MkdirAll(c.claimsDir(), 0755); err != nil {
		t.Fatal(err)
	}
	st, err := c.EnrollStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.LedgerPartial {
		t.Fatal("an empty ledger reported itself as a tail")
	}

	// A previous generation is proof that the counts have lost rows.
	if err := os.WriteFile(filepath.Join(c.claimsDir(), "ledger.jsonl.1"), []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st, err = c.EnrollStats()
	if err != nil {
		t.Fatal(err)
	}
	if !st.LedgerPartial {
		t.Fatal("counts taken from one generation of a rotated ledger were presented as totals")
	}
}

// The same shape for the use log. A slot whose last use fell out of the
// tail looks the same as one that was never used. An operator deletes a
// slot because of "never".
func TestSlotsSayWhenLastUseIsOutOfWindow(t *testing.T) {
	c := testConfig(t)
	c.UseLog = filepath.Join(t.TempDir(), "use.jsonl")
	write(t, c.SecretsPath, "a1b2c3d4e5f67890_GITHUB_TOKEN=ghp_x\n")
	if err := os.WriteFile(c.UseLog, []byte(`{"t":"2026-01-01T00:00:00Z","slot":"a1b2c3d4e5f67890","host":"api.example"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Slots()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	if rows[0].UsePartial {
		t.Fatal("a use log that fits in the window called itself partial")
	}

	// Past the byte budget that Tail reads: all lines before the cut are gone
	// from the answer, and nothing said so.
	var b strings.Builder
	for b.Len() < maxTailBytes+(1<<16) {
		b.WriteString(`{"t":"2026-01-02T00:00:00Z","slot":"ffffffffffffffff","host":"other.example"}` + "\n")
	}
	if err := os.WriteFile(c.UseLog, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	rows, err = c.Slots()
	if err != nil {
		t.Fatal(err)
	}
	if !rows[0].UsePartial {
		t.Fatal("last use taken from a truncated tail was presented as the whole history")
	}
}

// The reset button emptied the ledger and rewound only the agent DNS
// offset. The house resolver offset, the strip offset and the journal
// cursor did not move. Thus the next observe tick ingested nothing again
// from those logs. The rebuilt ledger had a hole of exactly the size of the
// data that reset said it discarded. The empty ledger also went out without
// a lock. Thus a daemon flush between the two writes put the discarded
// state directly back.
func TestResetObserveRewindsEveryCheckpoint(t *testing.T) {
	c := testConfig(t)
	dir := filepath.Dir(c.OffsetPath)
	c.HouseDNSLog = filepath.Join(dir, "dns-house.jsonl")
	write(t, c.DNSLogPath, "agent log\n")
	write(t, c.HouseDNSLog, "house log line\n")
	write(t, c.StripLog, `{"a":1}`+"\n")
	cursor := filepath.Join(dir, "journal.cursor")
	if err := os.WriteFile(cursor, []byte("s=deadbeef;i=1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := c.ResetObserve(); err != nil {
		t.Fatal(err)
	}
	for _, cp := range []struct{ off, log string }{
		{filepath.Join(dir, "dns-house.offset"), c.HouseDNSLog},
		{filepath.Join(dir, "strip.offset"), c.StripLog},
	} {
		raw, err := os.ReadFile(cp.off)
		if err != nil {
			t.Fatalf("%s was never rewound: %v", filepath.Base(cp.off), err)
		}
		fi, err := os.Stat(cp.log)
		if err != nil {
			t.Fatal(err)
		}
		if want := strconv.FormatInt(fi.Size(), 10); !strings.HasPrefix(string(raw), want+" ") {
			t.Errorf("%s = %q, want the end of the log at %s", filepath.Base(cp.off), raw, want)
		}
	}
	if _, err := os.Stat(cursor); !os.IsNotExist(err) {
		t.Errorf("the journal cursor survived a reset: %v", err)
	}
}
