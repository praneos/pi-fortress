package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A query that the resolver policy suppressed with an empty
// answer came here as "config NAME is NODATA" before. An upstream empty
// answer says the same. Thus the reader counted deliberate policy as
// ordinary traffic that did not resolve by chance, and a filtered AAAA and
// a sinkhole were the same line. Now it is "filtered", and it counts in
// its own column -- not in Blocked, where a filter that fires on each
// ordinary name would hide the blocks, and not as an Event, for which the
// ring has no room.
func TestPolicySuppressionCountsAsPolicy(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	body := rows(
		filtered("10.78.0.20", "ordinary.test", "AAAA"),
		blocked("10.78.0.20", "evil.top"),
		nodata("10.78.0.20", "nothing.test", "MX"),
	)
	if err := os.WriteFile(log, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), "10.78.0.0/24", "house")

	c := st.Clients["house/10.78.0.20"]
	if c == nil {
		t.Fatalf("no client: %v", st.Clients)
	}
	if c.Queries != 3 {
		t.Fatalf("client %+v, want all three queries counted", c)
	}
	if c.Filtered != 1 {
		t.Fatalf("client %+v, want the one suppressed query counted as policy", c)
	}
	if c.Blocked != 1 {
		t.Fatalf("client %+v: policy suppression must not be counted as a block, and the sinkhole must still be one", c)
	}
	b := st.Series["house"]
	if len(b) != 1 || b[0].Filtered != 1 || b[0].Blocked != 1 || b[0].Queries != 3 {
		t.Fatalf("hourly bucket %+v", b)
	}
	// The suppressed name is still a name that was asked for, and it
	// raises no event: the ring holds blocks, not policy that fires on
	// ordinary traffic.
	if rec := st.DNS["house/ordinary.test"]; rec == nil || rec.Sinkholed {
		t.Fatalf("dns record %+v", rec)
	}
	if len(st.Events) != 1 {
		t.Fatalf("%d events, want only the sinkhole: %+v", len(st.Events), st.Events)
	}
}
