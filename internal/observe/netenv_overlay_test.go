package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// apply sources net.env and then the net.env.local of the operator. Thus
// the agent subnet that the fence was built from is the subnet of the
// overlay. An observer that reads only the base measures a segment that
// the box does not have. Each query from the real agent then looks like it
// came from outside the segment and is dropped, and the screen of the
// operator says that the agent made no queries at all.
func TestSnapshotTakesTheAgentSubnetFromTheOperatorOverlay(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	logPath := write("dns.jsonl", rows(resolved("10.99.0.10", "example.com", "93.184.216.34")))
	env := write("net.env", "AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nVBOX_NAT_NET=10.0.2.0/24\n")
	local := write("net.env.local", "AGENT_NET=10.99.0.0/24\nPI_IP=10.99.0.1\n")

	o := &Observer{
		StatePath:   filepath.Join(dir, "observe.json"),
		JSONLPath:   filepath.Join(dir, "observe.jsonl"),
		DNSLog:      logPath,
		OffsetPath:  filepath.Join(dir, "dns.offset"),
		CTPath:      filepath.Join(dir, "missing-ct"),
		NetEnvPath:  []string{env},
		NetEnvLocal: local,
		Now:         func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	st := o.Snapshot()
	if st.DNS["example.com"] == nil {
		t.Fatal("a query from the overlay's agent subnet was dropped as off-segment; observe read net.env without net.env.local")
	}
}
