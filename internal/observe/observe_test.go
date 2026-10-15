package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPruneTieBreakIsDeterministic makes sure that map iteration order does not leak
// into the choice of which of two equally-stale entries is dropped. It
// builds the same tied table many times and requires the same victim each time.
func TestPruneTieBreakIsDeterministic(t *testing.T) {
	victims := map[string]bool{}
	for i := 0; i < 50; i++ {
		table := map[string]string{"b": "same", "a": "same", "c": "same"}
		dropped := prune(table, 2, func(v string) string { return v })
		if len(dropped) != 1 {
			t.Fatalf("dropped = %v, want 1 entry", dropped)
		}
		victims[dropped[0]] = true
	}
	if len(victims) != 1 {
		t.Fatalf("prune dropped different keys across runs: %v", victims)
	}
}

func TestDNSIngestAndShow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "dns.jsonl")
	body := rows(
		resolved("10.77.0.10", "example.com", "93.184.216.34"),
		blocked("10.77.0.10", "pi-fortress-block.test"),
		resolved("8.8.8.8", "evil.com", "1.2.3.4"),
	)
	if err := os.WriteFile(logPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nVBOX_NAT_NET=10.0.2.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		JSONLPath:  filepath.Join(dir, "observe.jsonl"),
		DNSLog:     logPath,
		OffsetPath: filepath.Join(dir, "dns.offset"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		NetEnvPath: []string{env},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	st := o.Snapshot()
	if st.DNS["example.com"] == nil || st.DNS["example.com"].Count != 1 || st.DNS["example.com"].Sinkholed {
		t.Fatalf("%+v", st.DNS["example.com"])
	}
	if st.DNS["pi-fortress-block.test"] == nil || !st.DNS["pi-fortress-block.test"].Sinkholed {
		t.Fatalf("%+v", st.DNS["pi-fortress-block.test"])
	}
	if _, ok := st.DNS["evil.com"]; ok {
		t.Fatal("non-agent query ingested")
	}
	var out strings.Builder
	o.Stdout = &out
	o.Show(st)
	if !strings.Contains(out.String(), "example.com") || !strings.Contains(out.String(), "sinkhole") {
		t.Fatal(out.String())
	}
	jsonl, err := os.ReadFile(o.JSONLPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonl), `"kind":"dns"`) {
		t.Fatal(string(jsonl))
	}
}

func TestConntrackSkipPiAndNAT(t *testing.T) {
	dir := t.TempDir()
	ct := filepath.Join(dir, "ct")
	lines := []string{
		"ipv4 2 tcp 6 src=10.77.0.10 dst=93.184.216.34 sport=12345 dport=443 src=93.184.216.34 dst=10.77.0.10 sport=443 dport=12345 bytes=100 bytes=200",
		"ipv4 2 tcp 6 src=10.77.0.10 dst=10.77.0.1 sport=3333 dport=53 bytes=10 bytes=10",
		"ipv4 2 tcp 6 src=10.77.0.10 dst=10.0.2.2 sport=1 dport=80 bytes=5 bytes=5",
		"",
	}
	if err := os.WriteFile(ct, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nVBOX_NAT_NET=10.0.2.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		JSONLPath:  filepath.Join(dir, "observe.jsonl"),
		DNSLog:     filepath.Join(dir, "missing.log"),
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     ct,
		NetEnvPath: []string{env},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	st := o.Snapshot()
	key := "10.77.0.10>93.184.216.34:443/tcp"
	if st.Flows[key] == nil || st.Flows[key].Bytes != 300 || st.Flows[key].Src != "10.77.0.10" {
		t.Fatalf("%+v", st.Flows)
	}
	if _, ok := st.Flows["10.77.0.10>10.77.0.1:53/tcp"]; ok {
		t.Fatal("pi dest")
	}
	if _, ok := st.Flows["10.77.0.10>10.0.2.2:80/tcp"]; ok {
		t.Fatal("nat dest")
	}
	c := st.Clients["agent/10.77.0.10"]
	if c == nil || c.Flows != 1 || c.Dests["93.184.216.34:443"] != 1 || c.Queries != 0 {
		t.Fatalf("client %+v", c)
	}
	// The same entry still open on the next poll is not another connection.
	if st = o.Snapshot(); st.Clients["agent/10.77.0.10"].Flows != 1 {
		t.Fatalf("client %+v", st.Clients["agent/10.77.0.10"])
	}
}

func TestConntrackCmdFallback(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "conntrack")
	script := "#!/bin/sh\n" +
		"[ \"$1\" = -L ] || exit 2\n" +
		"echo 'ipv4     2 tcp      6 117 TIME_WAIT src=10.77.0.10 dst=172.66.147.243 sport=51234 dport=443 packets=6 bytes=517 src=172.66.147.243 dst=10.77.0.10 sport=443 dport=51234 packets=5 bytes=4321 [ASSURED] mark=0 use=1'\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		JSONLPath:  filepath.Join(dir, "observe.jsonl"),
		DNSLog:     filepath.Join(dir, "missing.log"),
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		CTCmd:      []string{fake, "-L", "-o", "extended"},
		NetEnvPath: []string{env},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	st := o.Snapshot()
	key := "10.77.0.10>172.66.147.243:443/tcp"
	if st.Flows[key] == nil || st.Flows[key].Bytes != 4838 {
		t.Fatalf("%+v", st.Flows)
	}

	o.CTCmd = []string{filepath.Join(dir, "no-such-tool")}
	if st := o.Snapshot(); len(st.Flows) != 1 {
		t.Fatalf("missing tool must be silent, got %+v", st.Flows)
	}
}

func TestHouseDNSIngestTaggedAndKeyed(t *testing.T) {
	dir := t.TempDir()
	agentLog := filepath.Join(dir, "dns.jsonl")
	houseLog := filepath.Join(dir, "dns-house.jsonl")
	if err := os.WriteFile(agentLog, []byte(rows(resolved("10.77.0.10", "example.com", "93.184.216.34"))), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(houseLog, []byte(rows(
		resolved("10.78.0.20", "example.com", "93.184.216.34"),
		blocked("10.78.0.21", "evil.top"),
		resolved("10.77.0.10", "stray.com", "1.2.3.4"),
	)), 0644); err != nil {
		t.Fatal(err)
	}
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	houseEnv := filepath.Join(dir, "house.env")
	if err := os.WriteFile(houseEnv, []byte("HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:       filepath.Join(dir, "observe.json"),
		JSONLPath:       filepath.Join(dir, "observe.jsonl"),
		DNSLog:          agentLog,
		OffsetPath:      filepath.Join(dir, "dns.offset"),
		CTPath:          filepath.Join(dir, "missing-ct"),
		NetEnvPath:      []string{netEnv},
		HouseEnvPath:    []string{houseEnv},
		HouseDNSLog:     houseLog,
		HouseOffsetPath: filepath.Join(dir, "dns-house.offset"),
		Now:             func() time.Time { return time.Date(2026, 9, 6, 1, 2, 3, 0, time.UTC) },
	}
	st := o.Snapshot()
	if st.DNS["example.com"] == nil || st.DNS["example.com"].Segment != "" || st.DNS["example.com"].Src != "10.77.0.10" {
		t.Fatalf("agent record changed: %+v", st.DNS["example.com"])
	}
	h := st.DNS["house/example.com"]
	if h == nil || h.Segment != "house" || h.Src != "10.78.0.20" {
		t.Fatalf("house record %+v", h)
	}
	if e := st.DNS["house/evil.top"]; e == nil || !e.Sinkholed {
		t.Fatalf("house sinkhole %+v", e)
	}
	if _, ok := st.DNS["house/stray.com"]; ok {
		t.Fatal("a query from the agent net in the house log was accepted")
	}
	jsonl, _ := os.ReadFile(o.JSONLPath)
	if !strings.Contains(string(jsonl), `"segment":"house"`) {
		t.Fatal(string(jsonl))
	}
	// No house.env: the house log is ignored even if present.
	o2 := *o
	o2.HouseEnvPath = []string{filepath.Join(dir, "absent.env")}
	o2.StatePath = filepath.Join(dir, "observe2.json")
	o2.HouseOffsetPath = filepath.Join(dir, "off2")
	if st2 := o2.Snapshot(); st2.DNS["house/example.com"] != nil {
		t.Fatal("house log ingested without house.env")
	}
}

// A plain segment now resolves through this box. Thus its rows must be
// read and tagged with its own name. Before the desk got a resolver,
// there was nothing to read: segments.d described a segment that observe
// never opened a log for, and a desk lookup was nowhere in the
// ledger.
func TestAPlainSegmentsRowsAreReadAndTagged(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"desk.env":  "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n",
		"half.env":  "IF=eth4\n",
		"bad.env":   "IF=eth5\nNET=not-a-net\nIP=10.81.0.1\n",
		"notes.txt": "NET=10.82.0.0/24\nIP=10.82.0.1\n",
	} {
		if err := os.WriteFile(filepath.Join(segs, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	agentLog := filepath.Join(dir, "dns.jsonl")
	houseLog := filepath.Join(dir, "dns-house.jsonl")
	deskLog := filepath.Join(dir, "dns-desk.jsonl")
	for path, body := range map[string]string{
		agentLog: rows(resolved("10.77.0.10", "example.com", "93.184.216.34")),
		houseLog: "",
		deskLog: rows(
			resolved("10.79.0.2", "example.com", "93.184.216.34"),
			blocked("10.79.0.2", "evil.top"),
			resolved("10.79.0.1", "self.com", "1.2.3.4"),
			resolved("10.77.0.10", "stray.com", "1.2.3.4"),
		),
	} {
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:       filepath.Join(dir, "observe.json"),
		JSONLPath:       filepath.Join(dir, "observe.jsonl"),
		DNSLog:          agentLog,
		OffsetPath:      filepath.Join(dir, "dns.offset"),
		CTPath:          filepath.Join(dir, "missing-ct"),
		NetEnvPath:      []string{netEnv},
		HouseEnvPath:    []string{filepath.Join(dir, "absent.env")},
		HouseDNSLog:     houseLog,
		HouseOffsetPath: filepath.Join(dir, "dns-house.offset"),
		SegmentsDir:     segs,
		Now:             func() time.Time { return time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC) },
	}
	st := o.Snapshot()
	if d := st.DNS["desk/example.com"]; d == nil || d.Segment != "desk" || d.Src != "10.79.0.2" {
		t.Fatalf("desk record %+v", d)
	}
	if e := st.DNS["desk/evil.top"]; e == nil || !e.Sinkholed {
		t.Fatalf("desk sinkhole %+v", e)
	}
	if _, ok := st.DNS["desk/self.com"]; ok {
		t.Error("the segment's own address counted as one of its clients")
	}
	if _, ok := st.DNS["desk/stray.com"]; ok {
		t.Error("a query from another net in the desk log was accepted")
	}
	if st.DNS["example.com"] == nil {
		t.Error("the agent segment stopped being read")
	}
	// A segment that observe cannot describe is a segment that it does not
	// count. It is not a reason to drop the ledger: the half, the malformed
	// and the file that is not a segment at all are all skipped silently.
	if got := len(PlainSegments(o.SegmentsDir)); got != 1 {
		t.Errorf("plain segments read: %d, want the one that is complete", got)
	}
	// segments() is the wider list -- each L2 that the box terminates,
	// which the ARP watch needs. Thus it also carries the agent segment. A
	// read of the plain segments through it would count the agent log twice.
	if got := len(o.segments()); got != 2 {
		t.Errorf("segments read: %d, want the agent segment and the desk", got)
	}
	if !strings.Contains(string(mustRead(t, o.JSONLPath)), `"segment":"desk"`) {
		t.Error("the stream does not say which segment asked")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
