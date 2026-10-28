package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseARP(t *testing.T) {
	fixture := strings.Join([]string{
		"IP address       HW type     Flags       HW address            Mask     Device",
		"10.77.0.10       0x1         0x2         52:54:00:AB:CD:EF     *        eth1",
		"10.78.0.20       0x1         0x2         aa:bb:cc:dd:ee:20     *        eth2",
		"10.78.0.99       0x1         0x0         00:00:00:00:00:00     *        eth2",
		"garbage",
		"",
	}, "\n")
	got := parseARP(fixture)
	want := map[string]string{"10.77.0.10": "52:54:00:ab:cd:ef", "10.78.0.20": "aa:bb:cc:dd:ee:20"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for ip, mac := range want {
		if got[ip] != mac {
			t.Fatalf("%s: %q, want %q", ip, got[ip], mac)
		}
	}
}

func TestConntrackLineToClient(t *testing.T) {
	cases := []struct {
		name, line, segment, net, self string
		skip                           []string
		flowKey, clientKey, dest       string
	}{
		{"agent tcp", "ipv4 2 tcp 6 src=10.77.0.10 dst=1.2.3.4 sport=5 dport=443 bytes=1 bytes=2",
			"", "10.77.0.0/24", "10.77.0.1", []string{"10.0.2.0/24"},
			"10.77.0.10>1.2.3.4:443/tcp", "agent/10.77.0.10", "1.2.3.4:443"},
		{"house udp", "ipv4 2 udp 17 src=10.78.0.20 dst=8.8.8.8 sport=5 dport=53 bytes=1 bytes=2",
			"house", "10.78.0.0/24", "10.78.0.1", []string{"10.0.2.0/24", "10.78.0.0/24"},
			"house/10.78.0.20>8.8.8.8:53/udp", "house/10.78.0.20", "8.8.8.8:53"},
		{"house to pi", "ipv4 2 udp 17 src=10.78.0.20 dst=10.78.0.1 sport=5 dport=53 bytes=1 bytes=2",
			"house", "10.78.0.0/24", "10.78.0.1", []string{"10.0.2.0/24", "10.78.0.0/24"}, "", "", ""},
		{"house peer", "ipv4 2 tcp 6 src=10.78.0.20 dst=10.78.0.21 sport=5 dport=22 bytes=1 bytes=2",
			"house", "10.78.0.0/24", "10.78.0.1", []string{"10.0.2.0/24", "10.78.0.0/24"}, "", "", ""},
		{"pi mdns", "ipv4 2 udp 17 src=10.77.0.1 dst=224.0.0.251 sport=5353 dport=5353 bytes=1 bytes=2",
			"", "10.77.0.0/24", "10.77.0.1", []string{"10.0.2.0/24"}, "", "", ""},
		{"off net", "ipv4 2 tcp 6 src=10.77.0.10 dst=1.2.3.4 sport=5 dport=443 bytes=1 bytes=2",
			"house", "10.78.0.0/24", "10.78.0.1", nil, "", "", ""},
		{"no tuple", "ipv4 2 icmp 1 src=10.77.0.10 dst=1.2.3.4 type=8", "", "10.77.0.0/24", "10.77.0.1", nil, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &Observer{Now: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }}
			st := o.empty()
			o.ingestCT(st, c.line, c.segment, c.net, c.self, c.skip, map[string]int64{})
			if c.flowKey == "" {
				if len(st.Flows) != 0 || len(st.Clients) != 0 {
					t.Fatalf("recorded %v %v", st.Flows, st.Clients)
				}
				return
			}
			f := st.Flows[c.flowKey]
			if f == nil || f.Segment != c.segment || f.Src != strings.Split(c.clientKey, "/")[1] || f.Bytes != 3 {
				t.Fatalf("flows %v", st.Flows)
			}
			cl := st.Clients[c.clientKey]
			if cl == nil || cl.Flows != 1 || cl.Dests[c.dest] != 1 || cl.Segment != strings.Split(c.clientKey, "/")[0] {
				t.Fatalf("client %+v", cl)
			}
		})
	}
}

func TestDNSLineToClient(t *testing.T) {
	cases := []struct {
		name, log, segment, net, clientKey string
		queries, blocked                   uint32
		names                              map[string]uint32
	}{
		{"agent forwarded", rows(resolved("10.77.0.10", "a.test", "1.2.3.4")), "", "10.77.0.0/24",
			"agent/10.77.0.10", 1, 0, map[string]uint32{"a.test": 1}},
		{"house sinkholed twice", rows(blocked("10.78.0.20", "evil.top"), blocked("10.78.0.20", "evil.top")), "house", "10.78.0.0/24",
			"house/10.78.0.20", 2, 2, map[string]uint32{"evil.top": 2}},
		{"unanswered still counts", rows(dropped("10.78.0.21", "b.test", "AAAA")), "house", "10.78.0.0/24",
			"house/10.78.0.21", 1, 0, map[string]uint32{"b.test": 1}},
		{"off net", rows(resolved("10.77.0.10", "a.test", "1.2.3.4")), "house", "10.78.0.0/24", "", 0, 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "dns.jsonl")
			if err := os.WriteFile(log, []byte(c.log), 0644); err != nil {
				t.Fatal(err)
			}
			o := &Observer{Now: time.Now}
			st := o.empty()
			o.ingestDNSLog(st, log, filepath.Join(dir, "off"), c.net, c.segment)
			if c.clientKey == "" {
				if len(st.Clients) != 0 {
					t.Fatalf("%v", st.Clients)
				}
				return
			}
			cl := st.Clients[c.clientKey]
			if cl == nil || cl.Queries != c.queries || cl.Blocked != c.blocked || cl.Flows != 0 {
				t.Fatalf("client %+v", cl)
			}
			for n, k := range c.names {
				if cl.Names[n] != k {
					t.Fatalf("names %v", cl.Names)
				}
			}
		})
	}
}

func TestSuppressedDNSFoldsIntoCounters(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	body := rows(
		suppressed("10.78.0.20", 5, false),
		suppressed("10.78.0.20", 3, true),
		suppressed("untracked", 9, false),
		suppressed("garbage-notip", 4, false),
	)
	if err := os.WriteFile(log, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), "10.78.0.0/24", "house")
	cl := st.Clients["house/10.78.0.20"]
	if cl == nil || cl.Queries != 8 || cl.Blocked != 3 {
		t.Fatalf("client %+v", cl)
	}
	if len(st.Clients) != 1 {
		t.Fatalf("untracked/unparsable src must not create a client: %v", st.Clients)
	}
	if len(st.Events) != 0 {
		t.Fatalf("suppressed lines must not create events: %+v", st.Events)
	}
	s := st.Series["house"]
	if len(s) != 1 || s[0].Queries != 21 || s[0].Blocked != 3 {
		t.Fatalf("series %+v", s)
	}
}

func TestTwoClientsOneName(t *testing.T) {
	o := &Observer{Now: time.Now}
	st := o.empty()
	o.touchDNSSeg(st, "house", "shared.test", "10.78.0.20", "A", false)
	o.touchDNSSeg(st, "house", "shared.test", "10.78.0.21", "A", false)
	o.touchDNSSeg(st, "house", "shared.test", "10.78.0.21", "A", false)
	rec := st.DNS["house/shared.test"]
	if rec.Src != "10.78.0.21" || rec.Srcs["10.78.0.20"] != 1 || rec.Srcs["10.78.0.21"] != 2 || rec.Count != 3 {
		t.Fatalf("%+v", rec)
	}
	if st.Clients["house/10.78.0.20"].Queries != 1 || st.Clients["house/10.78.0.21"].Queries != 2 {
		t.Fatalf("%+v %+v", st.Clients["house/10.78.0.20"], st.Clients["house/10.78.0.21"])
	}
}

// TestNameSrcsCapped: each query can come from a different address of the
// segment. The row of one name keeps a maximum of maxNameSrcs queriers,
// and the busiest querier stays.
func TestNameSrcsCapped(t *testing.T) {
	o := &Observer{Now: time.Now}
	st := o.empty()
	for i := 0; i < 3; i++ {
		o.touchDNSSeg(st, "house", "shared.test", "10.78.0.20", "A", false)
	}
	for i := 0; i < 1000; i++ {
		src := fmt.Sprintf("10.78.%d.%d", 1+i/250, 1+i%250)
		o.touchDNSSeg(st, "house", "shared.test", src, "A", false)
	}
	rec := st.DNS["house/shared.test"]
	if len(rec.Srcs) > maxNameSrcs {
		t.Fatalf("one name counts %d queriers, want at most %d", len(rec.Srcs), maxNameSrcs)
	}
	if rec.Srcs["10.78.0.20"] != 3 || rec.Count != 1003 {
		t.Fatalf("busiest querier %d, count %d", rec.Srcs["10.78.0.20"], rec.Count)
	}
	// A row from a state file written before the limit gets back to it.
	for i := 0; i < 500; i++ {
		rec.Srcs[fmt.Sprintf("10.78.9.%d", i)] = 1
	}
	o.touchDNSSeg(st, "house", "shared.test", "10.78.0.21", "A", false)
	if len(rec.Srcs) > maxNameSrcs || rec.Srcs["10.78.0.20"] != 3 {
		t.Fatalf("loaded row: %d queriers, busiest %d", len(rec.Srcs), rec.Srcs["10.78.0.20"])
	}
}

func TestClientCapsAndEviction(t *testing.T) {
	t.Run("names cap by count then key", func(t *testing.T) {
		m := map[string]uint32{}
		for i := 0; i < maxPerClient; i++ {
			bump(m, fmt.Sprintf("n%03d", i))
		}
		bump(m, "n000")
		bump(m, "new.test")
		if len(m) != maxPerClient || m["n000"] != 2 || m["new.test"] != 1 {
			t.Fatalf("len %d n000=%d new=%d", len(m), m["n000"], m["new.test"])
		}
		if _, ok := m["n001"]; ok {
			t.Fatal("lowest count, lowest key survived")
		}
	})
	t.Run("clients per segment by LastSeen", func(t *testing.T) {
		tick := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
		o := &Observer{Now: func() time.Time { tick = tick.Add(time.Second); return tick }}
		st := o.empty()
		for i := 0; i < maxClients+1; i++ {
			o.client(st, "house", fmt.Sprintf("10.78.%d.%d", i/256, i%256), o.nowISO())
		}
		o.client(st, "agent", "10.77.0.10", o.nowISO())
		if len(st.Clients) != maxClients+1 {
			t.Fatalf("%d clients", len(st.Clients))
		}
		if _, ok := st.Clients["house/10.78.0.0"]; ok {
			t.Fatal("oldest house client survived")
		}
		if st.Clients["agent/10.77.0.10"] == nil || st.Clients["house/10.78.1.0"] == nil {
			t.Fatal("wrong segment or newest pruned")
		}
	})
	t.Run("idle 30 days", func(t *testing.T) {
		now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
		o := &Observer{Now: func() time.Time { return now }}
		st := o.empty()
		o.client(st, "house", "10.78.0.20", now.Add(-clientIdle-time.Hour).Format("2006-01-02T15:04:05Z"))
		o.client(st, "house", "10.78.0.21", now.Add(-clientIdle+time.Hour).Format("2006-01-02T15:04:05Z"))
		o.evictIdle(st)
		if st.Clients["house/10.78.0.20"] != nil || st.Clients["house/10.78.0.21"] == nil {
			t.Fatalf("%v", st.Clients)
		}
	})
}

// flushObserver tails one agent query per Snapshot, so each tick buffers
// a first-seen row.
func flushObserver(t *testing.T, now *time.Time) (*Observer, func(name string)) {
	t.Helper()
	dir := t.TempDir()
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:    filepath.Join(dir, "observe.json"),
		JSONLPath:    filepath.Join(dir, "observe.jsonl"),
		DNSLog:       filepath.Join(dir, "dns.jsonl"),
		OffsetPath:   filepath.Join(dir, "dns.offset"),
		CTPath:       filepath.Join(dir, "missing-ct"),
		NetEnvPath:   []string{env},
		HouseEnvPath: []string{filepath.Join(dir, "absent.env")},
		Now:          func() time.Time { return *now },
	}
	query := func(name string) {
		f, err := os.OpenFile(o.DNSLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(rows(resolved("10.77.0.10", name, "1.2.3.4")))
		f.Close()
	}
	return o, query
}

func onDisk(t *testing.T, o *Observer) (rows int, state bool) {
	t.Helper()
	raw, _ := os.ReadFile(o.JSONLPath)
	_, err := os.Stat(o.StatePath)
	return strings.Count(string(raw), "\n"), err == nil
}

func TestFlushByBytes(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	o, query := flushObserver(t, &now)
	o.FlushBytes, o.FlushInterval = 150, time.Hour
	query("one.test")
	o.Snapshot()
	if rows, state := onDisk(t, o); rows != 0 || state {
		t.Fatalf("flushed under the cap: rows=%d state=%v", rows, state)
	}
	if _, err := os.Stat(o.OffsetPath); err == nil {
		t.Fatal("offset written before the flush")
	}
	query("two.test")
	o.Snapshot()
	if rows, state := onDisk(t, o); rows != 2 || !state {
		t.Fatalf("cap reached: rows=%d state=%v", rows, state)
	}
	if o.rows.Len() != 0 {
		t.Fatal("buffer not drained")
	}
	if len(o.Load().DNS) != 2 {
		t.Fatalf("state on disk %v", o.Load().DNS)
	}
}

func TestFlushByInterval(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	o, query := flushObserver(t, &now)
	o.FlushBytes, o.FlushInterval = 10<<20, 15*time.Minute
	query("one.test")
	o.Snapshot()
	now = now.Add(14 * time.Minute)
	query("two.test")
	o.Snapshot()
	if rows, state := onDisk(t, o); rows != 0 || state {
		t.Fatalf("flushed early: rows=%d state=%v", rows, state)
	}
	now = now.Add(time.Minute)
	o.Snapshot()
	if rows, state := onDisk(t, o); rows != 2 || !state {
		t.Fatalf("interval: rows=%d state=%v", rows, state)
	}
	// Shutdown flushes whatever the interval has not.
	query("three.test")
	o.Snapshot()
	if err := o.Flush(); err != nil {
		t.Fatal(err)
	}
	if rows, _ := onDisk(t, o); rows != 3 {
		t.Fatalf("rows after Flush %d", rows)
	}
	raw, _ := os.ReadFile(o.OffsetPath)
	if fi, _ := os.Stat(o.DNSLog); offsetOf(string(raw)) != fmt.Sprint(fi.Size()) {
		t.Fatalf("offset %q, log size %d", raw, fi.Size())
	}
}

func TestEnrichNamesAndMACs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := &Observer{
		Now:         time.Now,
		ARPPath:     write("arp", "IP address HW type Flags HW address Mask Device\n10.78.0.20 0x1 0x2 aa:bb:cc:dd:ee:20 * eth2\n10.77.0.10 0x1 0x2 52:54:00:00:00:10 * eth1\n"),
		HouseLeases: write("leases", "1893456000 aa:bb:cc:dd:ee:20 10.78.0.20 phone 01:aa\n1893456000 aa:bb:cc:dd:ee:21 10.78.0.21 * 01:ab\n"),
		HouseHosts:  write("hosts", "# reserved\naa:bb:cc:dd:ee:21,10.78.0.21,printer\n"),
	}
	st := o.empty()
	for _, ip := range []string{"10.78.0.20", "10.78.0.21", "10.78.0.22"} {
		o.client(st, "house", ip, o.nowISO())
	}
	o.client(st, "agent", "10.77.0.10", o.nowISO())
	o.enrich(st)
	want := map[string][2]string{
		"house/10.78.0.20": {"aa:bb:cc:dd:ee:20", "phone"},
		"house/10.78.0.21": {"aa:bb:cc:dd:ee:21", "printer"},
		"house/10.78.0.22": {"", ""},
		"agent/10.77.0.10": {"52:54:00:00:00:10", ""},
	}
	for k, w := range want {
		c := st.Clients[k]
		if c.MAC != w[0] || c.Name != w[1] {
			t.Fatalf("%s: %+v, want %v", k, c, w)
		}
	}
}
