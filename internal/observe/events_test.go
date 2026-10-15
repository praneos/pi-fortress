package observe

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/policycompile"
)

func TestFeedForIPLongestPrefix(t *testing.T) {
	feeds := prefixFeeds(policycompile.ParseMap("203.0.113.0/24\tspamhaus-drop\n203.0.113.64/26\tfeodo-tracker\n198.51.100.7\tlocal\nnot-an-ip\tx\n"))
	cases := []struct{ ip, feed string }{
		{"203.0.113.9", "spamhaus-drop"},
		{"203.0.113.70", "feodo-tracker"},
		{"198.51.100.7", "local"},
		{"198.51.100.8", "local"},
		{"garbage", "local"},
	}
	for _, c := range cases {
		if got := feedForIP(feeds, c.ip); got != c.feed {
			t.Errorf("%s: %s, want %s", c.ip, got, c.feed)
		}
	}
}

func TestFeedForNameWalksParents(t *testing.T) {
	m := policycompile.ParseMap("evil.example\turlhaus-domains-online\nads.example\thagezi-pro\n")
	cases := []struct{ name, feed string }{
		{"evil.example", "urlhaus-domains-online"},
		{"cdn.evil.example", "urlhaus-domains-online"},
		{"example", "local"},
		{"notevil.example", "local"},
		{"", "local"},
	}
	for _, c := range cases {
		if got := feedForName(m, c.name); got != c.feed {
			t.Errorf("%s: %s, want %s", c.name, got, c.feed)
		}
	}
}

const kernelLine = `2026-09-13T15:12:41+0000 pi kernel: pi-fortress house-blacklist: IN=eth1 OUT=wlan0 MAC=b8:27:eb:00:00:01:aa:bb:cc:dd:ee:ff:08:00 SRC=10.78.0.20 DST=203.0.113.9 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=54321 DF PROTO=TCP SPT=51234 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0`

func TestParseNftLog(t *testing.T) {
	cases := []struct {
		name, line          string
		ok                  bool
		prefix, src, dst    string
		proto, dport, stamp string
	}{
		{"house blacklist tcp", kernelLine, true, "house-blacklist", "10.78.0.20", "203.0.113.9", "tcp", "443", "2026-09-13T15:12:41Z"},
		{"agent drop udp", `2026-09-13T15:12:42+0200 pi kernel: pi-fortress agent-drop: IN=eth0 OUT= MAC=aa SRC=10.77.0.10 DST=10.77.0.1 LEN=48 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=UDP SPT=5353 DPT=5353 LEN=28`,
			true, "agent-drop", "10.77.0.10", "10.77.0.1", "udp", "5353", "2026-09-13T13:12:42Z"},
		{"host named pi-fortress", `2026-09-15T00:02:56+0530 pi-fortress kernel: pi-fortress agent-blacklist: IN=eth0 OUT= SRC=10.77.0.10 DST=192.0.2.1 PROTO=TCP DPT=443`,
			true, "agent-blacklist", "10.77.0.10", "192.0.2.1", "tcp", "443", "2026-09-14T18:32:56Z"},
		{"colon offset", `2026-09-15T00:02:56+05:30 pi kernel: pi-fortress agent-doh: IN=eth0 OUT=wlan0 SRC=10.77.0.10 DST=8.8.8.8 PROTO=UDP DPT=443`,
			true, "agent-doh", "10.77.0.10", "8.8.8.8", "udp", "443", "2026-09-14T18:32:56Z"},
		{"icmp has no port", `2026-09-13T15:12:43+0000 pi kernel: pi-fortress desk-blacklist: IN=eth0.79 OUT=wlan0 SRC=10.79.0.5 DST=203.0.113.70 LEN=84 PROTO=ICMP TYPE=8 CODE=0`,
			true, "desk-blacklist", "10.79.0.5", "203.0.113.70", "icmp", "", "2026-09-13T15:12:43Z"},
		{"dmesg stamp keeps the fields", `[  123.456789] pi-fortress house-killswitch: IN=eth1 OUT=wlan0 SRC=10.78.0.20 DST=1.2.3.4 PROTO=TCP DPT=80`,
			true, "house-killswitch", "10.78.0.20", "1.2.3.4", "tcp", "80", ""},
		{"no addresses", `2026-09-13T15:12:41+0000 pi kernel: pi-fortress house-blacklist: garbage`, false, "", "", "", "", "", ""},
		{"not ours", `2026-09-13T15:12:41+0000 pi kernel: eth0: link up`, false, "", "", "", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, ok := parseNftLog(c.line)
			if ok != c.ok {
				t.Fatalf("ok=%v", ok)
			}
			if !ok {
				return
			}
			stamp := ""
			if !l.T.IsZero() {
				stamp = l.T.Format("2006-01-02T15:04:05Z")
			}
			if l.Prefix != c.prefix || l.Src != c.src || l.Dst != c.dst || l.Proto != c.proto || l.Dport != c.dport || stamp != c.stamp {
				t.Fatalf("%+v", l)
			}
		})
	}
}

func TestClassifyDirectIPAndDoH(t *testing.T) {
	o := &Observer{}
	cases := []struct {
		name, prefix, segment, threat string
		ok                            bool
	}{
		{"direct ip", "house-directip", "house", "direct_ip", true},
		{"doh", "agent-doh", "agent", "doh", true},
		{"plain http", "house-http", "house", "http", true},
		{"own vpn", "house-vpn", "house", "vpn", true},
		{"sni refused", "house-sni", "house", "sni", true},
		{"port strict drops", "house-port", "house", "port", true},
		{"port audit would drop", "house-audit", "house", "audit_port", true},
		{"local address", "house-local", "house", "lan", true},
		{"over a connection budget", "agent-connlimit", "agent", "conn_limit", true},
		{"a segment's budget", "desk-connlimit", "desk", "conn_limit", true},
		{"a spoofed source", "desk-spoof", "desk", "spoof", true},
		{"unknown suffix still refused", "agent-ssh-allow", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			segment, threat, ok := o.classify(nftLog{Prefix: c.prefix})
			if ok != c.ok || segment != c.segment || threat != c.threat {
				t.Fatalf("got %q %q %v, want %q %q %v", segment, threat, ok, c.segment, c.threat, c.ok)
			}
		})
	}
}

func TestJournalDirectIPAndDoHMakeEvents(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\n" +
		"echo '2026-09-13T15:12:41+0000 pi kernel: pi-fortress house-directip: IN=eth1 OUT=wlan0 SRC=10.78.0.20 DST=1.2.3.4 PROTO=TCP DPT=443'\n" +
		"echo '2026-09-13T15:12:42+0000 pi kernel: pi-fortress agent-doh: IN=eth0 OUT=wlan0 SRC=10.77.0.10 DST=8.8.8.8 PROTO=UDP DPT=443'\n" +
		"echo '-- cursor: c1'\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            filepath.Join(dir, "missing-ct"),
		NetEnvPath:        []string{env},
		JournalCmd:        []string{fake, "-k"},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Now:               func() time.Time { return now },
	}
	st := o.Snapshot()
	want := []Event{
		{T: time.Date(2026, 9, 13, 15, 12, 41, 0, time.UTC), Segment: "house", Src: "10.78.0.20", Dst: "1.2.3.4", Threat: "direct_ip", Detail: "tcp 443"},
		{T: time.Date(2026, 9, 13, 15, 12, 42, 0, time.UTC), Segment: "agent", Src: "10.77.0.10", Dst: "8.8.8.8", Threat: "doh", Detail: "udp 443"},
	}
	if len(st.Events) != len(want) {
		t.Fatalf("events: %+v", st.Events)
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
	}
	if c := st.Clients["house/10.78.0.20"]; c == nil || c.Blocked != 1 {
		t.Fatalf("house client: %+v", c)
	}
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 1 {
		t.Fatalf("agent client: %+v", c)
	}
}

func TestEventRingCapAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	for i := 0; i < maxEvents+5; i++ {
		o.event(st, Event{T: now.Add(time.Duration(i) * time.Second), Dst: strconv.Itoa(i), Threat: "local"})
	}
	if len(st.Events) != maxEvents || st.Events[0].T != now.Add(5*time.Second) {
		t.Fatalf("ring: %d first=%s", len(st.Events), st.Events[0].T)
	}
	st.Events = []Event{
		{T: now.Add(-eventTTL - time.Second)},
		{T: now.Add(-eventTTL + time.Second)},
		{T: now},
	}
	expireEvents(st, now)
	if len(st.Events) != 2 || st.Events[0].T != now.Add(-eventTTL+time.Second) {
		t.Fatalf("expiry: %+v", st.Events)
	}
}

// The retry loop of one client (2026-09-14: 496 house-directip hits in 10
// minutes) took 918 of the 1000 rows and evicted 640 feed hits.
func TestRepeatsCollapseWithinAMinute(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 10, 0, 0, time.UTC)
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	relay := Event{Segment: "house", Src: "10.78.0.20", Dst: "68.183.90.120", Threat: "direct_ip", Detail: "tcp 443"}
	at := func(e Event, d time.Duration) Event { e.T = now.Add(d); return e }
	o.event(st, at(relay, 0))
	o.event(st, at(relay, 30*time.Second))
	feed := relay
	feed.Threat = "hagezi-pro"
	o.event(st, at(feed, 31*time.Second))
	// A kernel-stamped line can arrive behind a row stamped now.
	o.event(st, at(relay, -20*time.Second))
	o.event(st, at(relay, 61*time.Second))
	want := []Event{at(relay, 0), at(feed, 31*time.Second), at(relay, 61*time.Second)}
	want[0].N = 3
	if len(st.Events) != len(want) {
		t.Fatalf("events: %+v", st.Events)
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
	}
	if got := st.Events[0].Hits() + st.Events[1].Hits() + st.Events[2].Hits(); got != 5 {
		t.Fatalf("hits %d", got)
	}
	if b := bucket(st, "house", now).Blocked; b != 5 {
		t.Fatalf("bucket blocked %d, want every hit", b)
	}
	var out bytes.Buffer
	o.Stdout = &out
	o.Show(st)
	if !strings.Contains(out.String(), "direct_ip tcp 443 ×3\n") || strings.Contains(out.String(), "hagezi-pro tcp 443 ×") {
		t.Fatalf("show:\n%s", out.String())
	}
}

func TestSinkholedNameMakesAnEvent(t *testing.T) {
	dir := t.TempDir()
	dmap := filepath.Join(dir, "blocked-domains.map")
	if err := os.WriteFile(dmap, []byte("evil.top\tphishing-army\n"), 0644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "dns.jsonl")
	body := rows(
		blocked("10.78.0.20", "evil.top"),
		blocked("10.78.0.20", "mine.test"),
		nxdomain("10.78.0.20", "typo.test"),
		resolved("10.78.0.21", "fine.test", "1.2.3.4"),
	)
	if err := os.WriteFile(log, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	o := &Observer{DomainMapPath: dmap, Now: func() time.Time { return now }}
	o.loadMaps()
	st := o.empty()
	o.ingestDNSLog(st, log, filepath.Join(dir, "off"), "10.78.0.0/24", "house")
	if len(st.Events) != 2 {
		t.Fatalf("events: %+v", st.Events)
	}
	want := []Event{
		{T: now, Segment: "house", Src: "10.78.0.20", Dst: "evil.top", Threat: "phishing-army", Detail: "dns A"},
		{T: now, Segment: "house", Src: "10.78.0.20", Dst: "mine.test", Threat: "local", Detail: "dns A"},
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
	}
	if c := st.Clients["house/10.78.0.20"]; c == nil || c.Blocked != 2 || c.Queries != 3 {
		t.Fatalf("client: %+v", c)
	}
	if c := st.Clients["house/10.78.0.21"]; c == nil || c.Blocked != 0 {
		t.Fatalf("client: %+v", c)
	}
}

func TestJournalDropsMakeEventsAndKeepTheCursor(t *testing.T) {
	dir := t.TempDir()
	imap := filepath.Join(dir, "blocked-ips.map")
	if err := os.WriteFile(imap, []byte("203.0.113.0/24\tspamhaus-drop\n"), 0644); err != nil {
		t.Fatal(err)
	}
	argsLog := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >>" + argsLog + "\n" +
		"case \"$*\" in *--after-cursor=c1*) echo '-- cursor: c1'; exit 0;; esac\n" +
		"echo '" + kernelLine + "'\n" +
		"echo '2026-09-13T15:12:42+0000 pi kernel: pi-fortress agent-drop: IN=eth0 OUT= SRC=10.77.0.10 DST=10.77.0.1 PROTO=TCP SPT=4 DPT=22'\n" +
		"echo '2026-09-13T15:12:43+0000 pi kernel: pi-fortress ssh-allow: IN=eth0 OUT=wlan0 SRC=10.77.0.10 DST=203.0.113.70 PROTO=TCP DPT=22'\n" +
		"echo '-- cursor: c1'\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            filepath.Join(dir, "missing-ct"),
		NetEnvPath:        []string{env},
		IPMapPath:         imap,
		JournalCmd:        []string{fake, "-k"},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Now:               func() time.Time { return now },
	}
	st := o.Snapshot()
	want := []Event{
		{T: time.Date(2026, 9, 13, 15, 12, 41, 0, time.UTC), Segment: "house", Src: "10.78.0.20", Dst: "203.0.113.9", Threat: "spamhaus-drop", Detail: "tcp 443"},
		{T: time.Date(2026, 9, 13, 15, 12, 42, 0, time.UTC), Segment: "agent", Src: "10.77.0.10", Dst: "10.77.0.1", Threat: "pi_input", Detail: "tcp 22"},
	}
	if len(st.Events) != len(want) {
		t.Fatalf("events: %+v", st.Events)
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
	}
	if c := st.Clients["house/10.78.0.20"]; c == nil || c.Blocked != 1 {
		t.Fatalf("house client: %+v", c)
	}
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 1 {
		t.Fatalf("agent client: %+v", c)
	}
	raw, err := os.ReadFile(o.JournalCursorPath)
	if err != nil || strings.TrimSpace(string(raw)) != "c1" {
		t.Fatalf("cursor on disk: %q %v", raw, err)
	}
	// A restart reads the cursor back and asks for what follows it.
	o2 := *o
	o2.st, o2.cursor, o2.cursorRead = nil, "", false
	if st := o2.Snapshot(); len(st.Events) != 2 {
		t.Fatalf("replayed: %+v", st.Events)
	}
	args, _ := os.ReadFile(argsLog)
	calls := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(calls) != 2 || !strings.Contains(calls[0], "-n 500") || !strings.Contains(calls[1], "--after-cursor=c1") {
		t.Fatalf("journalctl calls: %q", calls)
	}
	// No journalctl at all is silent.
	o.JournalCmd = []string{filepath.Join(dir, "no-such-tool")}
	if st := o.Snapshot(); len(st.Events) != 2 {
		t.Fatalf("missing tool: %+v", st.Events)
	}
}

// The address of the Pi itself showed as an agent client on 2026-09-14:
// its mDNS to 224.0.0.251, its own digs through dnsmasq, its own drops.
func TestPiIsNotAClient(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := write("net.env", "AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n", 0644)
	dns := write("dns.jsonl", rows(
		resolved("10.77.0.1", "example.com", "1.2.3.4"),
		resolved("10.77.0.10", "a.test", "1.2.3.5"),
	), 0644)
	ct := write("ct", "ipv4 2 udp 17 src=10.77.0.1 dst=224.0.0.251 sport=5353 dport=5353 bytes=1 bytes=2\n", 0644)
	fake := write("journalctl", "#!/bin/sh\n"+
		"echo '2026-09-13T15:12:42+0000 pi kernel: pi-fortress agent-blacklist: IN= OUT=eth0 SRC=10.77.0.1 DST=203.0.113.9 PROTO=TCP DPT=443'\n", 0755)
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            dns,
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            ct,
		NetEnvPath:        []string{env},
		JournalCmd:        []string{fake},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Now:               func() time.Time { return now },
	}
	st := o.Snapshot()
	if c := st.Clients["agent/10.77.0.1"]; c != nil {
		t.Fatalf("pi is a client: %+v", c)
	}
	if st.Clients["agent/10.77.0.10"] == nil || st.DNS["example.com"] != nil {
		t.Fatalf("clients %v dns %v", st.Clients, st.DNS)
	}
	if len(st.Events) != 1 || st.Events[0].Src != "10.77.0.1" {
		t.Fatalf("events: %+v", st.Events)
	}
}

// The unit runs with ProcSubset=pid. There, journalctl -k or -b fails with
// "Failed to get boot ID" (seen on the Pi 2026-09-14), so no event ever occurs.
func TestDefaultJournalCmdNeedsNoBootID(t *testing.T) {
	cmd := Defaults().JournalCmd
	if !slices.Contains(cmd, "_TRANSPORT=kernel") {
		t.Fatalf("no kernel match: %q", cmd)
	}
	for _, a := range cmd {
		if a == "-k" || a == "--dmesg" || a == "-b" || strings.HasPrefix(a, "--boot") {
			t.Fatalf("%q needs the boot ID: %q", a, cmd)
		}
	}
}

func TestJournalNoEntriesKeepsTheCursor(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >>" + argsLog + "\n" +
		"case \"$*\" in *--after-cursor=c1*) echo '-- No entries --'; exit 1;; esac\n" +
		"echo '" + kernelLine + "'\n" +
		"echo '-- cursor: c1'\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            filepath.Join(dir, "missing-ct"),
		NetEnvPath:        []string{env},
		JournalCmd:        []string{fake, "-k"},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Now:               func() time.Time { return now },
	}
	// systemd 257 exits 1 when -g matches nothing past the cursor. That
	// is not a rejected cursor: the next tick must not read -n 500 again.
	for range 3 {
		o.Snapshot()
	}
	if st := o.Snapshot(); len(st.Events) != 1 {
		t.Fatalf("events: %+v", st.Events)
	}
	if err := o.Flush(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(o.JournalCursorPath); err != nil || strings.TrimSpace(string(raw)) != "c1" {
		t.Fatalf("cursor on disk: %q %v", raw, err)
	}
	args, _ := os.ReadFile(argsLog)
	if n := strings.Count(string(args), "-n 500"); n != 1 {
		t.Fatalf("-n 500 calls: %d in %q", n, args)
	}
}

func TestJournalFailureIsLoggedOnce(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\necho 'Failed to get boot ID: No such file or directory' >&2\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            filepath.Join(dir, "missing-ct"),
		JournalCmd:        []string{fake},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Stderr:            &log,
		Now:               func() time.Time { return time.Date(2026, 9, 14, 18, 0, 0, 0, time.UTC) },
	}
	for range 3 {
		o.Snapshot()
	}
	if want := "observe: journalctl: Failed to get boot ID: No such file or directory\n"; log.String() != want {
		t.Fatalf("log %q, want %q", log.String(), want)
	}
	o.JournalCmd = []string{filepath.Join(dir, "no-such-tool")}
	o.Snapshot()
	if strings.Count(log.String(), "\n") != 1 {
		t.Fatalf("missing tool logged: %q", log.String())
	}
}

func TestStripRowsMakeCredentialEvents(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	strip := filepath.Join(dir, "strip.jsonl")
	rows := `{"t":"2026-09-13T15:12:41Z","host":"api.github.com","where":"header","rule":"github_classic","client_ip":"10.77.0.10"}` + "\n" +
		`{"t":"2026-09-13T15:12:42Z","ev":"substitution_refused","host":"pf-open-echo.test","sni":"pf-open-echo.test","where":"header","rule":"refused:kind_not_allowed_for_sni","cause":"kind_not_allowed_for_sni","slot":"a1","kind":"github","alert":true}` + "\n"
	if err := os.WriteFile(strip, []byte(rows), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
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
	st := o.Snapshot()
	want := []Event{
		{T: time.Date(2026, 9, 13, 15, 12, 41, 0, time.UTC), Segment: "agent", Src: "10.77.0.10", Dst: "api.github.com", Threat: "credential_strip", Detail: "github_classic"},
		{T: time.Date(2026, 9, 13, 15, 12, 42, 0, time.UTC), Segment: "agent", Src: "", Dst: "pf-open-echo.test", Threat: "credential_refused", Detail: "kind_not_allowed_for_sni"},
	}
	if len(st.Events) != len(want) {
		t.Fatalf("events: %+v", st.Events)
	}
	for i, w := range want {
		if st.Events[i] != w {
			t.Fatalf("event %d: %+v, want %+v", i, st.Events[i], w)
		}
	}
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 1 {
		t.Fatalf("client: %+v", c)
	}
	if len(st.Clients) != 1 {
		t.Fatalf("a row without client_ip made a client: %+v", st.Clients)
	}
	raw, err := os.ReadFile(o.StripOffsetPath)
	if err != nil || offsetOf(string(raw)) != strconv.Itoa(len(rows)) {
		t.Fatalf("offset on disk: %q %v", raw, err)
	}
	// A restart reads the offset back and replays nothing.
	o2 := *o
	o2.st, o2.offsets = nil, nil
	if st := o2.Snapshot(); len(st.Events) != 2 {
		t.Fatalf("replayed: %+v", st.Events)
	}
	// logrotate: a shorter file is read from the start.
	one := rows[:strings.Index(rows, "\n")+1]
	if err := os.WriteFile(strip, []byte(one), 0644); err != nil {
		t.Fatal(err)
	}
	// The replayed row is the same contact again, so it folds in.
	st = o2.Snapshot()
	if len(st.Events) != 2 || st.Events[0].Hits()+st.Events[1].Hits() != 3 || st.Clients["agent/10.77.0.10"].Blocked != 2 {
		t.Fatalf("after shrink: %+v, %+v", st.Events, st.Clients["agent/10.77.0.10"])
	}
}

func TestCanaryRowsMakeCanaryEvents(t *testing.T) {
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	rows := `{"t":"2026-09-13T15:12:41Z","host":"evil.example","where":"body","rule":"secret:d0d1d2d3d4d5d6d7_CANARY","client_ip":"10.77.0.10","threat":"canary"}` + "\n" +
		`{"t":"2026-09-13T15:12:42Z","ev":"substitution_refused","host":"evil.example","sni":"evil.example","where":"header","rule":"refused:kind_not_allowed_for_sni","cause":"kind_not_allowed_for_sni","slot":"d0d1d2d3d4d5d6d7","kind":"CANARY","alert":true,"client_ip":"10.77.0.10","threat":"canary"}` + "\n"
	if err := os.WriteFile(strip, []byte(rows), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	o := &Observer{
		StatePath:       filepath.Join(dir, "observe.json"),
		DNSLog:          filepath.Join(dir, "missing.log"),
		OffsetPath:      filepath.Join(dir, "off"),
		CTPath:          filepath.Join(dir, "missing-ct"),
		StripLog:        strip,
		StripOffsetPath: filepath.Join(dir, "strip.offset"),
		Now:             func() time.Time { return now },
	}
	st := o.Snapshot()
	if len(st.Events) != 2 || st.Events[0].Threat != "canary" || st.Events[0].Detail != "secret:d0d1d2d3d4d5d6d7_CANARY" ||
		st.Events[1].Threat != "canary" || st.Events[1].Detail != "kind_not_allowed_for_sni" {
		t.Fatalf("events: %+v", st.Events)
	}
}

// The ring held a thousand rows, oldest out, of any type. Thus an agent or
// a house device that caused drops pushed the dns_key and volume alerts
// out within seconds after they were raised. Those alerts, the tunnel
// alert and the canary keep a reserve of the ring through any flood of the
// other rows. Past the reserve, they age out among themselves.
func TestAlertsSurviveAFloodOfTheRing(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	o := &Observer{Now: func() time.Time { return now }}
	st := o.empty()
	threats := []string{"dns_key", "volume", "dns_tunnel", "canary"}
	for i := range 40 {
		o.event(st, Event{T: now, Src: "10.77.0.10", Dst: "keep" + strconv.Itoa(i), Threat: threats[i%4]})
	}
	for i := range 3 * maxEvents {
		o.event(st, Event{T: now, Src: "10.78.0.20", Dst: strconv.Itoa(i), Threat: "direct_ip"})
	}
	if len(st.Events) != maxEvents {
		t.Fatalf("ring %d, want %d", len(st.Events), maxEvents)
	}
	kept := 0
	for _, e := range st.Events {
		if strings.HasPrefix(e.Dst, "keep") {
			kept++
		}
	}
	if kept != 40 {
		t.Fatalf("%d of 40 alerts survived the flood", kept)
	}
	if last := st.Events[len(st.Events)-1]; last.Dst != strconv.Itoa(3*maxEvents-1) {
		t.Fatalf("the newest row is %+v", last)
	}

	st = o.empty()
	for i := range alertReserve + 50 {
		o.event(st, Event{T: now, Dst: "a" + strconv.Itoa(i), Threat: "dns_key"})
	}
	for i := range 2 * maxEvents {
		o.event(st, Event{T: now, Dst: strconv.Itoa(i), Threat: "direct_ip"})
	}
	var alerts []string
	for _, e := range st.Events {
		if e.Threat == "dns_key" {
			alerts = append(alerts, e.Dst)
		}
	}
	if len(alerts) != alertReserve || alerts[0] != "a50" {
		t.Fatalf("%d alerts kept from %v, want the newest %d", len(alerts), alerts[:1], alertReserve)
	}
}

// jsonJournal is a journalctl that prints entries c1..cN in -o json, each
// a kernel nft drop line, after the cursor that it gets. Then it waits for
// wait (an exec'd sleep), or prints the trailing cursor line.
func jsonJournal(t *testing.T, dir string, n int, wait string) (string, string) {
	t.Helper()
	argsLog := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >>" + argsLog + "\n" +
		"start=1\n" +
		"for a in \"$@\"; do case \"$a\" in --after-cursor=c*) start=$(( ${a#--after-cursor=c} + 1 ));; esac; done\n" +
		"if [ $start -gt " + strconv.Itoa(n) + " ]; then echo '-- No entries --'; exit 1; fi\n" +
		"i=$start\n" +
		"while [ $i -le " + strconv.Itoa(n) + " ]; do\n" +
		"  printf '{\"__CURSOR\":\"c%d\",\"__REALTIME_TIMESTAMP\":\"%d000000\",\"MESSAGE\":\"pi-fortress agent-drop: IN=eth0 OUT= SRC=10.77.0.10 DST=10.77.0.1 PROTO=TCP SPT=%d DPT=22\"}\\n' $i $((1790000000 + i)) $i\n" +
		"  i=$((i+1))\n" +
		"done\n"
	if wait != "" {
		script += "exec sleep " + wait + "\n"
	} else {
		script += "echo '-- cursor: c" + strconv.Itoa(n) + "'\n"
	}
	fake := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return fake, argsLog
}

func journalObserver(dir, fake string) *Observer {
	env := filepath.Join(dir, "net.env")
	_ = os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.2\n"), 0644)
	return &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		CTPath:            filepath.Join(dir, "missing-ct"),
		NetEnvPath:        []string{env},
		JournalCmd:        []string{fake, "-o", "json"},
		JournalCursorPath: filepath.Join(dir, "journal.cursor"),
		Now:               func() time.Time { return time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC) },
	}
}

// A backlog bigger than one capture lost the trailing cursor line each
// time. Thus the cursor never moved, and each tick read the same first
// 8 MiB again: the journal reader got stuck after observe downtime. Now
// the cursor comes from the last whole entry in the capture, so each tick
// continues from where the last one stopped.
func TestJournalBacklogPastTheCapStillMoves(t *testing.T) {
	dir := t.TempDir()
	fake, _ := jsonJournal(t, dir, 100, "")
	o := journalObserver(dir, fake)
	o.journalCap = 2000
	var st *State
	for range 15 {
		st = o.Snapshot()
		if err := o.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 100 {
		t.Fatalf("client %+v, want every one of 100 entries counted once", c)
	}
	if o.cursor != "c100" {
		t.Fatalf("cursor %q", o.cursor)
	}
	if e := st.Events[0]; !e.T.Equal(time.Unix(1790000001, 0).UTC()) {
		t.Fatalf("an entry's stamp is its own: %+v", e)
	}
}

// A journalctl that ran out of time dropped the cursor, and the next tick
// read the last 500 lines: the backlog between was skipped. Now it keeps
// what it read and the cursor of the last whole entry.
func TestJournalTimeoutKeepsTheBacklog(t *testing.T) {
	dir := t.TempDir()
	fake, argsLog := jsonJournal(t, dir, 5, "5")
	o := journalObserver(dir, fake)
	o.journalTimeout = 300 * time.Millisecond
	st := o.Snapshot()
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 5 {
		t.Fatalf("client %+v", c)
	}
	if o.cursor != "c5" {
		t.Fatalf("cursor %q after a timeout, want the last entry read", o.cursor)
	}
	if err := o.Flush(); err != nil {
		t.Fatal(err)
	}
	o.Snapshot()
	args, _ := os.ReadFile(argsLog)
	calls := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(calls) != 2 || !strings.Contains(calls[1], "--after-cursor=c5") {
		t.Fatalf("calls %q", calls)
	}
}

// systemd 252 under -o json prints only the cursor line and exits 1 when
// nothing is past the cursor, without "-- No entries --". The code read
// that as a failure. Thus it dropped the cursor on each quiet tick, read
// the last 500 lines again, and counted the same drops again.
func TestJSONJournalWithNothingNewKeepsTheCursor(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >>" + argsLog + "\n" +
		"case \"$*\" in *--after-cursor=c2*) echo '-- cursor: c2'; exit 1;; esac\n" +
		"for i in 1 2; do printf '{\"__CURSOR\":\"c%d\",\"__REALTIME_TIMESTAMP\":\"%d000000\",\"MESSAGE\":\"pi-fortress agent-drop: IN=eth0 OUT= SRC=10.77.0.10 DST=10.77.0.1 PROTO=TCP SPT=%d DPT=22\"}\\n' $i $((1790000000 + i)) $i; done\n" +
		"echo '-- cursor: c2'\n"
	fake := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	o := journalObserver(dir, fake)
	var errs bytes.Buffer
	o.Stderr = &errs
	o.Snapshot()
	if err := o.Flush(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		o.Snapshot()
	}
	st := o.Snapshot()
	if c := st.Clients["agent/10.77.0.10"]; c == nil || c.Blocked != 2 {
		t.Fatalf("client %+v, want the 2 drops counted once", c)
	}
	if o.cursor != "c2" {
		t.Fatalf("cursor %q, want c2 kept through quiet ticks", o.cursor)
	}
	args, _ := os.ReadFile(argsLog)
	if strings.Count(string(args), "-n 500") != 1 {
		t.Fatalf("the reader went back to the last 500 lines after a quiet tick:\n%s", args)
	}
	if errs.Len() != 0 {
		t.Fatalf("a quiet tick reported an error: %s", errs.String())
	}
}

func TestDefaultJournalCmdIsJSON(t *testing.T) {
	cmd := strings.Join(Defaults().JournalCmd, " ")
	if !strings.Contains(cmd, "-o json") {
		t.Fatalf("%q: an entry's own cursor needs -o json", cmd)
	}
}

// capWriter reports each byte as written, whatever it keeps: a short write
// ends the copy, and journalctl then dies of SIGPIPE at the limit.
func TestCapWriterNeverWritesShort(t *testing.T) {
	var b bytes.Buffer
	w := &capWriter{b: &b, n: 4}
	if n, err := w.Write([]byte("0123456789")); n != 10 || err != nil {
		t.Fatalf("Write = %d, %v; want 10, nil", n, err)
	}
	if n, _ := w.Write([]byte("abc")); n != 3 || b.String() != "0123" {
		t.Fatalf("Write = %d, kept %q", n, b.String())
	}
}

// The summary of the strip writer for the dropped rows of a client is not
// a strip itself: it makes no event and charges a block to nobody.
func TestStripSuppressedRowIsNoStrip(t *testing.T) {
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	row := `{"t":"2026-10-05T12:01:01Z","ev":"strip_suppressed","host":"*","where":"suppressed","rule":"suppressed","src":"split","count":101,"client_ip":"10.77.0.10"}` + "\n"
	if err := os.WriteFile(strip, []byte(row), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{StripLog: strip, StripOffsetPath: filepath.Join(dir, "off"), Now: func() time.Time { return time.Date(2026, 10, 5, 12, 2, 0, 0, time.UTC) }}
	st := o.empty()
	o.ingestStrip(st)
	if len(st.Events) != 0 || len(st.Clients) != 0 {
		t.Fatalf("events %+v clients %+v", st.Events, st.Clients)
	}
}
