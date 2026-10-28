package observe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/base"
	"pi-fortress/internal/jsonl"
)

const testDomainMap = "evil.example\turlhaus-domains-online\n" +
	"mine.example\tlocal\n" +
	"both.example\tlocal\n" +
	base.MapHouseMark + "\n" +
	"ads.example\thagezi-pro\n" +
	"vpn.example\thagezi-doh-vpn-proxy-bypass\n" +
	"bedtime.example\tlocal\n" +
	"both.example\tlocal\n"

// The two halves of the domain map give the class. Both halves label an
// operator entry "local", so only the half tells blacklist.domains from
// house.domains.
func TestDomainMapHalvesGiveTheClass(t *testing.T) {
	o := &Observer{}
	o.domainFeeds, o.domainLists = parseDomainMap(testDomainMap)
	cases := []struct{ name, class, feed string }{
		{"evil.example", jsonl.BlockSecurity, "urlhaus-domains-online"},
		{"a.b.evil.example", jsonl.BlockSecurity, "urlhaus-domains-online"},
		{"mine.example", jsonl.BlockOperator, "local"},
		{"both.example", jsonl.BlockOperator, "local"},
		{"ads.example", jsonl.BlockHouse, "hagezi-pro"},
		{"x.vpn.example", jsonl.BlockHouse, "hagezi-doh-vpn-proxy-bypass"},
		{"bedtime.example", jsonl.BlockHouse, "local"},
		{"dns.unlisted.example", jsonl.BlockOther, ""},
	}
	for _, c := range cases {
		if class, feed := o.nameClass(c.name); class != c.class || feed != c.feed {
			t.Errorf("%s: %s %q, want %s %q", c.name, class, feed, c.class, c.feed)
		}
	}
	// ParseMap still reads the same map: the mark is not an item.
	if m := base.ParseMap(testDomainMap); len(m) != len(o.domainFeeds) || m[base.MapHouseMark] != "" {
		t.Fatalf("ParseMap: %v", m)
	}
	// A map from before the mark reads all names as shared.
	o.domainFeeds, o.domainLists = parseDomainMap("ads.example\thagezi-pro\n")
	if class, _ := o.nameClass("ads.example"); class != jsonl.BlockSecurity {
		t.Fatalf("old map: %s", class)
	}
}

func readBlocks(t *testing.T, path string) []jsonl.Blocks {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []jsonl.Blocks
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var b jsonl.Blocks
		if err := json.Unmarshal([]byte(line), &b); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		out = append(out, b)
	}
	return out
}

// Flush writes one Blocks row for each segment to the notice log, with
// the checkpoints. A second pass over the same logs, also after a
// restart, writes nothing again. A house list block is only a count.
func TestBlocksRowsGoToNoticeWithTheCheckpoints(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dmap := write("blocked-domains.map", testDomainMap)
	imap := write("blocked-ips.map", "203.0.113.0/24\tspamhaus-drop\n192.0.2.1\tlocal\n")
	env := write("net.env", "AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n")
	house := write("house.env", "HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\n")
	agentLog := write("dns.jsonl", rows(
		blocked("10.77.0.10", "evil.example"),
		blocked("10.77.0.10", "evil.example"),
		blocked("10.77.0.11", "dns.unlisted.example"),
	))
	houseLog := write("dns-house.jsonl", rows(
		blocked("10.78.0.20", "ads.example"),
		blocked("10.78.0.20", "ads.example"),
		blocked("10.78.0.21", "mine.example"),
	))
	fake := write("journalctl", "#!/bin/sh\ncase \"$*\" in *--after-cursor=c1*) echo '-- cursor: c1'; exit 0;; esac\n"+
		"echo '"+kernelLine+"'\n"+
		"echo '2026-09-13T15:12:42+0000 pi kernel: pi-fortress agent-blacklist: IN=eth0 OUT=wlan0 SRC=10.77.0.10 DST=192.0.2.1 PROTO=TCP DPT=443'\n"+
		"echo '2026-09-13T15:12:43+0000 pi kernel: pi-fortress agent-drop: IN=eth0 OUT= SRC=10.77.0.10 DST=10.77.0.1 PROTO=TCP DPT=22'\n"+
		"echo '-- cursor: c1'\n")
	if err := os.Chmod(fake, 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	notice := filepath.Join(dir, "notice.jsonl")
	mk := func() *Observer {
		return &Observer{
			StatePath: filepath.Join(dir, "observe.json"), NoticePath: notice,
			DNSLog: agentLog, OffsetPath: filepath.Join(dir, "off"),
			HouseEnvPath: []string{house}, HouseDNSLog: houseLog, HouseOffsetPath: filepath.Join(dir, "house.off"),
			CTPath: filepath.Join(dir, "missing-ct"), NetEnvPath: []string{env},
			DomainMapPath: dmap, IPMapPath: imap,
			JournalCmd: []string{fake}, JournalCursorPath: filepath.Join(dir, "journal.cursor"),
			Now: func() time.Time { return now },
		}
	}
	o := mk()
	o.Snapshot()
	got := readBlocks(t, notice)
	if len(got) != 2 || got[0].Where != "agent" || got[1].Where != "house" {
		t.Fatalf("rows: %+v", got)
	}
	agent, hs := got[0], got[1]
	if agent.Threat != jsonl.BlocksThreat || agent.Counts[jsonl.BlockSecurity] != 2 || agent.Counts[jsonl.BlockOther] != 1 ||
		agent.Counts[jsonl.BlockOperator] != 1 || len(agent.Counts) != 3 {
		t.Fatalf("agent counts: %+v", agent.Counts)
	}
	if top := agent.Top[0]; top.Dst != "evil.example" || top.Src != "10.77.0.10" || top.N != 2 || top.Feed != "urlhaus-domains-online" {
		t.Fatalf("agent top: %+v", agent.Top)
	}
	if hs.Counts[jsonl.BlockHouse] != 2 || hs.Counts[jsonl.BlockOperator] != 1 || hs.Counts[jsonl.BlockSecurity] != 1 {
		t.Fatalf("house counts: %+v", hs.Counts)
	}
	for _, h := range hs.Top {
		if h.Class == jsonl.BlockHouse {
			t.Fatalf("a house list block has a name in the row: %+v", hs.Top)
		}
	}
	// Nothing new: no row. A restart reads from the checkpoints: no row.
	o.Snapshot()
	mk().Snapshot()
	if n := len(readBlocks(t, notice)); n != 2 {
		t.Fatalf("rows after replay: %d", n)
	}
}

// The tally keeps a bounded number of names. Past it, a block still
// counts in its class.
func TestTallyIsBounded(t *testing.T) {
	var tl blockTally
	for i := range maxTallyHits + 10 {
		tl.add("agent", jsonl.BlockSecurity, "f", "10.77.0.10", "n"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+".example"+string(rune('a'+i/26%26)), 1)
	}
	if len(tl.hits) > maxTallyHits || tl.counts["agent"][jsonl.BlockSecurity] != maxTallyHits+10 {
		t.Fatalf("hits %d counts %v", len(tl.hits), tl.counts)
	}
	if rows := tl.rows(time.Now()); len(rows[0].Top) != maxRowHits {
		t.Fatalf("top: %d", len(rows[0].Top))
	}
}
