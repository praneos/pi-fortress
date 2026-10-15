package monitor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseStatTicksCommWithSpaces(t *testing.T) {
	stat := "1234 (pf broker) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 75 0 0 20 0 9 0 1000 12345678 3000 18446744073709551615"
	if got := parseStatTicks(stat); got != 325 {
		t.Fatalf("ticks %d", got)
	}
	if parseStatTicks("garbage") != 0 {
		t.Fatal("garbage must be zero")
	}
}

func TestParseStatusMeminfoLoad(t *testing.T) {
	rss, thr, uid := parseStatus("Name:\tpf\nUid:\t998\t998\t998\t998\nVmRSS:\t   12345 kB\nThreads:\t9\n")
	if rss != 12345 || thr != 9 || uid != 998 {
		t.Fatalf("%d %d %d", rss, thr, uid)
	}
	total, avail, swap := parseMeminfo("MemTotal:  8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 100 kB\nSwapFree: 60 kB\n")
	if total != 8000000 || avail != 6000000 || swap != 40 {
		t.Fatalf("%d %d %d", total, avail, swap)
	}
	l1, l5 := parseLoadavg("0.42 0.30 0.10 1/200 4321\n")
	if l1 != 0.42 || l5 != 0.30 {
		t.Fatalf("%v %v", l1, l5)
	}
}

func TestParseWirelessAndNetDev(t *testing.T) {
	w := parseWireless("Inter-| sta-|   Quality        |   Discarded packets\n face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon\n wlan0: 0000   58.  -52.  -256        0      0      0     12      0        0\n")
	if got := w["wlan0"]; got.Quality != 58 || got.LevelDB != -52 {
		t.Fatalf("%+v", w)
	}
	nd := parseNetDev("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0 7000 12 0 0 0 0 0 0\n")
	if _, ok := nd["lo"]; ok {
		t.Fatal("lo must be skipped")
	}
	if nd["eth0"] != [2]uint64{5000, 7000} {
		t.Fatalf("%v", nd["eth0"])
	}
}

func TestDecodeThrottled(t *testing.T) {
	if decodeThrottled("0") != nil || decodeThrottled("") != nil {
		t.Fatal("zero must be nil")
	}
	got := decodeThrottled("throttled=0x50005")
	want := []string{"undervolt", "throttled", "undervolt_past", "throttled_past"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", got)
	}
}

func TestSampleSeesSelfAndRates(t *testing.T) {
	m := Defaults()
	m.Names = []string{filepath.Base(os.Args[0])}
	m.Dir = filepath.Join(t.TempDir(), "monitor")
	now := time.Unix(1_700_000_000, 0)
	m.Now = func() time.Time { return now }
	first := m.Sample()
	if first.MemTotalMB == 0 || first.Load1 < 0 {
		t.Fatalf("no box facts: %+v", first)
	}
	var me *Proc
	for i := range first.Procs {
		if first.Procs[i].PID == os.Getpid() {
			me = &first.Procs[i]
		}
	}
	if me == nil || me.RSSKB == 0 || me.Threads == 0 {
		t.Fatalf("own process not sampled: %+v", first.Procs)
	}
	busy := 0
	for i := 0; i < 20_000_000; i++ {
		busy += i % 7
	}
	_ = busy
	now = now.Add(time.Minute)
	second := m.Sample()
	for _, p := range second.Procs {
		if p.PID == os.Getpid() && p.CPU < 0 {
			t.Fatalf("negative cpu %+v", p)
		}
	}
	if err := m.Append(second); err != nil {
		t.Fatal(err)
	}
	tail, err := m.Tail(5)
	if err != nil || len(tail) != 1 || tail[0].TS != second.TS {
		t.Fatalf("tail %v %v", tail, err)
	}
	var out bytes.Buffer
	Print(&out, tail)
	if !strings.Contains(out.String(), "load=") || !strings.Contains(out.String(), "pid=") {
		t.Fatalf("%s", out.String())
	}
	if second.CPUs == 0 || second.MemUsedPct <= 0 || second.MemUsedPct >= 100 {
		t.Fatalf("box cpu/mem: %+v", second)
	}
}

func TestRoundedFloatsInJSON(t *testing.T) {
	m := &Monitor{Dir: t.TempDir()}
	s := Sample{TS: "2026-09-07T10:00:00Z", CPU: round1(28.000000000003), MemUsedPct: round1(3.5499), TempC: round1(47.412), Net: map[string]Net{"eth0": {RxKBps: round1(1234.5678)}}}
	s.Procs = []Proc{{PID: 1, Name: "pf engine", CPU: round1(0.049), RSSKB: 20480}}
	if err := m.Append(s); err != nil {
		t.Fatal(err)
	}
	sys, _ := os.ReadFile(m.file("system", "2026-09-07"))
	for _, want := range []string{`"cpu_pct":28,`, `"mem_used_pct":3.5,`, `"temp_c":47.4,`, `"rx_kbps":1234.6`} {
		if !strings.Contains(string(sys), want) {
			t.Fatalf("want %s in %s", want, sys)
		}
	}
	if strings.Contains(string(sys), "procs") || strings.Contains(string(sys), "pf engine") {
		t.Fatalf("procs leaked into the system line: %s", sys)
	}
	procs, _ := os.ReadFile(m.file("procs", "2026-09-07"))
	if string(procs) != `{"ts":"2026-09-07T10:00:00Z","pid":1,"name":"pf engine","uid":0,"cpu_pct":0,"rss_kb":20480,"threads":0,"fds":0}`+"\n" {
		t.Fatalf("%s", procs)
	}
}

func TestDailyFilesPruneTailSummarize(t *testing.T) {
	m := &Monitor{Dir: filepath.Join(t.TempDir(), "monitor")}
	_ = os.MkdirAll(m.Dir, 0755)
	for _, legacy := range []string{"monitor.jsonl", "monitor.jsonl.1"} {
		_ = os.WriteFile(filepath.Join(m.Dir, legacy), []byte("{}\n"), 0644)
	}
	_ = os.WriteFile(m.file("system", "2026-08-30"), []byte(`{"ts":"2026-08-30T00:00:00Z","cpu_pct":99}`+"\n"), 0644)
	_ = os.WriteFile(m.file("procs", "2026-08-30"), []byte(`{"ts":"2026-08-30T00:00:00Z","name":"old"}`+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(m.Dir, "system-notes.txt"), []byte("keep"), 0644)
	day := func(d int, hour int, cpu, mem float64, procCPU float64) Sample {
		ts := time.Date(2026, 9, d, hour, 0, 0, 0, time.UTC).Format(time.RFC3339)
		return Sample{TS: ts, CPU: cpu, MemUsedMB: uint64(mem * 80), MemUsedPct: mem, TempC: 45,
			Procs: []Proc{{PID: 10, Name: "pf engine", CPU: procCPU, RSSKB: 10240}, {PID: 20, Name: "dnsmasq", CPU: 0, RSSKB: 2048}, {PID: 21, Name: "dnsmasq", CPU: 1, RSSKB: 4096}}}
	}
	for _, s := range []Sample{day(1, 0, 10, 3, 1), day(6, 12, 2, 4, 3), day(7, 9, 4, 5, 5), day(7, 10, 6, 5, 7)} {
		if err := m.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, gone := range []string{"monitor.jsonl", "monitor.jsonl.1", "system-2026-08-30.jsonl", "procs-2026-08-30.jsonl"} {
		if _, err := os.Stat(filepath.Join(m.Dir, gone)); err == nil {
			t.Fatal("not pruned:", gone)
		}
	}
	if _, err := os.Stat(m.file("system", "2026-09-01")); err != nil {
		t.Fatal("day 7 of 7 pruned:", err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "system-notes.txt")); err != nil {
		t.Fatal("unrelated file removed")
	}
	if got := m.Latest(); got == nil || got.TS != "2026-09-07T10:00:00Z" || got.CPU != 6 || got.Procs != nil {
		t.Fatalf("latest %+v", got)
	}
	tail, err := m.Tail(3)
	if err != nil || len(tail) != 3 || tail[0].TS != "2026-09-06T12:00:00Z" || tail[2].TS != "2026-09-07T10:00:00Z" {
		t.Fatalf("tail %+v %v", tail, err)
	}
	if len(tail[2].Procs) != 3 || tail[2].Procs[0].Name != "pf engine" || tail[2].Procs[0].CPU != 7 || tail[2].Procs[2].RSSKB != 4096 {
		t.Fatalf("procs not joined by ts: %+v", tail[2].Procs)
	}
	sum, err := m.Summarize(time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	if err != nil || sum.Samples != 3 || sum.Since != "2026-09-06T12:00:00Z" || sum.CPU.avg() != 4 || sum.CPU.max != 6 || sum.MemMB.max != 400 {
		t.Fatalf("%+v %v", sum, err)
	}
	if len(sum.Procs) != 2 || sum.Procs[1].Name != "pf engine" || sum.Procs[1].CPU.avg() != 5 || sum.Procs[1].RSS.max != 10 || sum.Procs[0].Samples != 6 {
		t.Fatalf("%+v", sum.Procs)
	}
	var out bytes.Buffer
	PrintSummary(&out, sum)
	if !strings.Contains(out.String(), "cpu avg 4.0% max 6.0%") || !strings.Contains(out.String(), "pf engine") {
		t.Fatalf("%s", out.String())
	}
	if _, err := m.Summarize(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); !os.IsNotExist(err) {
		t.Fatal("empty window must be ErrNotExist:", err)
	}
}
