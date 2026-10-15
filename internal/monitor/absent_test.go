package monitor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// For each /proc file that readFile reads, an error becomes "". That
// parses as zero, and zero is a number that a Pi can really report: 0 load,
// 0 C, 0 conntrack entries, 0 MB free. A row that cannot tell which figures
// were read prints a failed read as a measurement.
func TestUnreadMetricsDoNotPrintAsZero(t *testing.T) {
	root := t.TempDir()
	m := Defaults()
	m.Root = root
	m.Dir = filepath.Join(root, "monitor")
	m.DiskPath = filepath.Join(root, "nowhere")
	m.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	var out bytes.Buffer
	Print(&out, []Sample{m.Sample()})
	got := out.String()
	for _, zero := range []string{"cpu=0.0%", "load=0.00/0.00", "mem_used=0MB(0.0%)", "temp=0.0C", "ct=0", "disk=0MB"} {
		if strings.Contains(got, zero) {
			t.Fatalf("a file that could not be read printed as a measurement (%s):\n%s", zero, got)
		}
	}
}

// A metric that was read still prints as a figure, also a real zero. The
// purpose of the signal is that absent and zero do not look the same. It
// is not that zero disappears.
func TestAReadZeroStillPrintsAsAFigure(t *testing.T) {
	var out bytes.Buffer
	Print(&out, []Sample{{TS: "2026-09-07T10:00:00Z"}})
	if got := out.String(); !strings.Contains(got, "temp=0.0C") || !strings.Contains(got, "ct=0") {
		t.Fatalf("a measured zero was hidden:\n%s", got)
	}
}

// Summarize must get its "leave this sample out" answer from the row. It
// must not guess that a small number is not a reading.
func TestSummarizeUsesTheRowsOwnSignal(t *testing.T) {
	root := t.TempDir()
	m := Defaults()
	m.Root = root
	m.Dir = filepath.Join(root, "monitor")
	now := time.Unix(1_700_000_000, 0)
	m.Now = func() time.Time { return now }
	day := now.UTC().Format("2006-01-02")
	if err := os.MkdirAll(m.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	ts := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }
	// Row two is a real 40 C and 20% on a box that the heuristic would
	// have kept. Row three is an unread thermal zone that parses as a
	// possible 0. The old gate would also have kept it for cpu.
	body := `{"ts":"` + ts(0) + `","cpu_pct":10,"temp_c":60,"mem_used_pct":50,"mem_used_mb":500}` + "\n" +
		`{"ts":"` + ts(time.Minute) + `","cpu_pct":30,"temp_c":40,"mem_used_pct":20,"mem_used_mb":200}` + "\n" +
		`{"ts":"` + ts(2*time.Minute) + `","cpu_pct":0,"temp_c":0,"mem_used_pct":0,"mem_used_mb":0,"missing":["cpu","temp","mem"]}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Dir, "system-"+day+".jsonl"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	procs := `{"ts":"` + ts(0) + `","name":"pf","cpu_pct":8,"rss_kb":2048}` + "\n" +
		`{"ts":"` + ts(time.Minute) + `","name":"pf","cpu_pct":0,"rss_kb":0,"missing":["cpu","rss"]}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Dir, "procs-"+day+".jsonl"), []byte(procs), 0644); err != nil {
		t.Fatal(err)
	}
	sum, err := m.Summarize(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := sum.CPU.avg(); got != 20 {
		t.Fatalf("cpu avg = %.1f, want 20 with the unread sample left out", got)
	}
	if got := sum.Temp.avg(); got != 50 {
		t.Fatalf("temp avg = %.1f, want 50 with the unread sample left out", got)
	}
	if got := sum.MemPct.avg(); got != 35 {
		t.Fatalf("mem avg = %.1f, want 35 with the unread sample left out", got)
	}
	if len(sum.Procs) != 1 || sum.Procs[0].CPU.avg() != 8 || sum.Procs[0].RSS.avg() != 2 {
		t.Fatalf("per-process averages counted an unread row: %+v", sum.Procs)
	}
}

// Before, one failed read of /proc/stat became the baseline for the next
// read. {0,0} in prevCPU makes the next sample divide the full busy count
// since boot by the full total since boot. It then prints the average
// since power-on as the figure for this interval.
func TestAFailedCPUReadDoesNotPoisonTheNextSample(t *testing.T) {
	root := t.TempDir()
	m := Defaults()
	m.Root = root
	m.Dir = filepath.Join(root, "monitor")
	m.DiskPath = ""
	m.Names = nil
	now := time.Unix(1_700_000_000, 0)
	m.Now = func() time.Time { return now }
	stat := filepath.Join(root, "proc", "stat")
	if err := os.MkdirAll(filepath.Dir(stat), 0755); err != nil {
		t.Fatal(err)
	}
	write := func(busy, idle uint64) {
		t.Helper()
		line := fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\ncpu0 %d 0 0 %d 0 0 0 0\n", busy, idle, busy, idle)
		if err := os.WriteFile(stat, []byte(line), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Since boot: 900 busy of 1000.
	write(900, 100)
	m.Sample()
	// The read fails. No data about this interval is known.
	if err := os.Remove(stat); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	m.Sample()
	// 10 busy jiffies of the 100 after the last good read.
	write(910, 190)
	now = now.Add(time.Minute)
	if got := m.Sample().CPU; got != 10 {
		t.Fatalf("cpu = %.1f%%, want 10; a failed read poisoned the baseline", got)
	}
}
