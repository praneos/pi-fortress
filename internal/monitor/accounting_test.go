package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Linux already counts guest in user and guest_nice in nice. Thus a sum
// of all fields on the cpu line counts virtualised time two times. Then
// the busy percentage that the operator reads is wrong on each box that
// runs a VM. All development boxes for this code run a VM.
func TestParseStatDoesNotDoubleCountGuest(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	line := "cpu  100 10 20 1000 50 1 2 3 40 5\ncpu0 100 10 20 1000 50 1 2 3 40 5\n"
	got, cpus := parseStat(line)
	if cpus != 1 {
		t.Fatalf("cpus = %d", cpus)
	}
	const wantTotal = 100 + 10 + 20 + 1000 + 50 + 1 + 2 + 3
	const wantBusy = wantTotal - (1000 + 50)
	if got != [2]uint64{wantBusy, wantTotal} {
		t.Fatalf("parseStat = %v, want {%d %d}", got, wantBusy, wantTotal)
	}
}

// writeProc makes the part of /proc that procs() reads.
func writeProc(t *testing.T, root string, pid int, comm string, start, ticks uint64) {
	t.Helper()
	dir := filepath.Join(root, "proc", fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Fields 3..22: state through starttime, with utime/stime at 14/15.
	f := make([]string, 20)
	for i := range f {
		f[i] = "0"
	}
	f[0] = "S"
	f[11] = fmt.Sprint(ticks)
	f[12] = "0"
	f[19] = fmt.Sprint(start)
	body := fmt.Sprintf("%d (%s) %s", pid, comm, join(f))
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(body+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\t"+comm+"\nUid:\t0\t0\t0\t0\nVmRSS:\t 100 kB\nThreads:\t1\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func join(f []string) string {
	out := ""
	for i, v := range f {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

// A PID is a small recycled integer. If the code gives a new process the
// tick count of the process that had its number before, it reports a CPU
// burst that did not occur. The operator watches this screen for exactly
// that.
func TestSampleDoesNotChargeARecycledPID(t *testing.T) {
	root := t.TempDir()
	m := Defaults()
	m.Root = root
	m.Dir = filepath.Join(root, "monitor")
	m.DiskPath = ""
	m.Names = []string{"pfthing"}
	now := time.Unix(1_700_000_000, 0)
	m.Now = func() time.Time { return now }
	writeProc(t, root, 42, "pfthing", 1000, 100)
	m.Sample()
	// The number comes back: a different process, started later, with
	// its own tick count.
	if err := os.RemoveAll(filepath.Join(root, "proc", "42")); err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, 42, "pfthing", 900000, 30000)
	now = now.Add(time.Minute)
	s := m.Sample()
	if len(s.Procs) != 1 {
		t.Fatalf("sampled %+v", s.Procs)
	}
	if s.Procs[0].CPU != 0 {
		t.Fatalf("charged the new process %.1f%%, want 0", s.Procs[0].CPU)
	}
}

// An unreadable thermal zone reads back as 0 C. That is not a temperature.
// If the average includes it, the reported figure moves toward freezing.
// That hides the throttling that the summary must show. Now the row that
// could not read it tells this. This test asserts the other half: a zero
// that the box did measure is a reading and counts as one. The old "a zero
// cannot be real" gate silently discarded it.
func TestSummarizeSkipsUnreadMetrics(t *testing.T) {
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
	body := "{\"ts\":\"" + now.UTC().Format(time.RFC3339) + "\",\"temp_c\":60,\"mem_used_pct\":50}\n" +
		"{\"ts\":\"" + now.Add(time.Minute).UTC().Format(time.RFC3339) + "\",\"temp_c\":0,\"mem_used_pct\":0,\"missing\":[\"temp\",\"mem\"]}\n" +
		"{\"ts\":\"" + now.Add(2*time.Minute).UTC().Format(time.RFC3339) + "\",\"temp_c\":0,\"mem_used_pct\":30}\n"
	if err := os.WriteFile(filepath.Join(m.Dir, "system-"+day+".jsonl"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	sum, err := m.Summarize(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := sum.Temp.avg(); got != 30 {
		t.Fatalf("temp avg = %.1f, want 30: the unread sample out, the measured 0 C in", got)
	}
	if got := sum.MemPct.avg(); got != 40 {
		t.Fatalf("mem avg = %.1f, want 40 with the unread sample left out", got)
	}
}
