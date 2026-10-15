// Package monitor samples the health of the box and of each process on a
// timer. It appends it to daily JSONL files, which it also prunes and
// summarises. pf monitor, internal/admin and the TUI use it.
package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// Under LogsDirectory=pi-fortress/monitor, so the user of the unit owns
	// the directory and can prune.
	DefaultDir = "/var/log/pi-fortress/monitor"
	// One system-<date>.jsonl and one procs-<date>.jsonl for each UTC day.
	// The next append removes older days.
	KeepDays = 7
	// USER_HZ: on Linux, /proc/[pid]/stat CPU times are in these ticks.
	clkTck = 100
)

// Proc is one process row. CPU is percent of one core, as top shows it.
// Thus a busy multi-threaded daemon can be more than 100.
type Proc struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	UID     int     `json:"uid"`
	CPU     float64 `json:"cpu_pct"`
	RSSKB   uint64  `json:"rss_kb"`
	Threads int     `json:"threads"`
	FDs     int     `json:"fds"`
	// Missing names the figures on this row that were not measured. Refer
	// to Sample.Missing. Here "cpu" also applies to the first sample of a
	// process. That sample has no previous tick count to subtract. Thus it
	// has no interval figure yet.
	Missing []string `json:"missing,omitempty"`
	ticks   uint64
	// start is the starttime of the process from /proc/[pid]/stat. A PID is
	// a small recycled integer. Thus the PID alone does not show that two
	// samples saw the same process.
	start uint64
}

// procKey identifies a process across samples: PID plus start time. The
// pair changes when the number comes back. When the code gave a new
// process the total ticks of the previous process, it reported a CPU burst
// that did not occur. The operator watches that screen for exactly that.
type procKey struct {
	pid   int
	start uint64
}

type ProcRow struct {
	TS string `json:"ts"`
	Proc
}

type Wifi struct {
	Quality float64 `json:"quality"`
	LevelDB float64 `json:"level_dbm"`
}

type Net struct {
	RxBytes uint64  `json:"rx_bytes"`
	TxBytes uint64  `json:"tx_bytes"`
	RxKBps  float64 `json:"rx_kbps"`
	TxKBps  float64 `json:"tx_kbps"`
}

// Sample is one snapshot. The box facts go to the system file as one
// line. Procs go to the procs file as one line each.
type Sample struct {
	TS          string          `json:"ts"`
	CPU         float64         `json:"cpu_pct"`
	CPUs        int             `json:"cpus"`
	Load1       float64         `json:"load1"`
	Load5       float64         `json:"load5"`
	MemTotalMB  uint64          `json:"mem_total_mb"`
	MemUsedMB   uint64          `json:"mem_used_mb"`
	MemUsedPct  float64         `json:"mem_used_pct"`
	MemAvailMB  uint64          `json:"mem_avail_mb"`
	SwapUsedMB  uint64          `json:"swap_used_mb"`
	TempC       float64         `json:"temp_c,omitempty"`
	Throttled   []string        `json:"throttled,omitempty"`
	Conntrack   int             `json:"conntrack,omitempty"`
	DiskAvailMB uint64          `json:"disk_avail_mb"`
	Wifi        map[string]Wifi `json:"wifi,omitempty"`
	Net         map[string]Net  `json:"net,omitempty"`
	Procs       []Proc          `json:"-"`
	// Missing names the figures on this row that were not measured. Each
	// source here is a file. A read error of the file becomes "", which
	// parses as zero. Zero is a number that a Pi really reports: 0 C, 0
	// conntrack entries, 0 MB free, an idle load. A judgement by size ("a
	// zero cannot be a reading") kept a real 0 out of the averages. It also
	// let a failed read through where zero looked possible. Thus the row
	// tells the reader which figures were read. The reader does not guess.
	// The field is omitted when all figures were read. A row written before
	// this field existed reads the same way.
	Missing []string `json:"missing,omitempty"`
}

// Has tells if this row measured a metric: "cpu", "load", "mem",
// "temp", "conntrack", "disk" on a Sample, "cpu" and "rss" on a Proc.
func (s Sample) Has(metric string) bool { return !slices.Contains(s.Missing, metric) }

func (s *Sample) absent(metric string) { s.Missing = append(s.Missing, metric) }

func (p Proc) Has(metric string) bool { return !slices.Contains(p.Missing, metric) }

func (p *Proc) absent(metric string) { p.Missing = append(p.Missing, metric) }

type Monitor struct {
	Root     string
	Dir      string
	DiskPath string
	Names    []string
	Interval time.Duration
	Now      func() time.Time

	prevAt    time.Time
	prevCPU   [2]uint64
	prevTicks map[procKey]uint64
	prevNet   map[string][2]uint64
}

func Defaults() *Monitor {
	return &Monitor{
		Root:     "/",
		Dir:      DefaultDir,
		DiskPath: "/var/log",
		Names:    []string{"pf", "dnsmasq", "hostapd", "wpa_supplicant", "NetworkManager"},
		Interval: 5 * time.Minute,
		Now:      time.Now,
	}
}

func (m *Monitor) path(p string) string { return filepath.Join(m.Root, p) }

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// Sample reads one snapshot. Rates and CPU percentages need a previous
// call. The first call reports them as zero.
func (m *Monitor) Sample() Sample {
	now := m.Now()
	s := Sample{TS: now.UTC().Format(time.RFC3339), Wifi: map[string]Wifi{}, Net: map[string]Net{}}
	elapsed := 0.0
	if !m.prevAt.IsZero() {
		elapsed = now.Sub(m.prevAt).Seconds()
	}

	m.sampleCPU(&s, elapsed)
	raw, ok := readFileOK(m.path("proc/loadavg"))
	s.Load1, s.Load5 = parseLoadavg(raw)
	if !ok || len(strings.Fields(raw)) < 2 {
		s.absent("load")
	}
	raw, ok = readFileOK(m.path("proc/meminfo"))
	totalKB, availKB, swapKB := parseMeminfo(raw)
	s.MemTotalMB, s.MemAvailMB, s.SwapUsedMB = totalKB>>10, availKB>>10, swapKB>>10
	if totalKB >= availKB && totalKB > 0 {
		s.MemUsedMB = (totalKB - availKB) >> 10
		s.MemUsedPct = round1(float64(totalKB-availKB) / float64(totalKB) * 100)
	}
	if !ok || totalKB == 0 {
		s.absent("mem")
	}
	raw, ok = readFileOK(m.path("sys/class/thermal/thermal_zone0/temp"))
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); ok && err == nil {
		s.TempC = round1(float64(v) / 1000)
	} else {
		s.absent("temp")
	}
	s.Throttled = decodeThrottled(strings.TrimSpace(readFile(m.path("sys/devices/platform/soc/soc:firmware/get_throttled"))))
	raw, ok = readFileOK(m.path("proc/sys/net/netfilter/nf_conntrack_count"))
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); ok && err == nil {
		s.Conntrack = v
	} else {
		s.absent("conntrack")
	}
	disk := false
	if m.DiskPath != "" {
		var st syscall.Statfs_t
		if err := syscall.Statfs(m.DiskPath, &st); err == nil {
			s.DiskAvailMB = uint64(st.Bavail) * uint64(st.Bsize) >> 20
			disk = true
		}
	}
	if !disk {
		s.absent("disk")
	}
	s.Wifi = parseWireless(readFile(m.path("proc/net/wireless")))

	m.sampleNet(&s, elapsed)
	m.sampleProcs(&s, elapsed)
	m.prevAt = now
	return s
}

func (m *Monitor) sampleCPU(s *Sample, elapsed float64) {
	raw, ok := readFileOK(m.path("proc/stat"))
	cpu, cpus := parseStat(raw)
	s.CPUs = cpus
	if elapsed > 0 && cpu[1] > m.prevCPU[1] {
		s.CPU = round1(float64(cpu[0]-m.prevCPU[0]) / float64(cpu[1]-m.prevCPU[1]) * 100)
	} else {
		s.absent("cpu")
	}
	// A failed read parses as {0,0}. When the code kept that as the
	// baseline, the next sample subtracted nothing. Thus it divided the full
	// busy count since boot by the full total since boot. It printed the
	// average since power-on as the figure for this interval. One bad read
	// made the next good read wrong. Now the last counter that was really
	// read stays. Busy over total is a ratio. Thus, over the longer window,
	// it is still a true interval average, not an average since boot.
	if ok && cpu[1] > 0 {
		m.prevCPU = cpu
	}
}

func (m *Monitor) sampleNet(s *Sample, elapsed float64) {
	next := map[string][2]uint64{}
	for iface, rxtx := range parseNetDev(readFile(m.path("proc/net/dev"))) {
		n := Net{RxBytes: rxtx[0], TxBytes: rxtx[1]}
		if prev, ok := m.prevNet[iface]; ok && elapsed > 0 && rxtx[0] >= prev[0] && rxtx[1] >= prev[1] {
			n.RxKBps = round1(float64(rxtx[0]-prev[0]) / 1024 / elapsed)
			n.TxKBps = round1(float64(rxtx[1]-prev[1]) / 1024 / elapsed)
		}
		s.Net[iface] = n
		next[iface] = rxtx
	}
	m.prevNet = next
}

func (m *Monitor) sampleProcs(s *Sample, elapsed float64) {
	ticks := map[procKey]uint64{}
	for _, p := range m.procs() {
		key := procKey{p.PID, p.start}
		if prev, ok := m.prevTicks[key]; ok && elapsed > 0 && p.ticks >= prev {
			p.CPU = round1(float64(p.ticks-prev) / clkTck / elapsed * 100)
		} else {
			p.absent("cpu")
		}
		ticks[key] = p.ticks
		s.Procs = append(s.Procs, p)
	}
	sort.Slice(s.Procs, func(i, j int) bool {
		return s.Procs[i].Name < s.Procs[j].Name || (s.Procs[i].Name == s.Procs[j].Name && s.Procs[i].PID < s.Procs[j].PID)
	})
	m.prevTicks = ticks
}

func (m *Monitor) procs() []Proc {
	entries, err := os.ReadDir(m.path("proc"))
	if err != nil {
		return nil
	}
	var out []Proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := m.path(filepath.Join("proc", e.Name()))
		comm := strings.TrimSpace(readFile(filepath.Join(dir, "comm")))
		if !m.wanted(comm) {
			continue
		}
		p := Proc{PID: pid, Name: comm, FDs: -1}
		if comm == "pf" {
			if sub := cmdlineArg(readFile(filepath.Join(dir, "cmdline")), 1); sub != "" {
				p.Name = "pf " + sub
			}
		}
		p.ticks, p.start = parseStatLine(readFile(filepath.Join(dir, "stat")))
		status, ok := readFileOK(filepath.Join(dir, "status"))
		p.RSSKB, p.Threads, p.UID = parseStatus(status)
		if !ok {
			p.absent("rss")
		}
		if fds, err := os.ReadDir(filepath.Join(dir, "fd")); err == nil {
			p.FDs = len(fds)
		}
		out = append(out, p)
	}
	return out
}

func (m *Monitor) wanted(comm string) bool {
	for _, n := range m.Names {
		if comm == n {
			return true
		}
	}
	return false
}

// Run samples on Interval and appends to the files of the day.
func (m *Monitor) Run(ctx context.Context) error {
	if m.Interval <= 0 {
		m.Interval = 5 * time.Minute
	}
	m.Sample()
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := m.Append(m.Sample()); err != nil {
				return err
			}
		}
	}
}

func dayOf(ts string) string {
	if len(ts) < 10 {
		return ts
	}
	return ts[:10]
}

func (m *Monitor) file(kind, day string) string {
	return filepath.Join(m.Dir, kind+"-"+day+".jsonl")
}

// Append writes the sample as one system line and one line per process,
// then prunes days older than KeepDays.
func (m *Monitor) Append(s Sample) error {
	if m.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.Dir, 0755); err != nil {
		return err
	}
	day := dayOf(s.TS)
	sys, err := json.Marshal(s)
	if err != nil {
		return err
	}
	var procs []byte
	for _, p := range s.Procs {
		raw, err := json.Marshal(ProcRow{TS: s.TS, Proc: p})
		if err != nil {
			return err
		}
		procs = append(procs, raw...)
		procs = append(procs, '\n')
	}
	if err := appendFile(m.file("system", day), append(sys, '\n')); err != nil {
		return err
	}
	if err := appendFile(m.file("procs", day), procs); err != nil {
		return err
	}
	m.prune(day)
	return nil
}

func appendFile(path string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	_, werr := f.Write(raw)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// prune removes day files older than KeepDays before today. It also
// removes the single-file layout that this package wrote before daily files.
func (m *Monitor) prune(today string) {
	cut, err := time.Parse("2006-01-02", today)
	if err != nil {
		return
	}
	cut = cut.AddDate(0, 0, -(KeepDays - 1))
	for _, kind := range []string{"system", "procs"} {
		for _, day := range m.days(kind) {
			if d, err := time.Parse("2006-01-02", day); err == nil && d.Before(cut) {
				_ = os.Remove(m.file(kind, day))
			}
		}
	}
	_ = os.Remove(filepath.Join(m.Dir, "monitor.jsonl"))
	_ = os.Remove(filepath.Join(m.Dir, "monitor.jsonl.1"))
}

// days lists the day files of one kind, oldest first.
func (m *Monitor) days(kind string) []string {
	matches, _ := filepath.Glob(filepath.Join(m.Dir, kind+"-*.jsonl"))
	var out []string
	for _, p := range matches {
		name := strings.TrimSuffix(filepath.Base(p), ".jsonl")
		day := strings.TrimPrefix(name, kind+"-")
		if _, err := time.Parse("2006-01-02", day); err == nil {
			out = append(out, day)
		}
	}
	sort.Strings(out)
	return out
}

func readJSONL[T any](path string, keep func(T) bool) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil && (keep == nil || keep(v)) {
			out = append(out, v)
		}
	}
	return out, sc.Err()
}

// Latest returns the newest sample without its processes, or nil.
func (m *Monitor) Latest() *Sample {
	days := m.days("system")
	if len(days) == 0 {
		return nil
	}
	rows, _ := readJSONL[Sample](m.file("system", days[len(days)-1]), nil)
	if len(rows) == 0 {
		return nil
	}
	return &rows[len(rows)-1]
}

// Tail returns the last n samples with their processes attached.
func (m *Monitor) Tail(n int) ([]Sample, error) {
	days := m.days("system")
	if len(days) == 0 {
		return nil, os.ErrNotExist
	}
	var out []Sample
	var used []string
	for i := len(days) - 1; i >= 0 && len(out) < n; i-- {
		rows, err := readJSONL[Sample](m.file("system", days[i]), nil)
		if err != nil {
			return nil, err
		}
		used = append(used, days[i])
		if len(rows) > n-len(out) {
			rows = rows[len(rows)-(n-len(out)):]
		}
		out = append(rows, out...)
	}
	byTS := map[string][]Proc{}
	for _, day := range used {
		rows, _ := readJSONL[ProcRow](m.file("procs", day), nil)
		for _, r := range rows {
			byTS[r.TS] = append(byTS[r.TS], r.Proc)
		}
	}
	for i := range out {
		out[i].Procs = byTS[out[i].TS]
	}
	return out, nil
}

type stat struct {
	n        int
	sum, max float64
}

func (s *stat) add(v float64) {
	s.n++
	s.sum += v
	if v > s.max {
		s.max = v
	}
}

func (s stat) avg() float64 {
	if s.n == 0 {
		return 0
	}
	return s.sum / float64(s.n)
}

type ProcSummary struct {
	Name     string
	Samples  int
	CPU, RSS stat
}

type Summary struct {
	Since, Until       string
	Samples            int
	CPU, MemPct, MemMB stat
	Temp               stat
	Procs              []ProcSummary
}

// Summarize averages the samples at or after since, for each box and
// each process name. For two processes with the same name (the two
// dnsmasq instances), it averages each row. It does not add them.
func (m *Monitor) Summarize(since time.Time) (Summary, error) {
	from := since.UTC().Format(time.RFC3339)
	keepDay := func(day string) bool { return day >= dayOf(from) }
	var sum Summary
	for _, day := range m.days("system") {
		if !keepDay(day) {
			continue
		}
		rows, err := readJSONL[Sample](m.file("system", day), func(s Sample) bool { return s.TS >= from })
		if err != nil {
			return sum, err
		}
		for _, s := range rows {
			if sum.Since == "" {
				sum.Since = s.TS
			}
			sum.Until = s.TS
			sum.Samples++
			// A metric with a file that could not be read comes back as the
			// zero value. That number looks possible, but it is not a
			// measurement. A missing thermal zone reported 0 C. In the
			// average, it moved the figure toward freezing and hid the
			// throttling that this summary must show. The row tells which of
			// its figures were read. Thus a sample stays out of an average
			// because it has no reading. It is not because the reading
			// looked too small.
			if s.Has("cpu") {
				sum.CPU.add(s.CPU)
			}
			if s.Has("mem") {
				sum.MemPct.add(s.MemUsedPct)
				sum.MemMB.add(float64(s.MemUsedMB))
			}
			if s.Has("temp") {
				sum.Temp.add(s.TempC)
			}
		}
	}
	byName := map[string]*ProcSummary{}
	for _, day := range m.days("procs") {
		if !keepDay(day) {
			continue
		}
		rows, err := readJSONL[ProcRow](m.file("procs", day), func(r ProcRow) bool { return r.TS >= from })
		if err != nil {
			return sum, err
		}
		for _, r := range rows {
			ps := byName[r.Name]
			if ps == nil {
				ps = &ProcSummary{Name: r.Name}
				byName[r.Name] = ps
			}
			ps.Samples++
			if r.Has("cpu") {
				ps.CPU.add(r.CPU)
			}
			if r.Has("rss") {
				ps.RSS.add(float64(r.RSSKB) / 1024)
			}
		}
	}
	for _, ps := range byName {
		sum.Procs = append(sum.Procs, *ps)
	}
	sort.Slice(sum.Procs, func(i, j int) bool { return sum.Procs[i].Name < sum.Procs[j].Name })
	if sum.Samples == 0 {
		return sum, os.ErrNotExist
	}
	return sum, nil
}

func PrintSummary(w io.Writer, s Summary) {
	fmt.Fprintf(w, "%s .. %s  samples=%d\n", s.Since, s.Until, s.Samples)
	fmt.Fprintf(w, "system  cpu avg %.1f%% max %.1f%%  mem used avg %.0fMB (%.1f%%) max %.0fMB  temp avg %.1fC max %.1fC\n",
		s.CPU.avg(), s.CPU.max, s.MemMB.avg(), s.MemPct.avg(), s.MemMB.max, s.Temp.avg(), s.Temp.max)
	for _, p := range s.Procs {
		fmt.Fprintf(w, "  %-20s cpu avg %5.1f%% max %5.1f%%  rss avg %6.1fMB max %6.1fMB  rows=%d\n",
			p.Name, p.CPU.avg(), p.CPU.max, p.RSS.avg(), p.RSS.max, p.Samples)
	}
}

// Print renders samples as rows: one line of box facts, one line for
// each process. Rates are blank on a first sample.
func Print(w io.Writer, samples []Sample) {
	for _, s := range samples {
		wifi := ""
		for iface, wf := range s.Wifi {
			wifi += fmt.Sprintf(" %s=%.0fdBm", iface, wf.LevelDB)
		}
		net := ""
		for _, iface := range sortedKeys(s.Net) {
			n := s.Net[iface]
			net += fmt.Sprintf(" %s=%.0f/%.0fKB/s", iface, n.RxKBps, n.TxKBps)
		}
		thr := ""
		if len(s.Throttled) > 0 {
			thr = " throttled=" + strings.Join(s.Throttled, ",")
		}
		fmt.Fprintf(w, "%s cpu=%s load=%s mem_used=%s swap=%s temp=%s ct=%s disk=%s%s%s%s\n", s.TS,
			figure(s.Has("cpu"), "%.1f%%", s.CPU),
			figure(s.Has("load"), "%.2f/%.2f", s.Load1, s.Load5),
			figure(s.Has("mem"), "%dMB(%.1f%%)", s.MemUsedMB, s.MemUsedPct),
			figure(s.Has("mem"), "%dMB", s.SwapUsedMB),
			figure(s.Has("temp"), "%.1fC", s.TempC),
			figure(s.Has("conntrack"), "%d", s.Conntrack),
			figure(s.Has("disk"), "%dMB", s.DiskAvailMB),
			wifi, net, thr)
		for _, p := range s.Procs {
			fds := "?"
			if p.FDs >= 0 {
				fds = strconv.Itoa(p.FDs)
			}
			fmt.Fprintf(w, "  %-20s pid=%-6d uid=%-5d cpu=%-6s rss=%-9s thr=%-3d fds=%s\n", p.Name, p.PID, p.UID,
				figure(p.Has("cpu"), "%.1f%%", p.CPU), figure(p.Has("rss"), "%dKB", p.RSSKB), p.Threads, fds)
		}
	}
}

func sortedKeys(m map[string]Net) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func readFile(path string) string {
	s, _ := readFileOK(path)
	return s
}

// readFileOK is readFile plus the one bit that readFile discards: if there
// was data to parse. Without it, each caller below changes a missing or
// unreadable file into the same zero that a healthy box can report.
func readFileOK(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// figure prints a measurement, or n/a when the row does not have it.
// n/a is longer than most of the numbers that it replaces. Thus the two
// callers pad. They do not align on a fixed width.
func figure(ok bool, format string, args ...any) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf(format, args...)
}

// parseStat returns {busy, total} jiffies from the aggregate cpu line of
// /proc/stat and the number of cpuN lines. iowait counts as idle.
//
// The sum includes only user through steal. Linux reports guest time in
// user and guest_nice in nice, and also in their own columns. Thus a sum
// of all fields counted virtualised time two times. The Status screen of
// the seat and the daily summary both print this figure.
const statFields = 8

func parseStat(s string) ([2]uint64, int) {
	var out [2]uint64
	cpus := 0
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			cpus++
			continue
		}
		var total, idle uint64
		cols := f[1:]
		if len(cols) > statFields {
			cols = cols[:statFields]
		}
		for i, v := range cols {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 {
				idle += n
			}
		}
		out = [2]uint64{total - idle, total}
	}
	return out, cpus
}

func parseLoadavg(s string) (float64, float64) {
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0, 0
	}
	l1, _ := strconv.ParseFloat(f[0], 64)
	l5, _ := strconv.ParseFloat(f[1], 64)
	return l1, l5
}

func parseMeminfo(s string) (total, avail, swapUsed uint64) {
	var swapTotal, swapFree uint64
	for line := range strings.SplitSeq(s, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(f[0], 10, 64)
		switch key {
		case "MemTotal":
			total = v
		case "MemAvailable":
			avail = v
		case "SwapTotal":
			swapTotal = v
		case "SwapFree":
			swapFree = v
		}
	}
	if swapTotal >= swapFree {
		swapUsed = swapTotal - swapFree
	}
	return
}

// parseStatTicks returns utime+stime from /proc/[pid]/stat. The comm
// field can contain spaces and parentheses. Thus split after the last ')'.
func parseStatTicks(s string) uint64 {
	t, _ := parseStatLine(s)
	return t
}

// parseStatLine also returns starttime. starttime tells one process apart
// from the next process that gets the same PID.
func parseStatLine(s string) (ticks, start uint64) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0
	}
	f := strings.Fields(s[i+1:])
	// f[0] is state (field 3); utime is field 14, stime field 15,
	// starttime field 22.
	if len(f) < 13 {
		return 0, 0
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	if len(f) > 19 {
		start, _ = strconv.ParseUint(f[19], 10, 64)
	}
	return u + st, start
}

func parseStatus(s string) (rssKB uint64, threads, uid int) {
	for line := range strings.SplitSeq(s, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		switch key {
		case "VmRSS":
			rssKB, _ = strconv.ParseUint(f[0], 10, 64)
		case "Threads":
			threads, _ = strconv.Atoi(f[0])
		case "Uid":
			uid, _ = strconv.Atoi(f[0])
		}
	}
	return
}

func cmdlineArg(raw string, i int) string {
	parts := strings.Split(strings.TrimRight(raw, "\x00"), "\x00")
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// parseWireless reads /proc/net/wireless: iface, status, link quality,
// signal level (dBm), noise. Values have a trailing '.'.
func parseWireless(s string) map[string]Wifi {
	out := map[string]Wifi{}
	for i, line := range strings.Split(s, "\n") {
		if i < 2 {
			continue
		}
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 3 {
			continue
		}
		q, _ := strconv.ParseFloat(strings.TrimSuffix(f[1], "."), 64)
		l, _ := strconv.ParseFloat(strings.TrimSuffix(f[2], "."), 64)
		out[strings.TrimSpace(iface)] = Wifi{Quality: q, LevelDB: l}
	}
	return out
}

// parseNetDev reads /proc/net/dev into iface -> {rx bytes, tx bytes}.
func parseNetDev(s string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for i, line := range strings.Split(s, "\n") {
		if i < 2 {
			continue
		}
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface = strings.TrimSpace(iface)
		if iface == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		out[iface] = [2]uint64{rx, tx}
	}
	return out
}

// decodeThrottled changes the Pi firmware get_throttled bitmask into names.
func decodeThrottled(hex string) []string {
	hex = strings.TrimPrefix(strings.TrimPrefix(hex, "throttled="), "0x")
	if hex == "" {
		return nil
	}
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil || v == 0 {
		return nil
	}
	names := map[uint]string{
		0: "undervolt", 1: "freq_capped", 2: "throttled", 3: "soft_temp_limit",
		16: "undervolt_past", 17: "freq_capped_past", 18: "throttled_past", 19: "soft_temp_limit_past",
	}
	var out []string
	for bit := uint(0); bit < 32; bit++ {
		if v&(1<<bit) != 0 {
			if n, ok := names[bit]; ok {
				out = append(out, n)
			} else {
				out = append(out, "bit"+strconv.Itoa(int(bit)))
			}
		}
	}
	return out
}
