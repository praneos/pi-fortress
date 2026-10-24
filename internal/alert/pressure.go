package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Pressure watches memory and CPU pressure on the Pi. It posts before a
// box with no swap stops on an exhausted RAM, and it names the units that
// hold the memory and the CPU. It runs in its own goroutine beside the log
// tails. A post goes out from the sender, so a slow webhook never delays a
// read here.
//
// With PSI (/proc/pressure), the kernel wakes the loop through a trigger.
// Without triggers, the loop reads the files each 2 s. Without PSI, it
// uses MemAvailable, the load and /proc/stat.
type Pressure struct {
	// Root is the file system root of /proc and /sys. Tests use a fake tree.
	Root string
	// MemFullPct is the share of time in which all tasks wait on memory.
	MemFullPct float64
	// MemAvailPct is the floor of MemAvailable, as a share of MemTotal.
	MemAvailPct float64
	// MemFor is how long a memory condition must hold.
	MemFor time.Duration
	// CPUPct is the share of time in which some task waits on a CPU
	// (PSI cpu some), or without PSI, the busy share of the CPUs.
	CPUPct float64
	// CPUFor is how long the CPU condition must hold.
	CPUFor time.Duration
	// LoadPerCPU is the load for each CPU above which a busy CPU counts,
	// without PSI.
	LoadPerCPU float64
	// Repeat is the minimum time between two posts while pressure stays.
	Repeat time.Duration
	// Calm is how long all conditions must be off before "recovered".
	Calm time.Duration
	// StatePath keeps the last sample and a clean-stop mark across a hard
	// stop of the Pi. Empty is no state file.
	StatePath string
	Stdout    io.Writer
	Stderr    io.Writer
	Now       func() time.Time
	// newWaiter is the wait of the loop. Tests give a script.
	newWaiter func(ctx context.Context, r *procReader) waiter
}

// Pressure defaults. The nightly feed fetch and compile use all CPUs for
// some minutes, and some page cache. They do not make all tasks wait on
// memory, and they do not keep tasks in a queue for 30 s.
const (
	DefaultMemFullPct  = 10
	DefaultMemAvailPct = 5
	DefaultCPUPct      = 80
	DefaultLoadPerCPU  = 2
	defaultMemFor      = 4 * time.Second
	defaultCPUFor      = 30 * time.Second
	defaultRepeat      = 10 * time.Minute
	defaultCalm        = time.Minute
	// pollEvery is the read interval while a condition holds, and always
	// without triggers. idleEvery is the interval with triggers and no
	// condition: the trigger wakes the loop before that.
	pollEvery = 2 * time.Second
	idleEvery = 10 * time.Second
	// oomRescan reads the oom_kill of each unit again, so that a unit that
	// started since the last read has its own count.
	oomRescan = 5 * time.Minute
	// sendQueue bounds the posts that wait on the sender.
	sendQueue = 8
	// stateEvery is the interval of the state file.
	stateEvery = 30 * time.Second
	// DefaultStatePath is in the StateDirectory of alert.service.
	DefaultStatePath = "/var/lib/pi-fortress/alert/pressure.json"
)

func DefaultPressure() *Pressure {
	return &Pressure{
		Root:        "/",
		MemFullPct:  DefaultMemFullPct,
		MemAvailPct: DefaultMemAvailPct,
		MemFor:      defaultMemFor,
		CPUPct:      DefaultCPUPct,
		CPUFor:      defaultCPUFor,
		LoadPerCPU:  DefaultLoadPerCPU,
		Repeat:      defaultRepeat,
		Calm:        defaultCalm,
		StatePath:   DefaultStatePath,
	}
}

const (
	resMem = iota
	resCPU
	nRes
)

var resName = [nRes]string{"memory", "CPU"}

// The bits that a wait returns.
const (
	firedMem  = 1 << resMem
	firedCPU  = 1 << resCPU
	firedOOM  = 1 << 2
	firedStop = 1 << 3
)

// waiter blocks until a trigger fires, an oom_kill counter changes, the
// context ends, or the timeout passes.
type waiter interface {
	wait(timeout time.Duration) uint32
	// triggers reports whether PSI triggers wake the wait.
	triggers() bool
	// window is the trigger window of each resource, 0 without a trigger.
	window(res int) time.Duration
	// mode is one line for the journal.
	mode() string
	close()
}

// sleepWaiter has no trigger. It wakes at the timeout or at the end of
// the context.
type sleepWaiter struct {
	ctx  context.Context
	why  string
	tick *time.Timer
}

func (w *sleepWaiter) wait(d time.Duration) uint32 {
	if w.tick == nil {
		w.tick = time.NewTimer(d)
	} else {
		w.tick.Reset(d)
	}
	select {
	case <-w.ctx.Done():
		return firedStop
	case <-w.tick.C:
		return 0
	}
}

func (w *sleepWaiter) triggers() bool           { return false }
func (w *sleepWaiter) window(int) time.Duration { return 0 }
func (w *sleepWaiter) mode() string             { return w.why }
func (w *sleepWaiter) close()                   {}

// psiSpec is one trigger line: "some" or "full", a stall and a window in
// microseconds.
func psiSpec(kind string, pct float64, window time.Duration) string {
	us := window.Microseconds()
	stall := int64(pct / 100 * float64(us))
	stall = min(max(stall, 1), us-1)
	return fmt.Sprintf("%s %d %d", kind, stall, us)
}

type verdict int

const (
	vNone verdict = iota
	vHigh
	vUpdate
	vRecovered
)

// detector is the decision of the loop, with no I/O. A resource is on
// when its condition held for its full time (MemFor, CPUFor). Pressure is
// high from the first resource on, until no condition held for Calm. One
// post at the start, at most one update each Repeat, one post at the end.
type detector struct {
	p      *Pressure
	since  [nRes]time.Time
	fired  [nRes]time.Time
	window [nRes]time.Duration
	high   bool
	// lastOn is the last set of resources that were on.
	lastOn [nRes]bool
	highAt time.Time
	postAt time.Time
	calmAt time.Time
}

// cond is the condition of one resource in this sample. A trigger that
// fired in its last window counts: the PSI averages are slow to rise.
func (d *detector) cond(res int, s *sample, now time.Time) bool {
	recent := d.window[res] > 0 && !d.fired[res].IsZero() && now.Sub(d.fired[res]) <= d.window[res]+pollEvery
	switch res {
	case resMem:
		if s.psi && (s.memFull[0] >= d.p.MemFullPct || recent) {
			return true
		}
		return s.memTotal > 0 && float64(s.memAvail)*100 < d.p.MemAvailPct*float64(s.memTotal)
	case resCPU:
		if s.psi {
			return s.cpuSome[0] >= d.p.CPUPct || recent
		}
		return s.busy >= d.p.CPUPct && s.load[0] >= d.p.LoadPerCPU*float64(max(s.cpus, 1))
	}
	return false
}

func (d *detector) holdFor(res int) time.Duration {
	if res == resCPU {
		return d.p.CPUFor
	}
	return d.p.MemFor
}

// active reports whether a condition holds or pressure is high. The loop
// then reads each 2 s.
func (d *detector) active() bool {
	if d.high {
		return true
	}
	for _, t := range d.since {
		if !t.IsZero() {
			return true
		}
	}
	return false
}

// step takes one sample and the bits of the wait. It returns what to post
// and the resources that are on now.
func (d *detector) step(s *sample, fired uint32, now time.Time) (verdict, [nRes]bool) {
	var on [nRes]bool
	anyCond, anyOn := false, false
	for r := range nRes {
		if fired&(1<<r) != 0 {
			d.fired[r] = now
		}
		if !d.cond(r, s, now) {
			d.since[r] = time.Time{}
			continue
		}
		anyCond = true
		if d.since[r].IsZero() {
			d.since[r] = now
		}
		// A trigger is itself a held condition over its window.
		if now.Sub(d.since[r]) >= d.holdFor(r) || (d.window[r] >= d.holdFor(r) && fired&(1<<r) != 0) {
			on[r] = true
			anyOn = true
		}
	}
	if anyOn {
		d.lastOn = on
	}
	switch {
	case !d.high && anyOn:
		d.high, d.highAt, d.postAt, d.calmAt = true, now, now, time.Time{}
		return vHigh, on
	case !d.high:
		return vNone, on
	case anyCond:
		d.calmAt = time.Time{}
		if now.Sub(d.postAt) >= d.p.Repeat {
			d.postAt = now
			return vUpdate, on
		}
		return vNone, on
	case d.calmAt.IsZero():
		d.calmAt = now
		return vNone, on
	case now.Sub(d.calmAt) >= d.p.Calm:
		d.high = false
		return vRecovered, on
	}
	return vNone, on
}

// oomTracker turns oom_kill counters into posts. The sum of the slices
// shows each kill, also when the cgroup of the unit is already gone. The
// unit counters name it when they can. systemd removes the cgroup of a
// unit when it stops, so a restart starts its counter at 0 again.
type oomTracker struct {
	init   bool
	total  uint64
	units  map[string]uint64
	pend   map[string]uint64
	postAt time.Time
	scanAt time.Time
}

const oomOther = "other processes"

func (o *oomTracker) step(total uint64, scan func() map[string]uint64, now time.Time, repeat time.Duration) string {
	if !o.init {
		o.init, o.total, o.units, o.scanAt = true, total, scan(), now
		return ""
	}
	if total != o.total || now.Sub(o.scanAt) >= oomRescan {
		cur := scan()
		var named uint64
		for u, n := range cur {
			prev, seen := o.units[u]
			inc := n
			if seen && n >= prev {
				inc = n - prev
			}
			if inc > 0 {
				o.add(u, inc)
				named += inc
			}
		}
		if total > o.total && total-o.total > named {
			o.add(oomOther, total-o.total-named)
		}
		o.total, o.units, o.scanAt = total, cur, now
	}
	if len(o.pend) == 0 || (!o.postAt.IsZero() && now.Sub(o.postAt) < repeat) {
		return ""
	}
	parts := make([]string, 0, len(o.pend))
	for _, u := range sortedNames(o.pend) {
		parts = append(parts, fmt.Sprintf("%s %d", u, o.pend[u]))
	}
	o.pend, o.postAt = nil, now
	return "OOM KILL: the kernel stopped a process for lack of memory: " + strings.Join(parts, ", ") + "."
}

func (o *oomTracker) add(u string, n uint64) {
	if o.pend == nil {
		o.pend = map[string]uint64{}
	}
	o.pend[u] += n
}

func mib(kb uint64) string {
	if kb >= 1<<20 {
		return fmt.Sprintf("%.1f GiB", float64(kb)/(1<<20))
	}
	return fmt.Sprintf("%d MiB", kb>>10)
}

// text is one line with the values of a sample.
func (s *sample) text() string {
	var b strings.Builder
	if s.psi {
		fmt.Fprintf(&b, "memory full %.1f%%/%.1f%% some %.1f%%/%.1f%%, CPU some %.1f%%/%.1f%% (avg10/avg60); ",
			s.memFull[0], s.memFull[1], s.memSome[0], s.memSome[1], s.cpuSome[0], s.cpuSome[1])
	} else if s.busy >= 0 {
		fmt.Fprintf(&b, "CPU busy %.0f%%; ", s.busy)
	}
	if s.memTotal > 0 {
		fmt.Fprintf(&b, "MemAvailable %s of %s (%.1f%%); ", mib(s.memAvail), mib(s.memTotal), 100*float64(s.memAvail)/float64(s.memTotal))
	}
	fmt.Fprintf(&b, "load %.2f %.2f %.2f on %d CPUs", s.load[0], s.load[1], s.load[2], s.cpus)
	return b.String()
}

func rankText(rs []ranked, unit func(uint64) string) string {
	if len(rs) == 0 {
		return "none"
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.name + " " + unit(r.v)
	}
	return strings.Join(parts, ", ")
}

func onText(on [nRes]bool) string {
	var names []string
	for r := range nRes {
		if on[r] {
			names = append(names, resName[r])
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, " and ")
}

func (p *Pressure) clock() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pressure) errw() io.Writer {
	if p.Stderr != nil {
		return p.Stderr
	}
	return os.Stderr
}

func (p *Pressure) out() io.Writer {
	if p.Stdout != nil {
		return p.Stdout
	}
	return os.Stdout
}

// tops names the three groups with the most memory, and the three with
// the most CPU in one second. It waits that second, or less when ctx ends.
func (p *Pressure) tops(ctx context.Context, r *procReader) string {
	groups := r.groups()
	before := cpuUsage(groups)
	t := time.NewTimer(time.Second)
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	t.Stop()
	cpu := topCPU(before, cpuUsage(groups))
	mem := r.topMemory()
	return "Top memory: " + rankText(mem, func(v uint64) string { return mib(v >> 10) }) +
		". Top CPU (100% is one CPU): " + rankText(cpu, func(v uint64) string { return fmt.Sprintf("%d%%", v/10000) }) + "."
}

func (p *Pressure) message(v verdict, d *detector, on [nRes]bool, s *sample, now time.Time, tops string) string {
	switch v {
	case vHigh:
		return "PRESSURE HIGH on " + onText(on) + ": " + s.text() + ". " + tops + " The Pi can stop if this continues."
	case vUpdate:
		return "PRESSURE STILL HIGH after " + now.Sub(d.highAt).Round(time.Minute).String() + " on " + onText(on) + ": " + s.text() + ". " + tops
	case vRecovered:
		return "PRESSURE RECOVERED after " + now.Sub(d.highAt).Round(time.Second).String() + ": " + s.text() + "."
	}
	return ""
}

// Run is the loop. post must not block.
func (p *Pressure) Run(ctx context.Context, post func(string)) {
	r := newProcReader(p.Root)
	defer r.close()
	mk := p.newWaiter
	if mk == nil {
		mk = p.waiterFor
	}
	w := mk(ctx, r)
	defer w.close()
	fmt.Fprintln(p.errw(), "pressure: "+w.mode())
	d := &detector{p: p}
	for res := range nRes {
		d.window[res] = w.window(res)
	}
	var (
		oom oomTracker
		s   sample
	)
	r.read(&s)
	oom.step(s.oomKills, r.unitOOMKills, p.clock(), p.Repeat)
	bootID := r.bootID()
	var states *stateWriter
	if p.StatePath != "" {
		if prev, ok := readState(p.StatePath); ok {
			if msg := uncleanRestart(prev, bootID); msg != "" {
				post(msg)
			}
		}
		states = newStateWriter(p.StatePath, p.errw())
		go states.run()
		defer func() {
			st := d.state(bootID, &s, p.clock())
			st.Clean = true
			states.finish(st)
		}()
	}
	var savedAt time.Time
	save := func(now time.Time) {
		if states != nil && (savedAt.IsZero() || now.Sub(savedAt) >= stateEvery) {
			states.put(d.state(bootID, &s, now))
			savedAt = now
		}
	}
	save(p.clock())
	for {
		every := pollEvery
		if w.triggers() && !d.active() {
			every = idleEvery
		}
		fired := w.wait(every)
		if fired&firedStop != 0 || ctx.Err() != nil {
			return
		}
		now := p.clock()
		r.read(&s)
		if v, on := d.step(&s, fired, now); v != vNone {
			tops := ""
			if v != vRecovered {
				tops = p.tops(ctx, r)
			}
			post(p.message(v, d, on, &s, now, tops))
		}
		if msg := oom.step(s.oomKills, r.unitOOMKills, now, p.Repeat); msg != "" {
			post(msg + " " + s.text() + ".")
		}
		save(now)
	}
}

// pressureState is the state file. It outlives a hard stop of the Pi. A
// stop of the unit (SIGTERM, also at each shutdown and reboot) writes
// Clean. A file without Clean from an earlier boot is a boot that did not
// shut down: a power cut, a hang that the hardware watchdog reset, or a
// kernel crash.
type pressureState struct {
	BootID   string    `json:"boot_id"`
	Clean    bool      `json:"clean"`
	At       time.Time `json:"at"`
	High     string    `json:"high,omitempty"`
	Snapshot string    `json:"snapshot"`
}

func (d *detector) state(bootID string, s *sample, now time.Time) pressureState {
	st := pressureState{BootID: bootID, At: now.UTC(), Snapshot: s.text()}
	if d.high {
		st.High = onText(d.lastOn)
	}
	return st
}

// uncleanRestart is the post for a boot that did not shut down, or "".
// The boot ID must differ: a crash of this unit alone is not a restart of
// the Pi.
func uncleanRestart(prev pressureState, bootID string) string {
	if prev.Clean || prev.BootID == "" || bootID == "" || prev.BootID == bootID {
		return ""
	}
	msg := "RESTART: the Pi started again without a clean shutdown (a power cut, a hang that the hardware watchdog reset, or a kernel crash)."
	when := "Last pressure"
	if !prev.At.IsZero() {
		when += " at " + prev.At.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	msg += " " + when + ": " + prev.Snapshot + "."
	if prev.High != "" {
		msg += " Pressure was HIGH on " + prev.High + " then."
	}
	return msg
}

func readState(path string) (pressureState, bool) {
	var st pressureState
	f, err := os.Open(path)
	if err != nil {
		return st, false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8<<10))
	if err != nil || json.Unmarshal(raw, &st) != nil {
		return st, false
	}
	return st, true
}

// writeState replaces the file in one rename. A torn file after a power
// cut is then the old file or the new file, never a part. Only the clean
// mark waits for the disk: the periodic write is small, and the kernel
// commits it within seconds.
func writeState(path string, st pressureState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err == nil && st.Clean {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stateWriter writes the state file in its own goroutine. A disk that is
// slow under pressure then never delays the watch. Only the newest state
// waits: put replaces a state that is not written yet.
type stateWriter struct {
	path   string
	errw   io.Writer
	ch     chan pressureState
	done   chan struct{}
	failed bool
}

func newStateWriter(path string, errw io.Writer) *stateWriter {
	return &stateWriter{path: path, errw: errw, ch: make(chan pressureState, 1), done: make(chan struct{})}
}

func (w *stateWriter) run() {
	defer close(w.done)
	for st := range w.ch {
		if err := writeState(w.path, st); err != nil && !w.failed {
			// One line, not one each 30 s.
			fmt.Fprintf(w.errw, "pressure: state file not written: %v\n", err)
			w.failed = true
		}
	}
}

// put and finish are called from the loop goroutine only.
func (w *stateWriter) put(st pressureState) {
	select {
	case w.ch <- st:
		return
	default:
	}
	select {
	case <-w.ch:
	default:
	}
	select {
	case w.ch <- st:
	default:
	}
}

// finish writes st as the last state and waits for it.
func (w *stateWriter) finish(st pressureState) {
	select {
	case <-w.ch:
	default:
	}
	w.ch <- st
	close(w.ch)
	<-w.done
}

// Check refuses a value that would make the watch fire always or never.
func (p *Pressure) Check() error {
	for _, v := range []struct {
		name string
		pct  float64
	}{{"-pressure-mem-full", p.MemFullPct}, {"-pressure-mem-avail", p.MemAvailPct}, {"-pressure-cpu", p.CPUPct}} {
		if !(v.pct > 0 && v.pct < 100) {
			return fmt.Errorf("%s=%g: use a percent above 0 and below 100", v.name, v.pct)
		}
	}
	if p.MemFor <= 0 || p.CPUFor <= 0 || p.Repeat <= 0 {
		return fmt.Errorf("-pressure-mem-for, -pressure-cpu-for and -pressure-repeat must be above 0")
	}
	if p.LoadPerCPU <= 0 {
		return fmt.Errorf("-pressure-load=%g: use a value above 0", p.LoadPerCPU)
	}
	return nil
}
