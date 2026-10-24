package alert

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testMeminfo = "MemTotal:        8000000 kB\nMemFree:          100000 kB\nMemAvailable:    4000000 kB\nBuffers: 1 kB\n"
	testPSIMem  = "some avg10=1.50 avg60=0.75 avg300=0.10 total=12345\nfull avg10=0.25 avg60=0.10 avg300=0.00 total=99\n"
	testPSICPU  = "some avg10=12.00 avg60=8.00 avg300=1.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
	testStat    = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 25 0 25 175 25 0 0 0 0 0\ncpu1 1 0 1 1 1 0 0 0 0 0\ncpu2 1 0 1 1 1 0 0 0 0 0\ncpu3 1 0 1 1 1 0 0 0 0 0\nintr 1 2 3\n"
)

const stubSlice = `system-pi\x2dfortress\x2ddns\x2dstub.slice`

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeRoot is a /proc and /sys tree: two pi-fortress units (one a
// template instance), a user session, and PSI unless psi is false.
func fakeRoot(t *testing.T, psi bool) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "proc/meminfo", testMeminfo)
	put(t, root, "proc/loadavg", "0.50 0.40 0.30 1/200 999\n")
	put(t, root, "proc/stat", testStat)
	put(t, root, "proc/sys/kernel/random/boot_id", "boot-a\n")
	if psi {
		put(t, root, "proc/pressure/memory", testPSIMem)
		put(t, root, "proc/pressure/cpu", testPSICPU)
	}
	cg := "sys/fs/cgroup/"
	put(t, root, cg+"system.slice/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	put(t, root, cg+"user.slice/memory.events", "oom_kill 0\n")
	for _, u := range []struct{ dir, mem, cpu string }{
		{"system.slice/pi-fortress-broker.service", "300000000", "usage_usec 1000\nuser_usec 1\n"},
		{"system.slice/" + stubSlice + "/pi-fortress-dns-stub@house.service", "20000000", "usage_usec 50\n"},
		{"system.slice/ssh.service", "5000000", "usage_usec 10\n"},
		{"user.slice/user-1000.slice", "100000000", "usage_usec 9000\n"},
	} {
		put(t, root, cg+u.dir+"/memory.current", u.mem+"\n")
		put(t, root, cg+u.dir+"/cpu.stat", u.cpu)
		put(t, root, cg+u.dir+"/memory.events", "oom 0\noom_kill 0\n")
	}
	return root
}

func TestPressureParsers(t *testing.T) {
	if got := psiAvg([]byte(testPSIMem), "full"); got != [2]float64{0.25, 0.10} {
		t.Fatalf("psi full = %v", got)
	}
	if got := psiAvg([]byte(testPSIMem), "some"); got != [2]float64{1.5, 0.75} {
		t.Fatalf("psi some = %v", got)
	}
	if got := meminfoKB([]byte(testMeminfo), "MemAvailable:"); got != 4000000 {
		t.Fatalf("MemAvailable = %d", got)
	}
	if busy, total := statCPU([]byte(testStat)); busy != 200 || total != 1000 {
		t.Fatalf("stat = %d/%d", busy, total)
	}
	if got := eventCount([]byte("oom 3\noom_kill 2\noom_group_kill 9\n"), "oom_kill"); got != 2 {
		t.Fatalf("oom_kill = %d", got)
	}
}

func TestPressureReaderFakeRoot(t *testing.T) {
	root := fakeRoot(t, true)
	r := newProcReader(root)
	defer r.close()
	var s sample
	r.read(&s)
	if !s.psi || s.cpus != 4 || s.memTotal != 8000000 || s.memAvail != 4000000 || s.load[0] != 0.5 || s.cpuSome[0] != 12 || s.busy != -1 {
		t.Fatalf("first read: %+v", s)
	}
	// A second read sees the new content of the same files, and the busy
	// share between the two reads.
	put(t, root, "proc/stat", "cpu  190 0 110 780 120 0 0 0 0 0\n")
	put(t, root, "proc/meminfo", "MemTotal: 8000000 kB\nMemAvailable: 100000 kB\n")
	put(t, root, "sys/fs/cgroup/system.slice/memory.events", "oom_kill 2\n")
	r.read(&s)
	if s.memAvail != 100000 || s.busy != 50 || s.oomKills != 2 {
		t.Fatalf("second read: avail %d busy %v oom %d", s.memAvail, s.busy, s.oomKills)
	}
	if allocs := testing.AllocsPerRun(20, func() { r.read(&s) }); allocs != 0 {
		t.Fatalf("a read allocates %v times; the 2 s loop must not", allocs)
	}
	units := r.unitOOMKills()
	if _, ok := units["pi-fortress-dns-stub@house.service"]; !ok || len(units) != 2 {
		t.Fatalf("units = %v; want the broker and the stub instance, not ssh", units)
	}
	mem := r.topMemory()
	if len(mem) != 3 || mem[0].name != "pi-fortress-broker.service" || mem[1].name != "user-1000.slice" {
		t.Fatalf("top memory = %v", mem)
	}
	if bootID := r.bootID(); bootID != "boot-a" {
		t.Fatalf("boot id = %q", bootID)
	}
}

func TestPressureReaderNoPSI(t *testing.T) {
	r := newProcReader(fakeRoot(t, false))
	defer r.close()
	var s sample
	r.read(&s)
	if s.psi || s.memTotal == 0 {
		t.Fatalf("no PSI: %+v", s)
	}
}

func testPressure() *Pressure {
	p := DefaultPressure()
	p.StatePath = ""
	return p
}

// at is a time n seconds after a fixed start.
func at(n float64) time.Time {
	return time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC).Add(time.Duration(n * float64(time.Second)))
}

func calmPSI() sample {
	return sample{psi: true, memTotal: 8 << 20, memAvail: 4 << 20, cpus: 4, busy: -1}
}

func TestDetectorMemoryNeedsTimeAndRecoversAfterCalm(t *testing.T) {
	d := &detector{p: testPressure()}
	s := calmPSI()
	s.memFull[0] = 25
	if v, _ := d.step(&s, 0, at(0)); v != vNone {
		t.Fatalf("one sample posted %v; a short stall must not", v)
	}
	if v, _ := d.step(&s, 0, at(2)); v != vNone {
		t.Fatalf("2 s posted %v", v)
	}
	v, on := d.step(&s, 0, at(4))
	if v != vHigh || !on[resMem] || on[resCPU] {
		t.Fatalf("4 s: %v %v; want high on memory", v, on)
	}
	// While high: no repeat before Repeat, one update at Repeat.
	for n := 6.0; n < 600; n += 2 {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("%v s: %v; at most one post each 10 min", n, v)
		}
	}
	if v, _ := d.step(&s, 0, at(604)); v != vUpdate {
		t.Fatalf("10 min: %v; want one update", v)
	}
	// Calm, but not for a full minute: a stall in between resets it.
	s.memFull[0] = 0
	for _, n := range []float64{606, 640} {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("%v s: %v", n, v)
		}
	}
	s.memFull[0] = 30
	if v, _ := d.step(&s, 0, at(660)); v != vNone {
		t.Fatalf("stall again: %v", v)
	}
	s.memFull[0] = 0
	if v, _ := d.step(&s, 0, at(662)); v != vNone {
		t.Fatal("calm start posted")
	}
	if v, _ := d.step(&s, 0, at(700)); v != vNone {
		t.Fatal("38 s of calm posted recovered")
	}
	if v, _ := d.step(&s, 0, at(722)); v != vRecovered {
		t.Fatalf("60 s of calm: %v; want recovered", v)
	}
	if v, _ := d.step(&s, 0, at(724)); v != vNone {
		t.Fatalf("after recovered: %v; want one message only", v)
	}
}

func TestDetectorCPUNeedsThirtySeconds(t *testing.T) {
	d := &detector{p: testPressure()}
	s := calmPSI()
	s.cpuSome[0] = 79
	for n := 0.0; n <= 60; n += 2 {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("79%% posted %v at %v s", v, n)
		}
	}
	// A compile burst: high for 20 s, then a gap.
	s.cpuSome[0] = 95
	for n := 100.0; n <= 120; n += 2 {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("20 s burst posted at %v s", n)
		}
	}
	s.cpuSome[0] = 50
	d.step(&s, 0, at(122))
	s.cpuSome[0] = 95
	for n := 124.0; n < 154; n += 2 {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("the hold did not start again after the gap (%v s)", n)
		}
	}
	if v, on := d.step(&s, 0, at(154)); v != vHigh || !on[resCPU] {
		t.Fatalf("30 s at 95%%: %v %v", v, on)
	}
}

func TestDetectorTriggerCountsOverItsWindow(t *testing.T) {
	d := &detector{p: testPressure()}
	d.window[resMem] = 2 * time.Second
	s := calmPSI()
	// avg10 is slow to rise. The trigger events alone hold the condition.
	if v, _ := d.step(&s, firedMem, at(0)); v != vNone {
		t.Fatal("one event posted")
	}
	if v, _ := d.step(&s, firedMem, at(2)); v != vNone {
		t.Fatal("two events in 2 s posted")
	}
	if v, on := d.step(&s, firedMem, at(4)); v != vHigh || !on[resMem] {
		t.Fatalf("events for 4 s: %v", v)
	}
	// One event and no more: the condition ends after window + 2 s.
	d2 := &detector{p: testPressure()}
	d2.window[resMem] = 2 * time.Second
	d2.step(&s, firedMem, at(0))
	if v, _ := d2.step(&s, 0, at(5)); v != vNone || !d2.since[resMem].IsZero() {
		t.Fatalf("a lone event still holds after 5 s")
	}
}

func TestDetectorFallbackWithoutPSI(t *testing.T) {
	d := &detector{p: testPressure()}
	s := sample{memTotal: 1000, memAvail: 49, cpus: 4, busy: 10}
	d.step(&s, 0, at(0))
	d.step(&s, 0, at(2))
	if v, on := d.step(&s, 0, at(4)); v != vHigh || !on[resMem] {
		t.Fatalf("MemAvailable 4.9%% for 3 samples: %v", v)
	}
	// CPU without PSI needs a busy CPU and a long run queue.
	d = &detector{p: testPressure()}
	s = sample{memTotal: 1000, memAvail: 500, cpus: 4, busy: 99, load: [3]float64{4}}
	for n := 0.0; n <= 40; n += 2 {
		if v, _ := d.step(&s, 0, at(n)); v != vNone {
			t.Fatalf("all CPUs busy with load 1 each posted %v; that is a compile", v)
		}
	}
	s.load[0] = 9
	for n := 50.0; n < 80; n += 2 {
		d.step(&s, 0, at(n))
	}
	if v, on := d.step(&s, 0, at(80)); v != vHigh || !on[resCPU] {
		t.Fatalf("busy with load 9 on 4 CPUs for 30 s: %v", v)
	}
}

func TestOOMTrackerNamesUnitAndRateLimits(t *testing.T) {
	units := map[string]uint64{"pi-fortress-broker.service": 0, "pi-fortress-dns-house.service": 0}
	scan := func() map[string]uint64 {
		out := map[string]uint64{}
		for k, v := range units {
			out[k] = v
		}
		return out
	}
	var o oomTracker
	rep := 10 * time.Minute
	if msg := o.step(0, scan, at(0), rep); msg != "" {
		t.Fatalf("baseline posted %q", msg)
	}
	units["pi-fortress-broker.service"] = 1
	msg := o.step(1, scan, at(2), rep)
	if !strings.Contains(msg, "pi-fortress-broker.service 1") || strings.Contains(msg, oomOther) {
		t.Fatalf("kill in the broker: %q", msg)
	}
	// The unit restarts: its cgroup is new and starts at 0. Two kills in
	// a unit whose cgroup is already gone, and one more in the broker.
	units["pi-fortress-broker.service"] = 1
	delete(units, "pi-fortress-dns-house.service")
	if msg := o.step(3, scan, at(4), rep); msg != "" {
		t.Fatalf("second kill inside the 10 min posted at once: %q", msg)
	}
	units["pi-fortress-broker.service"] = 0
	if msg := o.step(3, scan, at(400), rep); msg != "" {
		t.Fatalf("rescan posted %q", msg)
	}
	units["pi-fortress-broker.service"] = 1
	msg = o.step(4, scan, at(602), rep)
	if !strings.Contains(msg, "pi-fortress-broker.service 1") || !strings.Contains(msg, oomOther+" 2") {
		t.Fatalf("after 10 min: %q; want the broker 1 and other 2 together", msg)
	}
	if msg := o.step(4, scan, at(1300), rep); msg != "" {
		t.Fatalf("no new kill posted %q", msg)
	}
}

// scriptWaiter returns the bits of steps in order, then firedStop. Each
// wait moves the clock by the timeout.
type scriptWaiter struct {
	steps []uint32
	clock *time.Time
	trig  bool
	win   time.Duration
	hook  func(i int)
	i     int
}

func (w *scriptWaiter) wait(d time.Duration) uint32 {
	*w.clock = w.clock.Add(d)
	if w.i >= len(w.steps) {
		return firedStop
	}
	if w.hook != nil {
		w.hook(w.i)
	}
	w.i++
	return w.steps[w.i-1]
}
func (w *scriptWaiter) triggers() bool { return w.trig }
func (w *scriptWaiter) window(res int) time.Duration {
	if res == resMem {
		return w.win
	}
	return 0
}
func (w *scriptWaiter) mode() string { return "script" }
func (w *scriptWaiter) close()       {}

type postLog struct {
	mu   sync.Mutex
	msgs []string
}

func (l *postLog) post(m string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, m)
}

func TestPressureRunPostsHighThenRecovered(t *testing.T) {
	root := fakeRoot(t, true)
	now := at(0)
	p := testPressure()
	p.Root = root
	p.Now = func() time.Time { return now }
	p.Stderr = &bytes.Buffer{}
	steps := make([]uint32, 60)
	steps[0] = firedMem
	w := &scriptWaiter{steps: steps, clock: &now, trig: true, win: 2 * time.Second}
	w.hook = func(i int) {
		switch i {
		case 0:
			put(t, root, "proc/pressure/memory", "some avg10=60.00 avg60=20.00 avg300=1.00 total=1\nfull avg10=30.00 avg60=9.00 avg300=1.00 total=1\n")
		case 10:
			put(t, root, "proc/pressure/memory", testPSIMem)
		}
	}
	p.newWaiter = func(context.Context, *procReader) waiter { return w }
	var log postLog
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p.Run(ctx, log.post)
	if len(log.msgs) != 2 {
		t.Fatalf("posts = %q; want high, then recovered", log.msgs)
	}
	high := log.msgs[0]
	for _, want := range []string{"PRESSURE HIGH on memory", "memory full 30.0%/9.0%", "MemAvailable 3.8 GiB of 7.6 GiB", "Top memory: pi-fortress-broker.service 286 MiB, user-1000.slice 95 MiB"} {
		if !strings.Contains(high, want) {
			t.Fatalf("high message lacks %q: %s", want, high)
		}
	}
	if !strings.HasPrefix(log.msgs[1], "PRESSURE RECOVERED after ") {
		t.Fatalf("second post: %s", log.msgs[1])
	}
}

func TestPressureCheckRefusesBadValues(t *testing.T) {
	for _, mut := range []func(*Pressure){
		func(p *Pressure) { p.MemFullPct = 0 },
		func(p *Pressure) { p.CPUPct = 100 },
		func(p *Pressure) { p.MemAvailPct = -1 },
		func(p *Pressure) { p.CPUFor = 0 },
		func(p *Pressure) { p.LoadPerCPU = 0 },
	} {
		p := DefaultPressure()
		mut(p)
		if p.Check() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	if err := DefaultPressure().Check(); err != nil {
		t.Fatal(err)
	}
}

func TestPsiSpec(t *testing.T) {
	for _, c := range []struct {
		kind string
		pct  float64
		win  time.Duration
		want string
	}{
		{"full", 10, time.Second, "full 100000 1000000"},
		{"full", 10, 2 * time.Second, "full 200000 2000000"},
		{"some", 80, 10 * time.Second, "some 8000000 10000000"},
		{"some", 99.99999, time.Second, "some 999999 1000000"},
	} {
		if got := psiSpec(c.kind, c.pct, c.win); got != c.want {
			t.Fatalf("psiSpec(%s, %v, %v) = %q, want %q", c.kind, c.pct, c.win, got, c.want)
		}
	}
}
