package alert

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// sample is one read of the pressure files. Percentages are 0 to 100. A
// PSI value is avg10 and avg60. Memory sizes are in KiB.
type sample struct {
	psi      bool
	memSome  [2]float64
	memFull  [2]float64
	cpuSome  [2]float64
	memTotal uint64
	memAvail uint64
	load     [3]float64
	// busy is the share of CPU time that was not idle since the previous
	// read. It is -1 on the first read.
	busy float64
	cpus int
	// oomKills is the sum of oom_kill of the top slices. A slice is never
	// removed, so the sum only increases.
	oomKills uint64
}

// procReader keeps the pressure files open and reads them again with
// pread into one buffer. Thus a read in the steady state makes no
// allocations. A file that is absent stays nil, and its values stay 0.
type procReader struct {
	root                  string
	meminfo, loadavg, cpu *os.File
	psiMem, psiCPU        *os.File
	slices                []*os.File
	buf                   [4096]byte
	prevBusy, prevTotal   uint64
	cpus                  int
}

func openIf(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	return f
}

func newProcReader(root string) *procReader {
	r := &procReader{root: root}
	r.meminfo = openIf(r.path("proc/meminfo"))
	r.loadavg = openIf(r.path("proc/loadavg"))
	r.cpu = openIf(r.path("proc/stat"))
	r.psiMem = openIf(r.path("proc/pressure/memory"))
	r.psiCPU = openIf(r.path("proc/pressure/cpu"))
	for _, dir := range r.topSlices() {
		if f := openIf(filepath.Join(dir, "memory.events")); f != nil {
			r.slices = append(r.slices, f)
		}
	}
	if raw, err := os.ReadFile(r.path("proc/stat")); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
				r.cpus++
			}
		}
	}
	if r.cpus == 0 {
		r.cpus = 1
	}
	return r
}

func (r *procReader) path(p string) string { return filepath.Join(r.root, p) }

func (r *procReader) cgroup() string { return r.path("sys/fs/cgroup") }

func (r *procReader) close() {
	for _, f := range append([]*os.File{r.meminfo, r.loadavg, r.cpu, r.psiMem, r.psiCPU}, r.slices...) {
		if f != nil {
			_ = f.Close()
		}
	}
}

// topSlices are the slices directly below the cgroup root:
// system.slice, user.slice and machine.slice when it exists.
func (r *procReader) topSlices() []string {
	ents, err := os.ReadDir(r.cgroup())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".slice") {
			out = append(out, filepath.Join(r.cgroup(), e.Name()))
		}
	}
	return out
}

// fill reads f from offset 0 into the buffer. It returns nil when f is
// nil or the read fails.
func (r *procReader) fill(f *os.File, max int) []byte {
	if f == nil {
		return nil
	}
	n, _ := f.ReadAt(r.buf[:max], 0)
	if n <= 0 {
		return nil
	}
	return r.buf[:n]
}

func (r *procReader) read(s *sample) {
	s.cpus = r.cpus
	s.psi = r.psiMem != nil && r.psiCPU != nil
	if b := r.fill(r.psiMem, len(r.buf)); b != nil {
		s.memSome = psiAvg(b, "some")
		s.memFull = psiAvg(b, "full")
	} else {
		s.psi = false
	}
	if b := r.fill(r.psiCPU, len(r.buf)); b != nil {
		s.cpuSome = psiAvg(b, "some")
	} else {
		s.psi = false
	}
	if b := r.fill(r.meminfo, len(r.buf)); b != nil {
		s.memTotal = meminfoKB(b, "MemTotal:")
		s.memAvail = meminfoKB(b, "MemAvailable:")
	}
	if b := r.fill(r.loadavg, 128); b != nil {
		for i := range s.load {
			var v float64
			v, b = nextFloat(b)
			s.load[i] = v
		}
	}
	s.busy = -1
	// Only the first line of /proc/stat. The intr line after it can be
	// many KiB long.
	if b := r.fill(r.cpu, 512); b != nil {
		busy, total := statCPU(b)
		if r.prevTotal > 0 && total > r.prevTotal && busy >= r.prevBusy {
			s.busy = 100 * float64(busy-r.prevBusy) / float64(total-r.prevTotal)
		}
		r.prevBusy, r.prevTotal = busy, total
	}
	s.oomKills = 0
	for _, f := range r.slices {
		if b := r.fill(f, 512); b != nil {
			s.oomKills += eventCount(b, "oom_kill")
		}
	}
}

// psiAvg returns avg10 and avg60 of the line that starts with kind
// ("some" or "full").
func psiAvg(b []byte, kind string) [2]float64 {
	var out [2]float64
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		if !bytes.HasPrefix(line, []byte(kind)) {
			continue
		}
		for j, key := range [2]string{"avg10=", "avg60="} {
			if i := bytes.Index(line, []byte(key)); i >= 0 {
				out[j], _ = nextFloat(line[i+len(key):])
			}
		}
		break
	}
	return out
}

func meminfoKB(b []byte, key string) uint64 {
	i := bytes.Index(b, []byte(key))
	if i < 0 {
		return 0
	}
	v, _ := nextUint(b[i+len(key):])
	return v
}

// eventCount returns the value of key in a memory.events file.
func eventCount(b []byte, key string) uint64 {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		if len(line) > len(key) && string(line[:len(key)]) == key && line[len(key)] == ' ' {
			v, _ := nextUint(line[len(key):])
			return v
		}
	}
	return 0
}

// statCPU returns the busy and the total ticks of the cpu line of
// /proc/stat, with the same sum as internal/monitor: user to steal, with
// idle and iowait as idle.
func statCPU(b []byte) (busy, total uint64) {
	if !bytes.HasPrefix(b, []byte("cpu ")) {
		return 0, 0
	}
	b = b[4:]
	var idle uint64
	for i := 0; i < 8; i++ {
		var v uint64
		v, b = nextUint(b)
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return total - idle, total
}

// nextUint skips spaces and reads one decimal number.
func nextUint(b []byte) (uint64, []byte) {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	var v uint64
	for len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
		v = v*10 + uint64(b[0]-'0')
		b = b[1:]
	}
	return v, b
}

// nextFloat skips spaces and reads one number of the form 12.34.
func nextFloat(b []byte) (float64, []byte) {
	w, b := nextUint(b)
	v := float64(w)
	if len(b) > 0 && b[0] == '.' {
		b = b[1:]
		var frac uint64
		div := 1.0
		for len(b) > 0 && b[0] >= '0' && b[0] <= '9' && div < 1e15 {
			frac = frac*10 + uint64(b[0]-'0')
			div *= 10
			b = b[1:]
		}
		v += float64(frac) / div
		for len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
			b = b[1:]
		}
	}
	return v, b
}

// bootID is the random ID that the kernel makes at each boot.
func (r *procReader) bootID() string {
	raw, err := os.ReadFile(r.path("proc/sys/kernel/random/boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// unitDirs are the cgroups of the pi-fortress units. A template unit
// (dns-stub@) is one level lower, in its own slice.
func (r *procReader) unitDirs() map[string]string {
	out := map[string]string{}
	sys := filepath.Join(r.cgroup(), "system.slice")
	ents, _ := os.ReadDir(sys)
	for _, e := range ents {
		name := e.Name()
		switch {
		case !e.IsDir():
		case strings.HasPrefix(name, "pi-fortress-") && strings.HasSuffix(name, ".service"):
			out[name] = filepath.Join(sys, name)
		case strings.HasPrefix(name, `system-pi\x2dfortress`) && strings.HasSuffix(name, ".slice"):
			sub, _ := os.ReadDir(filepath.Join(sys, name))
			for _, s := range sub {
				if s.IsDir() && strings.HasSuffix(s.Name(), ".service") {
					out[s.Name()] = filepath.Join(sys, name, s.Name())
				}
			}
		}
	}
	return out
}

// unitOOMKills reads oom_kill of each pi-fortress unit.
func (r *procReader) unitOOMKills() map[string]uint64 {
	out := map[string]uint64{}
	for name, dir := range r.unitDirs() {
		raw, err := os.ReadFile(filepath.Join(dir, "memory.events"))
		if err != nil {
			continue
		}
		out[name] = eventCount(raw, "oom_kill")
	}
	return out
}

// groups are the cgroups that the top lists compare: each service, and
// each user session slice. The alert unit runs with ProtectProc=invisible.
// So it cannot see the processes of other users, but each cgroup file is
// world-readable. A unit name is also what the operator stops or restarts.
func (r *procReader) groups() map[string]string {
	out := map[string]string{}
	for _, top := range r.topSlices() {
		ents, _ := os.ReadDir(top)
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(top, e.Name())
			if filepath.Base(top) == "system.slice" && strings.HasSuffix(e.Name(), ".slice") {
				sub, _ := os.ReadDir(dir)
				for _, s := range sub {
					if s.IsDir() {
						out[s.Name()] = filepath.Join(dir, s.Name())
					}
				}
				continue
			}
			out[e.Name()] = dir
		}
	}
	return out
}

func readUint(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return v, err == nil
}

// cpuUsage reads usage_usec of each group.
func cpuUsage(groups map[string]string) map[string]uint64 {
	out := make(map[string]uint64, len(groups))
	for name, dir := range groups {
		raw, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
		if err != nil {
			continue
		}
		out[name] = eventCount(raw, "usage_usec")
	}
	return out
}

type ranked struct {
	name string
	v    uint64
}

// top3 returns the three largest values, largest first. A zero is not
// listed.
func top3(m map[string]uint64) []ranked {
	out := make([]ranked, 0, len(m))
	for k, v := range m {
		if v > 0 {
			out = append(out, ranked{k, v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].name < out[j].name
	})
	return out[:min(3, len(out))]
}

// topMemory is memory.current of each group: the RAM and the page cache
// that the kernel charges to it.
func (r *procReader) topMemory() []ranked {
	m := map[string]uint64{}
	for name, dir := range r.groups() {
		if v, ok := readUint(filepath.Join(dir, "memory.current")); ok {
			m[name] = v
		}
	}
	return top3(m)
}

// topCPU compares two reads of usage_usec. The caller waits one second
// between them. A group under 1% of one CPU is not listed.
func topCPU(before, after map[string]uint64) []ranked {
	m := map[string]uint64{}
	for k, v := range after {
		if b, ok := before[k]; ok && v >= b+10000 {
			m[k] = v - b
		}
	}
	return top3(m)
}

func sortedNames(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
