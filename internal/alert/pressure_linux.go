package alert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// The poll(2) event bits. They are the same on amd64 and arm64. arm64 has
// no poll syscall, so the wait uses ppoll.
const (
	pollIn  = 0x1
	pollPri = 0x2
	pollErr = 0x8
	pollHup = 0x10
)

type pollFd struct {
	fd      int32
	events  int16
	revents int16
}

// pollWaiter waits in ppoll on the PSI triggers, on memory.events of the
// top slices, and on a pipe that closes when the context ends.
type pollWaiter struct {
	fds   []pollFd
	bits  []uint32
	files []*os.File
	stopR *os.File
	stopW *os.File
	win   [nRes]time.Duration
	why   string
	buf   [512]byte
}

// armTrigger opens path and writes the first spec that the kernel takes.
// A process without CAP_SYS_RESOURCE gets a trigger only on kernel 6.5 and
// later, and only with a window that is a multiple of 2 s. Before that, the
// kernel refuses each unprivileged trigger. EINVAL and EPERM try the next
// spec. Each other error stops.
func armTrigger(path string, specs []string, windows []time.Duration) (*os.File, string, time.Duration, error) {
	var last error
	for i, spec := range specs {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, "", 0, err
		}
		if _, err = f.Write(append([]byte(spec), 0)); err == nil {
			return f, spec, windows[i], nil
		}
		_ = f.Close()
		last = err
		if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.EPERM) {
			break
		}
	}
	return nil, "", 0, last
}

func (p *Pressure) waiterFor(ctx context.Context, r *procReader) waiter {
	w := &pollWaiter{}
	var err error
	if w.stopR, w.stopW, err = os.Pipe(); err != nil {
		return &sleepWaiter{ctx: ctx, why: "no pipe for the wait (" + err.Error() + "); files read each 2 s"}
	}
	w.add(w.stopR, pollIn, firedStop)
	go func() {
		<-ctx.Done()
		_ = w.stopW.Close()
	}()
	for _, f := range r.slices {
		g, err := os.Open(f.Name())
		if err != nil {
			continue
		}
		w.add(g, pollPri, firedOOM)
		// kernfs reports a change since the last read. The first read sets
		// the start.
		_, _ = g.ReadAt(w.buf[:], 0)
	}
	if r.psiMem == nil || r.psiCPU == nil {
		w.why = "no PSI (/proc/pressure); MemAvailable, load and /proc/stat read each 2 s"
		return w
	}
	memFile, memSpec, memWin, err := armTrigger(r.path("proc/pressure/memory"),
		[]string{psiSpec("full", p.MemFullPct, time.Second), psiSpec("full", p.MemFullPct, 2*time.Second)},
		[]time.Duration{time.Second, 2 * time.Second})
	if err != nil {
		w.why = "PSI triggers refused (" + err.Error() + "); PSI read each 2 s"
		return w
	}
	cpuFile, cpuSpec, cpuWin, err := armTrigger(r.path("proc/pressure/cpu"),
		[]string{psiSpec("some", p.CPUPct, 10*time.Second)}, []time.Duration{10 * time.Second})
	if err != nil {
		_ = memFile.Close()
		w.why = "PSI triggers refused (" + err.Error() + "); PSI read each 2 s"
		return w
	}
	w.add(memFile, pollPri, firedMem)
	w.add(cpuFile, pollPri, firedCPU)
	w.win[resMem], w.win[resCPU] = memWin, cpuWin
	w.why = fmt.Sprintf("PSI triggers armed (memory %q, cpu %q)", memSpec, cpuSpec)
	return w
}

func (w *pollWaiter) add(f *os.File, events int16, bit uint32) {
	w.files = append(w.files, f)
	w.fds = append(w.fds, pollFd{fd: int32(f.Fd()), events: events})
	w.bits = append(w.bits, bit)
}

func (w *pollWaiter) wait(d time.Duration) uint32 {
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return 0
		}
		ts := syscall.NsecToTimespec(left.Nanoseconds())
		n, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&w.fds[0])), uintptr(len(w.fds)),
			uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		if e == syscall.EINTR {
			continue
		}
		if e != 0 {
			// A failed ppoll must not spin. Wait the full time.
			time.Sleep(left)
			return 0
		}
		if n == 0 {
			return 0
		}
		var fired uint32
		for i := range w.fds {
			if w.fds[i].revents == 0 {
				continue
			}
			fired |= w.bits[i]
			if w.bits[i] == firedOOM {
				_, _ = w.files[i].ReadAt(w.buf[:], 0)
			}
			w.fds[i].revents = 0
		}
		return fired
	}
}

func (w *pollWaiter) triggers() bool               { return w.win[resMem] > 0 }
func (w *pollWaiter) window(res int) time.Duration { return w.win[res] }
func (w *pollWaiter) mode() string                 { return w.why }

func (w *pollWaiter) close() {
	for _, f := range w.files {
		_ = f.Close()
	}
	_ = w.stopW.Close()
}
