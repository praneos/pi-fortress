package alert

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestPollWaiterTimeoutAndStop: without PSI, ppoll waits on the slice
// files and the stop pipe. It returns at the timeout, and at once when the
// context ends.
func TestPollWaiterTimeoutAndStop(t *testing.T) {
	r := newProcReader(fakeRoot(t, false))
	defer r.close()
	ctx, cancel := context.WithCancel(context.Background())
	w := DefaultPressure().waiterFor(ctx, r)
	defer w.close()
	if !strings.Contains(w.mode(), "no PSI") || w.triggers() {
		t.Fatalf("mode = %q", w.mode())
	}
	start := time.Now()
	if got := w.wait(100 * time.Millisecond); got != 0 {
		t.Fatalf("timeout returned %b", got)
	}
	if el := time.Since(start); el < 90*time.Millisecond {
		t.Fatalf("returned after %v", el)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start = time.Now()
	if got := w.wait(10 * time.Second); got&firedStop == 0 {
		t.Fatalf("stop returned %b", got)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("stop took %v", el)
	}
}

// TestArmTriggerRealKernel arms the triggers on the PSI of this host, if
// the kernel allows it. An unprivileged process gets the 2 s window from
// kernel 6.5. The test skips where there is no PSI or no unprivileged
// trigger.
func TestArmTriggerRealKernel(t *testing.T) {
	r := newProcReader("/")
	defer r.close()
	if r.psiMem == nil {
		t.Skip("no /proc/pressure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := DefaultPressure().waiterFor(ctx, r)
	defer w.close()
	t.Log(w.mode())
	if !w.triggers() {
		t.Skip(w.mode())
	}
	if win := w.window(resMem); win != time.Second && win != 2*time.Second {
		t.Fatalf("memory window %v", win)
	}
	if got := w.wait(50 * time.Millisecond); got&firedStop != 0 {
		t.Fatalf("wait = %b", got)
	}
}
