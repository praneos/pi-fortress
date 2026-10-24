package alert

import (
	"math"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
)

// TestLockMemoryNeedsInfinity: with a finite LimitMEMLOCK, LockMemory does
// not call mlockall. The Go runtime would stop later when the heap grows.
// It sets the heap limit only when GOMEMLIMIT did not.
func TestLockMemoryNeedsInfinity(t *testing.T) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(rlimitMemlock, &rl); err != nil || rl.Cur == math.MaxUint64 {
		t.Skip("RLIMIT_MEMLOCK is infinity here; the test would lock its own pages")
	}
	prev := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prev)
	debug.SetMemoryLimit(math.MaxInt64)
	got := LockMemory(80 << 20)
	if !strings.Contains(got, "not infinity") || !strings.Contains(got, "Go heap limit 80 MiB") {
		t.Fatalf("LockMemory = %q", got)
	}
	if debug.SetMemoryLimit(-1) != 80<<20 {
		t.Fatal("the heap limit is not set")
	}
	debug.SetMemoryLimit(64 << 20)
	if got := LockMemory(80 << 20); strings.Contains(got, "heap") || debug.SetMemoryLimit(-1) != 64<<20 {
		t.Fatalf("LockMemory replaced the GOMEMLIMIT cap: %q", got)
	}
}
