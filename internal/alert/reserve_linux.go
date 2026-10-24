package alert

import (
	"fmt"
	"math"
	"runtime/debug"
	"strings"
	"syscall"
)

// mclOnFault locks each page when it is first used, not at the call. The
// Go runtime reserves large address ranges that it never uses. Without
// this flag, mlockall would fill them. The value is the same on amd64 and
// arm64. The syscall package does not have it.
const mclOnFault = 0x4

const rlimitMemlock = 8

// LockMemory keeps the pages of this process in RAM, and caps the Go heap
// at heapLimit when GOMEMLIMIT does not set a cap. Thus the reclaim of the
// kernel cannot put the alert code out of RAM when RAM is short.
//
// The kernel counts the full size of each mapping against RLIMIT_MEMLOCK,
// not the pages in use. A Go process maps about 1 GiB at start. So a
// finite limit refuses MCL_CURRENT. With MCL_FUTURE only, the Go runtime
// stops later, when its heap grows past the limit. LockMemory locks only
// when the limit is infinity. The MemoryMax of the unit is then the bound.
// It returns one line for the journal.
func LockMemory(heapLimit int64) string {
	var note []string
	if heapLimit > 0 && debug.SetMemoryLimit(-1) == math.MaxInt64 {
		debug.SetMemoryLimit(heapLimit)
		note = append(note, fmt.Sprintf("Go heap limit %d MiB", heapLimit>>20))
	}
	var rl syscall.Rlimit
	switch err := syscall.Getrlimit(rlimitMemlock, &rl); {
	case err != nil:
		note = append(note, "memory not locked: "+err.Error())
	case rl.Cur != math.MaxUint64:
		note = append(note, fmt.Sprintf("memory not locked: LimitMEMLOCK is %d, not infinity", rl.Cur))
	default:
		if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE | mclOnFault); err != nil {
			note = append(note, "memory not locked: "+err.Error())
		} else {
			note = append(note, "memory locked")
		}
	}
	return strings.Join(note, "; ")
}
