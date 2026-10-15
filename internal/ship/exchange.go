package ship

import (
	"os"
	"syscall"
	"unsafe"
)

const renameExchange = 1 << 1

// exchange swaps two existing paths in one step (renameat2
// RENAME_EXCHANGE), so the tree is never absent. Kernels or filesystems
// without it get three renames.
func exchange(a, b string) error {
	if sysRenameat2 != 0 {
		pa, err := syscall.BytePtrFromString(a)
		if err != nil {
			return err
		}
		pb, err := syscall.BytePtrFromString(b)
		if err != nil {
			return err
		}
		cwd := -100
		_, _, errno := syscall.Syscall6(sysRenameat2, uintptr(cwd), uintptr(unsafe.Pointer(pa)), uintptr(cwd), uintptr(unsafe.Pointer(pb)), renameExchange, 0)
		if errno == 0 {
			return nil
		}
		if errno != syscall.ENOSYS && errno != syscall.EINVAL {
			return &os.LinkError{Op: "exchange", Old: a, New: b, Err: errno}
		}
	}
	tmp := b + ".swap"
	if err := os.Rename(b, tmp); err != nil {
		return err
	}
	if err := os.Rename(a, b); err != nil {
		os.Rename(tmp, b)
		return err
	}
	return os.Rename(tmp, a)
}
