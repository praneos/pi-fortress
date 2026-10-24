package ship

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// renameat2ABI holds the kernel values that exchange passes to the
// syscall. A wrong number calls a different syscall with two pointers.
var renameat2ABI = map[string]struct {
	nr       uintptr // __NR_renameat2
	exchange uintptr // RENAME_EXCHANGE
}{
	// arch/x86/entry/syscalls/syscall_64.tbl: 316 common renameat2.
	// include/uapi/linux/fs.h: RENAME_EXCHANGE (1 << 1).
	"amd64": {nr: 316, exchange: 2},
	// include/uapi/asm-generic/unistd.h: __NR_renameat2 276.
	// include/uapi/linux/fs.h: RENAME_EXCHANGE (1 << 1).
	"arm64": {nr: 276, exchange: 2},
}

func TestRenameat2ABI(t *testing.T) {
	want, ok := renameat2ABI[runtime.GOARCH]
	if !ok {
		if sysRenameat2 != 0 {
			t.Fatalf("GOARCH %s has sysRenameat2=%d but no row in the ABI table", runtime.GOARCH, sysRenameat2)
		}
		t.Skipf("no renameat2 on GOARCH %s; exchange uses three renames", runtime.GOARCH)
	}
	if sysRenameat2 != want.nr {
		t.Fatalf("sysRenameat2 = %d, kernel __NR_renameat2 on %s = %d", sysRenameat2, runtime.GOARCH, want.nr)
	}
	if renameExchange != want.exchange {
		t.Fatalf("renameExchange = %d, kernel RENAME_EXCHANGE = %d", renameExchange, want.exchange)
	}
}

// TestRenameat2SwapsOnThisKernel calls the syscall number exchange uses,
// with the same arguments, and checks that the two paths swapped. It runs
// only after the table check, so a wrong number never gets here.
func TestRenameat2SwapsOnThisKernel(t *testing.T) {
	if _, ok := renameat2ABI[runtime.GOARCH]; !ok || sysRenameat2 != renameat2ABI[runtime.GOARCH].nr {
		t.Skip("no verified renameat2 number on this GOARCH")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("A"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(b, 0o700); err != nil {
		t.Fatal(err)
	}
	pa, err := syscall.BytePtrFromString(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := syscall.BytePtrFromString(b)
	if err != nil {
		t.Fatal(err)
	}
	// include/uapi/linux/fcntl.h: AT_FDCWD -100, the value exchange uses.
	cwd := -100
	_, _, errno := syscall.Syscall6(sysRenameat2, uintptr(cwd), uintptr(unsafe.Pointer(pa)), uintptr(cwd), uintptr(unsafe.Pointer(pb)), renameExchange, 0)
	if errno == syscall.ENOSYS || errno == syscall.EINVAL {
		t.Skipf("kernel or filesystem has no RENAME_EXCHANGE: %v", errno)
	}
	if errno != 0 {
		t.Fatalf("renameat2: %v", errno)
	}
	assertSwapped(t, a, b)
}

func TestExchangeSwapsFileAndDir(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("A"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(b, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := exchange(a, b); err != nil {
		t.Fatal(err)
	}
	assertSwapped(t, a, b)
	if _, err := os.Lstat(b + ".swap"); !os.IsNotExist(err) {
		t.Fatalf("swap temp left behind: %v", err)
	}
}

// assertSwapped expects a to be the directory and b the file "A".
func assertSwapped(t *testing.T, a, b string) {
	t.Helper()
	if fi, err := os.Lstat(a); err != nil || !fi.IsDir() {
		t.Fatalf("a is not the directory after the swap: %v", err)
	}
	got, err := os.ReadFile(b)
	if err != nil || string(got) != "A" {
		t.Fatalf("b = %q, %v; want the file \"A\"", got, err)
	}
}
