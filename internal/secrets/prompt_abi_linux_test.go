package secrets

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// termiosABI is struct termios as TCGETS/TCSETS read and write it.
var termiosABI = map[string]struct {
	size                                 uintptr
	iflag, oflag, cflag, lflag, line, cc uintptr
	tcgets, tcsets                       uint
}{
	// include/uapi/asm-generic/termbits.h (x86 includes it): struct termios
	// { u32 c_iflag, c_oflag, c_cflag, c_lflag; u8 c_line; u8 c_cc[19] },
	// size 36. include/uapi/asm-generic/ioctls.h: TCGETS 0x5401, TCSETS 0x5402.
	"amd64": {size: 36, iflag: 0, oflag: 4, cflag: 8, lflag: 12, line: 16, cc: 17, tcgets: 0x5401, tcsets: 0x5402},
	// arm64 uses the same asm-generic headers.
	"arm64": {size: 36, iflag: 0, oflag: 4, cflag: 8, lflag: 12, line: 16, cc: 17, tcgets: 0x5401, tcsets: 0x5402},
}

// syscall.Termios is the glibc shape and is larger than the kernel
// struct; the kernel uses only its prefix, so the prefix must match.
func TestPromptTermiosLayout(t *testing.T) {
	k, ok := termiosABI[runtime.GOARCH]
	if !ok {
		t.Skipf("no ABI row for GOARCH %s", runtime.GOARCH)
	}
	var tm syscall.Termios
	if unsafe.Sizeof(tm) < k.size {
		t.Fatalf("Sizeof(syscall.Termios) = %d < kernel %d", unsafe.Sizeof(tm), k.size)
	}
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"Offsetof(Iflag)", unsafe.Offsetof(tm.Iflag), k.iflag},
		{"Offsetof(Oflag)", unsafe.Offsetof(tm.Oflag), k.oflag},
		{"Offsetof(Cflag)", unsafe.Offsetof(tm.Cflag), k.cflag},
		{"Offsetof(Lflag)", unsafe.Offsetof(tm.Lflag), k.lflag},
		{"Offsetof(Line)", unsafe.Offsetof(tm.Line), k.line},
		{"Offsetof(Cc)", unsafe.Offsetof(tm.Cc), k.cc},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, kernel %s = %d", c.name, c.got, runtime.GOARCH, c.want)
		}
	}
	if syscall.TCGETS != k.tcgets || syscall.TCSETS != k.tcsets {
		t.Errorf("TCGETS/TCSETS = %#x/%#x, kernel %#x/%#x", syscall.TCGETS, syscall.TCSETS, k.tcgets, k.tcsets)
	}
}

// TestEchoOffOnPTY runs echoOff and its restore on a real pty, so the
// ioctl path, not only the layout, is checked.
func TestEchoOffOnPTY(t *testing.T) {
	s := openTestPTY(t)
	var before, during, after syscall.Termios
	if err := ioctl(s.Fd(), syscall.TCGETS, &before); err != nil {
		t.Fatal(err)
	}
	if before.Lflag&syscall.ECHO == 0 {
		t.Skip("pty starts with echo off")
	}
	restore, err := echoOff(s.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if err := ioctl(s.Fd(), syscall.TCGETS, &during); err != nil {
		t.Fatal(err)
	}
	if during.Lflag&syscall.ECHO != 0 {
		t.Fatalf("echo still on: lflag=%#x", during.Lflag)
	}
	if during.Lflag&(syscall.ICANON|syscall.ISIG) != syscall.ICANON|syscall.ISIG {
		t.Fatalf("ICANON or ISIG off: lflag=%#x", during.Lflag)
	}
	restore()
	if err := ioctl(s.Fd(), syscall.TCGETS, &after); err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag || after.Cc != before.Cc {
		t.Fatalf("restore did not put back the termios: before=%+v after=%+v", before, after)
	}
}

func openTestPTY(t *testing.T) *os.File {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Skip("TIOCGPTN:", e)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skip("TIOCSPTLCK:", e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("open slave:", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
