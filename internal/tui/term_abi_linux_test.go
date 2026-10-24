package tui

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// termABI is the kernel side of the three ioctls in term_linux.go.
type termABI struct {
	// struct termios (TCGETS/TCSETS read and write this, not termios2).
	termiosSize                          uintptr
	iflag, oflag, cflag, lflag, line, cc uintptr
	nccs                                 int
	vtime, vmin                          int
	// struct winsize (TIOCGWINSZ).
	winsizeSize, row, col, xpixel, ypixel  uintptr
	tcgets, tcsets, tiocgwinsz, tiocswinsz uint
}

var kernelTermABI = map[string]termABI{
	// arch/x86/include/uapi/asm/termbits.h and ioctls.h include the
	// asm-generic ones. include/uapi/asm-generic/termbits.h: struct termios
	// { tcflag_t (u32) c_iflag, c_oflag, c_cflag, c_lflag; cc_t c_line;
	// cc_t c_cc[NCCS=19] }, size 36; VTIME 5, VMIN 6.
	// include/uapi/asm-generic/termios.h: struct winsize { u16 ws_row,
	// ws_col, ws_xpixel, ws_ypixel }, size 8.
	// include/uapi/asm-generic/ioctls.h: TCGETS 0x5401, TCSETS 0x5402,
	// TIOCGWINSZ 0x5413, TIOCSWINSZ 0x5414.
	"amd64": {
		termiosSize: 36, iflag: 0, oflag: 4, cflag: 8, lflag: 12, line: 16, cc: 17, nccs: 19, vtime: 5, vmin: 6,
		winsizeSize: 8, row: 0, col: 2, xpixel: 4, ypixel: 6,
		tcgets: 0x5401, tcsets: 0x5402, tiocgwinsz: 0x5413, tiocswinsz: 0x5414,
	},
	// arch/arm64 uses the asm-generic headers directly; same values.
	"arm64": {
		termiosSize: 36, iflag: 0, oflag: 4, cflag: 8, lflag: 12, line: 16, cc: 17, nccs: 19, vtime: 5, vmin: 6,
		winsizeSize: 8, row: 0, col: 2, xpixel: 4, ypixel: 6,
		tcgets: 0x5401, tcsets: 0x5402, tiocgwinsz: 0x5413, tiocswinsz: 0x5414,
	},
}

// winsizeT is the type of ws in (*linuxTerm).Size. Keep the two the same.
type winsizeT = struct{ Row, Col, X, Y uint16 }

type sizeCheck struct {
	name      string
	got, want uintptr
}

func runChecks(t *testing.T, cs []sizeCheck) {
	t.Helper()
	for _, c := range cs {
		if c.got != c.want {
			t.Errorf("%s = %d, kernel %s = %d", c.name, c.got, runtime.GOARCH, c.want)
		}
	}
}

func abiRow(t *testing.T) termABI {
	t.Helper()
	k, ok := kernelTermABI[runtime.GOARCH]
	if !ok {
		t.Skipf("no ABI row for GOARCH %s", runtime.GOARCH)
	}
	return k
}

// The Go syscall.Termios is the glibc shape (NCCS 32 plus two speeds), so
// it is larger than the kernel struct. That is safe for TCGETS/TCSETS: the
// kernel reads and writes only its prefix. The prefix must match.
func TestTermiosLayout(t *testing.T) {
	k := abiRow(t)
	var tm syscall.Termios
	if unsafe.Sizeof(tm) < k.termiosSize {
		t.Fatalf("Sizeof(syscall.Termios) = %d < kernel struct termios %d: TCGETS writes past it", unsafe.Sizeof(tm), k.termiosSize)
	}
	if len(tm.Cc) < k.nccs {
		t.Fatalf("len(Termios.Cc) = %d < kernel NCCS %d", len(tm.Cc), k.nccs)
	}
	runChecks(t, []sizeCheck{
		{"Offsetof(Iflag)", unsafe.Offsetof(tm.Iflag), k.iflag},
		{"Offsetof(Oflag)", unsafe.Offsetof(tm.Oflag), k.oflag},
		{"Offsetof(Cflag)", unsafe.Offsetof(tm.Cflag), k.cflag},
		{"Offsetof(Lflag)", unsafe.Offsetof(tm.Lflag), k.lflag},
		{"Offsetof(Line)", unsafe.Offsetof(tm.Line), k.line},
		{"Offsetof(Cc)", unsafe.Offsetof(tm.Cc), k.cc},
		{"Sizeof(Iflag)", unsafe.Sizeof(tm.Iflag), 4},
	})
	if syscall.VTIME != k.vtime || syscall.VMIN != k.vmin {
		t.Errorf("syscall VTIME/VMIN = %d/%d, kernel %d/%d", syscall.VTIME, syscall.VMIN, k.vtime, k.vmin)
	}
	if syscall.VTIME >= k.nccs || syscall.VMIN >= k.nccs {
		t.Errorf("VTIME/VMIN index past the kernel c_cc[%d]", k.nccs)
	}
}

func TestWinsizeLayout(t *testing.T) {
	k := abiRow(t)
	var ws winsizeT
	runChecks(t, []sizeCheck{
		{"Sizeof(winsize)", unsafe.Sizeof(ws), k.winsizeSize},
		{"Offsetof(Row)", unsafe.Offsetof(ws.Row), k.row},
		{"Offsetof(Col)", unsafe.Offsetof(ws.Col), k.col},
		{"Offsetof(X)", unsafe.Offsetof(ws.X), k.xpixel},
		{"Offsetof(Y)", unsafe.Offsetof(ws.Y), k.ypixel},
	})
}

func TestTermIoctlNumbers(t *testing.T) {
	k := abiRow(t)
	got := []uint{syscall.TCGETS, syscall.TCSETS, syscall.TIOCGWINSZ, syscall.TIOCSWINSZ}
	want := []uint{k.tcgets, k.tcsets, k.tiocgwinsz, k.tiocswinsz}
	names := []string{"TCGETS", "TCSETS", "TIOCGWINSZ", "TIOCSWINSZ"}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("syscall.%s = %#x, kernel %#x", names[i], got[i], want[i])
		}
	}
}

// TestTCGETSWritesOnlyTheKernelPrefix fills a Termios with a sentinel and
// checks that TCGETS on a real pty changes no byte past the kernel size.
func TestTCGETSWritesOnlyTheKernelPrefix(t *testing.T) {
	k := abiRow(t)
	s := openPTY(t)
	var tm syscall.Termios
	b := unsafe.Slice((*byte)(unsafe.Pointer(&tm)), unsafe.Sizeof(tm))
	for i := range b {
		b[i] = 0xa5
	}
	if err := ioctl(s.Fd(), syscall.TCGETS, unsafe.Pointer(&tm)); err != nil {
		t.Fatal(err)
	}
	for i := k.termiosSize; i < uintptr(len(b)); i++ {
		if b[i] != 0xa5 {
			t.Fatalf("TCGETS wrote byte %d; kernel struct termios is %d bytes", i, k.termiosSize)
		}
	}
	if tm.Cflag == 0xa5a5a5a5 || tm.Line == 0xa5 {
		t.Fatalf("TCGETS did not fill the prefix: cflag=%#x line=%#x", tm.Cflag, tm.Line)
	}
}

// TestSizeReadsKernelWinsize sets a known size on a pty and checks that
// Size gets the columns and rows back in the right order.
func TestSizeReadsKernelWinsize(t *testing.T) {
	abiRow(t)
	s := openPTY(t)
	set := winsizeT{Row: 37, Col: 113, X: 0, Y: 0}
	if err := ioctl(s.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&set)); err != nil {
		t.Skip("TIOCSWINSZ:", err)
	}
	term := &linuxTerm{in: s, out: s}
	cols, rows := term.Size()
	if cols != 113 || rows != 37 {
		t.Fatalf("Size() = %d cols, %d rows; want 113, 37", cols, rows)
	}
}
