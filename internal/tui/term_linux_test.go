package tui

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openPTY returns a pty slave to use as the stdin of the seat. Without a
// real tty, there is no termios to get wrong. Thus the test skips, and
// does not claim that it checked.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		t.Skip("TIOCGPTN:", err)
	}
	var unlock int32
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		t.Skip("TIOCSPTLCK:", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("open slave:", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// EnterRaw puts the terminal in raw mode, and only then writes the escapes
// that switch to the alternate screen. If that write fails, the caller
// never installs its Restore. The operator then has a shell that echoes
// nothing.
func TestEnterRawRestoresWhenTheSetupWriteFails(t *testing.T) {
	in := openPTY(t)
	var before syscall.Termios
	if err := ioctl(in.Fd(), syscall.TCGETS, unsafe.Pointer(&before)); err != nil {
		t.Fatal(err)
	}
	// A closed file is a writer that fails on the first byte.
	dead, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.Close()
	term := &linuxTerm{in: in, out: dead}
	if err := term.EnterRaw(); err == nil {
		t.Fatal("EnterRaw reported success though it could not write")
	}
	var after syscall.Termios
	if err := ioctl(in.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag {
		t.Fatalf("terminal left raw: lflag %#x -> %#x, iflag %#x -> %#x",
			before.Lflag, after.Lflag, before.Iflag, after.Iflag)
	}
}

// The terminal turns bracketed paste on with the alternate screen, and off
// again on restore. A shell that gets a tty with the mode still on reads
// the brackets of the next paste as text.
func TestRawModeTurnsBracketedPasteOnAndOff(t *testing.T) {
	in := openPTY(t)
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	term := &linuxTerm{in: in, out: out}
	if err := term.EnterRaw(); err != nil {
		t.Fatal(err)
	}
	term.Restore()
	raw, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	on, off := strings.Index(string(raw), pasteOn), strings.LastIndex(string(raw), pasteOff)
	if on < 0 || off < on {
		t.Fatalf("bracketed paste not on then off: %q", raw)
	}
}

// A paste start with no end must not hold the seat. When no byte comes for
// a short time, the paste is over. Before, every later key was a paste, so
// q, Ctrl-C and a typed confirm did nothing until the idle timer.
func TestPasteStartWithNoEndStops(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	stop := make(chan struct{})
	defer close(stop)
	term := &linuxTerm{src: newByteSource(r, stop), wake: stop}
	read := func(then func()) Key {
		t.Helper()
		got := make(chan Key, 1)
		go func() { k, _ := term.ReadKey(); got <- k }()
		then()
		select {
		case k := <-got:
			return k
		case <-time.After(5 * time.Second):
			t.Fatal("no key")
		}
		return Key{}
	}
	if k := read(func() { _, _ = w.Write([]byte("\x1b[200~a")) }); k.Rune != 'a' || !k.Paste {
		t.Fatalf("a key after the start is not a paste: %+v", k)
	}
	// A short stop in a paste (a slow link) does not end it.
	k := read(func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("b"))
	})
	if k.Rune != 'b' || !k.Paste {
		t.Fatalf("a short stop ended the paste: %+v", k)
	}
	// The seat waits in ReadKey, and the operator types q later.
	k = read(func() {
		time.Sleep(1500 * time.Millisecond)
		_, _ = w.Write([]byte("q"))
	})
	if k.Rune != 'q' || k.Paste {
		t.Fatalf("a typed key long after an open paste start is a paste: %+v", k)
	}
}
