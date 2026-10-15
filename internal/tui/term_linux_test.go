package tui

import (
	"fmt"
	"os"
	"syscall"
	"testing"
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
