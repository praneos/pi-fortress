package tui

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const signalSlaveEnv = "PF_TUI_SIGNAL_SLAVE"

// newPTY returns the master and the path of its slave. The user of the
// slave opens it. For this test, that is a child process.
func newPTY(t *testing.T) (*os.File, string) {
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
	return m, fmt.Sprintf("/dev/pts/%d", n)
}

// Ctrl-C sends SIGINT. Raw mode is a property of the tty, not of the
// process that set it. A seat that dies of SIGINT without a restore of the
// tty leaves the shell of the operator with no echo, no line editing and
// the alternate screen still on. Nothing on the screen says why. SIGQUIT
// is the same. Before, the code caught only SIGTERM and SIGHUP.
//
// The restore must occur in the process that is about to die. Thus the
// seat half runs as a child. The pty stays open here. After the child is
// gone, this side reads back the tty and the exit status of the child.
func TestInterruptRestoresTheTerminalAndStillDies(t *testing.T) {
	cases := []struct {
		sig syscall.Signal
		// signaled says that the signal itself should kill the process. The
		// default of SIGINT is exactly that. In a Go program, the default of
		// SIGQUIT belongs to the runtime, which prints a goroutine dump and
		// exits 2. A reset to that default still gives the signal back its
		// meaning. Thus this side can only require that the seat died and did
		// not continue.
		signaled bool
	}{{syscall.SIGINT, true}, {syscall.SIGQUIT, false}}
	for _, tc := range cases {
		sig := tc.sig
		t.Run(sig.String(), func(t *testing.T) {
			_, path := newPTY(t)
			watcher, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
			if err != nil {
				t.Skip("open slave:", err)
			}
			defer watcher.Close()
			var before syscall.Termios
			if err := ioctl(watcher.Fd(), syscall.TCGETS, unsafe.Pointer(&before)); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=TestSeatKilledBySignal", "-test.timeout=60s")
			cmd.Env = append(os.Environ(), signalSlaveEnv+"="+path, "PF_TUI_SIGNAL="+sig.String())
			runErr := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(runErr, &ee) {
				t.Fatalf("seat child exited %v, want death by %s", runErr, sig)
			}
			if tc.signaled {
				ws, ok := ee.Sys().(syscall.WaitStatus)
				if !ok || !ws.Signaled() || ws.Signal() != sig {
					t.Fatalf("seat child exited %v; the signal's meaning was swallowed", ee)
				}
			}
			var after syscall.Termios
			if err := ioctl(watcher.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
				t.Fatal(err)
			}
			if after.Lflag&(syscall.ECHO|syscall.ICANON) != before.Lflag&(syscall.ECHO|syscall.ICANON) {
				t.Fatalf("tty left raw after %s: lflag %#x -> %#x", sig, before.Lflag, after.Lflag)
			}
		})
	}
}

// TestSeatKilledBySignal is the child half of the test above. It is a seat
// in raw mode that gets killed. It does nothing unless the parent gives it
// a pty.
func TestSeatKilledBySignal(t *testing.T) {
	path := os.Getenv(signalSlaveEnv)
	if path == "" {
		t.Skip("child half of TestInterruptRestoresTheTerminalAndStillDies")
	}
	sig := syscall.SIGINT
	if os.Getenv("PF_TUI_SIGNAL") == syscall.SIGQUIT.String() {
		sig = syscall.SIGQUIT
	}
	in, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	term := &linuxTerm{in: in, out: in}
	if err := term.EnterRaw(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	// The code reaches this only if it caught the signal and then dropped
	// it. That is its own failure: the kill of the operator did nothing.
	time.Sleep(10 * time.Second)
	t.Fatal("still alive after", sig)
}
