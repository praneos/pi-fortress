package tui

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

type linuxTerm struct {
	in, out *os.File
	// mu guards raw and the two signal channels. The death watcher
	// touches them from its own goroutine.
	mu    sync.Mutex
	saved syscall.Termios
	raw   bool
	src   *byteSource
	winch chan os.Signal
	death chan os.Signal
	// Restore closes wake. A read on a tty does not end when the loop that
	// wanted it is gone. A restore of the termios does not end it either.
	// Thus, without wake, the app could not get its key goroutine back. It
	// could only return and leave the goroutine there.
	wake chan struct{}
}

// Open wraps stdin and stdout; both must be terminals.
func Open(in, out *os.File) (Terminal, error) {
	if !IsTerminal(in.Fd()) || !IsTerminal(out.Fd()) {
		return nil, errors.New("pf tui needs a terminal on stdin and stdout")
	}
	return &linuxTerm{in: in, out: out}, nil
}

func ioctl(fd uintptr, req uint, arg unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

func IsTerminal(fd uintptr) bool {
	var t syscall.Termios
	return ioctl(fd, syscall.TCGETS, unsafe.Pointer(&t)) == nil
}

func (t *linuxTerm) Size() (int, int) {
	var ws struct{ Row, Col, X, Y uint16 }
	if ioctl(t.out.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)) != nil || ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

// deathSignals are the ways that a seat ends from outside the key loop.
// Raw mode is a property of the tty and lives longer than the process. If
// the seat dies under one of them without a restore of the tty, the
// operator gets a terminal with no echo, no line editing and the alternate
// screen still on. Nothing on it says why.
//
// SIGTERM and SIGHUP are systemctl stop, a closed ssh session, a reboot.
// SIGINT and SIGQUIT are the other half, and were missing. Raw mode clears
// ISIG, so the Ctrl-C of the seat itself arrives as a key. But an operator
// could type kill -INT on the pf process from a different shell. Or their
// Ctrl-C could arrive before EnterRaw, or arrive on the process group from
// a parent shell. Then the terminal of the operator broke, and they could
// not know the cause.
var deathSignals = []os.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT}

func (t *linuxTerm) EnterRaw() error {
	if err := ioctl(t.in.Fd(), syscall.TCGETS, unsafe.Pointer(&t.saved)); err != nil {
		return err
	}
	raw := t.saved
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0
	if err := ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		return err
	}
	t.mu.Lock()
	t.raw = true
	t.wake = make(chan struct{})
	t.src = newByteSource(t.in, t.wake)
	t.winch = make(chan os.Signal, 1)
	signal.Notify(t.winch, syscall.SIGWINCH)
	t.death = make(chan os.Signal, 1)
	signal.Notify(t.death, deathSignals...)
	go t.watchDeath(t.death)
	t.mu.Unlock()
	if err := t.Write([]byte("\x1b[?1049h\x1b[?25l" + pasteOn + "\x1b[H\x1b[2J")); err != nil {
		// The caller has no Restore installed yet, because it waits on
		// this return. Thus the tty gets its restore here or not at all.
		t.Restore()
		return err
	}
	return nil
}

// watchDeath restores the tty and lets the signal do what it would have
// done. Thus the exit status still says that the process was terminated.
func (t *linuxTerm) watchDeath(ch chan os.Signal) {
	s, ok := <-ch
	if !ok {
		return
	}
	t.Restore()
	signal.Reset(s)
	if sig, ok := s.(syscall.Signal); ok {
		_ = syscall.Kill(syscall.Getpid(), sig)
	}
}

func (t *linuxTerm) Restore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.raw {
		return
	}
	t.raw = false
	// Released before all else: a caller that waits to join its key
	// goroutine is the one that will see the rest of this.
	close(t.wake)
	signal.Stop(t.winch)
	if t.death != nil {
		// Stop first: when the notifier is gone, nothing can send. Thus the
		// close releases the watcher, and does not race with it.
		signal.Stop(t.death)
		close(t.death)
		t.death = nil
	}
	// Each exit comes here: q, idle, end of input, a panic that unwinds Run
	// and a signal (watchDeath). A shell that gets the tty with bracketed
	// paste still on would read the brackets of the next paste as text.
	_ = t.Write([]byte(pasteOff + "\x1b[0m\x1b[?25h\x1b[?1049l"))
	_ = ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&t.saved))
}

func (t *linuxTerm) Write(p []byte) error {
	_, err := t.out.Write(p)
	return err
}

func (t *linuxTerm) ReadKey() (Key, error) {
	if t.src == nil {
		return Key{}, io.EOF
	}
	// The loop skips the paste brackets: they are not keys.
	for {
		if b, ok := t.src.pending(); ok {
			if k, ok := t.src.key(b); ok {
				return k, nil
			}
			continue
		}
		select {
		case b := <-t.src.ch:
			if k, ok := t.src.key(b); ok {
				return k, nil
			}
		case <-t.winch:
			return Key{Kind: KeyResize}, nil
		case err := <-t.src.err:
			return Key{}, err
		case <-t.src.pasteWait():
			// No byte for pasteGap: the paste is over.
			t.src.pasting = false
		case <-t.wake:
			// Restored: there is no tty to read from now, and the caller
			// waits for this goroutine, not for a keystroke.
			return Key{}, io.EOF
		}
	}
}
