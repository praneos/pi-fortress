package secrets

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// ReadPassphrase reads one line from the terminal with echo disabled.
// It opens /dev/tty and does not read stdin. Thus a script or a file
// cannot pipe a passphrase in, and the passphrase cannot get into a
// shell history, a process listing or the environment of a unit. The
// bytes go from here into a KDF and to no other location: never to
// disk, never into an audit Args map.
//
// The code drives termios through syscall directly, not through
// x/term. x/term would be a second module for two ioctls.
func ReadPassphrase(prompt string, out io.Writer) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("secrets: no terminal to read a passphrase from")
	}
	defer tty.Close()
	fmt.Fprint(out, prompt)
	defer fmt.Fprintln(out)
	restore, err := echoOff(tty.Fd())
	if err != nil {
		return nil, err
	}
	defer restore()
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return []byte(line), nil
}

func echoOff(fd uintptr) (func(), error) {
	var t syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, &t); err != nil {
		return nil, err
	}
	old := t
	t.Lflag &^= syscall.ECHO
	t.Lflag |= syscall.ICANON | syscall.ISIG
	if err := ioctl(fd, syscall.TCSETS, &t); err != nil {
		return nil, err
	}
	return func() { _ = ioctl(fd, syscall.TCSETS, &old) }, nil
}

func ioctl(fd uintptr, req uint, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(unsafe.Pointer(t)), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// ConfirmNewPassphrase prompts two times. A mistyped passphrase on a
// store that is sealed for the first time loses all credentials
// in it.
func ConfirmNewPassphrase(out io.Writer) ([]byte, error) {
	first, err := ReadPassphrase("New passphrase: ", out)
	if err != nil {
		return nil, err
	}
	if len(first) < 8 {
		return nil, errors.New("secrets: passphrase must be at least 8 characters")
	}
	again, err := ReadPassphrase("Again: ", out)
	if err != nil {
		return nil, err
	}
	if string(first) != string(again) {
		return nil, errors.New("secrets: the two passphrases differ")
	}
	return first, nil
}
