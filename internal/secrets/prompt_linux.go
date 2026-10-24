//go:build linux

package secrets

import (
	"syscall"
	"unsafe"
)

// The code drives termios through syscall directly, not through
// x/term. x/term would be a second module for two ioctls.
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
