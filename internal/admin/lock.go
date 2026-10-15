package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrLocked = errors.New("another apply is running")

type Lock struct{ fd int }

// TryLock takes an exclusive, non-blocking flock on path. The code opens the
// descriptor without CLOEXEC intentionally. pf apply execs apply.sh, and the
// lock must live as long as the script. TryLock refuses a symlink at path
// and does not follow it.
func TryLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0640)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: is a symlink", path)
		}
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &Lock{fd: fd}, nil
}

func (l *Lock) Release() {
	if l != nil && l.fd >= 0 {
		syscall.Close(l.fd)
		l.fd = -1
	}
}

// Held reports whether a process holds the apply lock. It finds this by
// inode in /proc/locks, and does not take the lock. A probe with flock would
// make a concurrent apply fail falsely for the length of the probe.
func Held(path string) bool {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return false
	}
	raw, err := os.ReadFile("/proc/locks")
	if err != nil {
		return false
	}
	want := fmt.Sprintf(":%d ", st.Ino)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, " FLOCK ") && strings.Contains(line, " WRITE ") && strings.Contains(line, want) {
			return true
		}
	}
	return false
}
