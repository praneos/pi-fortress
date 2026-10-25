package admin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The lock helper is this test binary, run again with these variables set.
const (
	lockHelperMode = "PF_TEST_LOCK_HELPER"
	lockHelperPath = "PF_TEST_LOCK_PATH"
	lockHelperFD   = "PF_TEST_LOCK_FD"
)

// lockHelper starts the test binary again as a helper in mode. It returns
// the started command, its stdin and the first line it wrote.
func lockHelper(t *testing.T, mode, path string, fd int) (*exec.Cmd, io.WriteCloser, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		lockHelperMode+"="+mode,
		lockHelperPath+"="+path,
		lockHelperFD+"="+strconv.Itoa(fd))
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
		_, _ = io.Copy(io.Discard, out)
	}()
	select {
	case s := <-line:
		return cmd, in, s
	case <-time.After(30 * time.Second):
		t.Fatalf("lock helper %s wrote nothing", mode)
	}
	return nil, nil, ""
}

// TestLockHelperProcess is not a test of its own. TestLockHandoffToChild
// runs it in a child process. In the "hold" mode, it checks that the lock
// descriptor came through exec, says "ready" and keeps the descriptor open
// until its stdin closes. In the "try" mode, it tries to take the lock and
// says "locked" or "free".
func TestLockHelperProcess(t *testing.T) {
	mode := os.Getenv(lockHelperMode)
	if mode == "" {
		t.Skip("runs only as a child of TestLockHandoffToChild")
	}
	path := os.Getenv(lockHelperPath)
	switch mode {
	case "hold":
		fd, err := strconv.Atoi(os.Getenv(lockHelperFD))
		if err != nil {
			fmt.Println("fail: no descriptor number")
			os.Exit(1)
		}
		var got, want syscall.Stat_t
		if err := syscall.Fstat(fd, &got); err != nil {
			fmt.Printf("fail: descriptor %d is not open in the child: %v\n", fd, err)
			os.Exit(1)
		}
		if err := syscall.Stat(path, &want); err != nil || got.Dev != want.Dev || got.Ino != want.Ino {
			fmt.Printf("fail: descriptor %d is not the lock file\n", fd)
			os.Exit(1)
		}
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	case "try":
		l, err := TryLock(path)
		switch {
		case errors.Is(err, ErrLocked):
			fmt.Println("locked")
		case err != nil:
			fmt.Println("fail:", err)
		default:
			l.Release()
			fmt.Println("free")
		}
		return
	}
	fmt.Println("fail: unknown mode", mode)
	os.Exit(1)
}

// pf apply takes the lock and then execs apply.sh. The lock must stay
// held for as long as apply.sh runs. Thus the descriptor must not have
// close-on-exec, and the child must hold the lock after pf lets go of
// its own copy.
func TestLockHandoffToChild(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	path := filepath.Join(t.TempDir(), "apply.lock")
	l, err := TryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(l.fd), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags&syscall.FD_CLOEXEC != 0 {
		t.Fatal("the lock descriptor has close-on-exec; apply.sh would not hold the lock")
	}

	_, in, got := lockHelper(t, "hold", path, l.fd)
	if got != "ready" {
		t.Fatalf("child: %s", got)
	}
	// From here the child alone holds the lock, as after the exec of pf.
	l.Release()
	if _, _, got := lockHelper(t, "try", path, -1); got != "locked" {
		t.Fatalf("a third process got %q while the child ran, want locked", got)
	}
	if !Held(path) {
		t.Fatal("Held is false while the child holds the lock")
	}

	// The lock goes when the child exits.
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for Held(path) {
		if time.Now().After(deadline) {
			t.Fatal("the lock stayed held after the child closed its stdin")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, got := lockHelper(t, "try", path, -1); got != "free" {
		t.Fatalf("a third process got %q after the child exited, want free", got)
	}
}
