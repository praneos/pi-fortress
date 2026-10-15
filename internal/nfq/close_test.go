package nfq

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

// idleQueue is a Queue on a netfilter netlink socket that is bound to no
// queue. Nothing arrives on it. For Recv, this is an idle house. It does
// not need root. The queue bind of Open needs root.
func idleQueue(t *testing.T) *Queue {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		t.Skipf("netlink bind: %v", err)
	}
	if err := setRecvWait(fd); err != nil {
		syscall.Close(fd)
		t.Fatal(err)
	}
	return &Queue{fd: fd, num: 7}
}

// Close on an idle queue ends a Recv that waits for a packet. Before,
// Close waited for the next packet, and pf dns stopped responding on
// stop until systemd killed it.
func TestCloseEndsAnIdleRecv(t *testing.T) {
	q := idleQueue(t)
	got := make(chan error, 1)
	go func() {
		_, err := q.Recv()
		got <- err
	}()
	time.Sleep(100 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- q.Close() }()
	deadline := time.After(3 * recvWait)
	for range 2 {
		select {
		case err := <-got:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("Recv after Close: %v, want ErrClosed", err)
			}
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("Close did not end the Recv waiting on an idle queue")
		}
	}
	// A judge that finishes after the stop must not write to the fd.
	// The number of the fd can now name a different file.
	if err := q.Verdict(1, Drop, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verdict after Close: %v, want ErrClosed", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
