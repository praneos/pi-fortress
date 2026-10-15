package nfq

// queue.go is the only file that uses a socket. All other files are pure
// encode/decode. Thus unit tests need no root and no live NFQUEUE.

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"
)

// ErrClosed is Recv or Verdict on a Queue that Close has closed.
var ErrClosed = errors.New("nfq: queue closed")

// logf is where Recv reports what it skips. It is a var so a test can see it.
var logf = log.Printf

// recvWait limits one Recvfrom. When the code closes the fd, a read that is
// blocked in the kernel does not wake up. Without recvWait, a Close on an
// idle queue waited for the next packet. When pf dns stopped with no house
// TLS flow in progress, it stopped responding until systemd killed it 90 s later.
const recvWait = 250 * time.Millisecond

// Open binds queue num with copy mode packet (range 0xffff) and flags
// NFQA_CFG_F_GSO. No FAIL_OPEN: when no caller reads, the kernel drops
// (the caller relies on fail-closed).
func Open(num uint16) (*Queue, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nfq: socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("nfq: bind: %w", err)
	}
	// Best effort: a full kernel socket buffer causes ENOBUFS packet
	// drops (Recv handles them). It is not a fatal error here.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)

	q := &Queue{fd: fd, num: num}

	// PF_UNBIND then PF_BIND: a no-op on modern kernels (protocol families
	// register automatically). Old kernels need it for a clean queue
	// handoff. The code ignores errors on both.
	q.sendConfig(cfgFields{cmd: cfgCmdPfUnbind, pf: afInet}, true)
	q.sendConfig(cfgFields{cmd: cfgCmdPfBind, pf: afInet}, true)

	if err := q.sendConfig(cfgFields{cmd: cfgCmdBind, pf: afInet}, false); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("nfq: bind queue %d: %w", num, err)
	}
	if err := q.sendConfig(cfgFields{copyMode: copyPacket, copyRange: 0xffff}, false); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("nfq: set copy mode: %w", err)
	}
	gso := uint32(cfgFGSO)
	if err := q.sendConfig(cfgFields{flags: &gso}, false); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("nfq: set flags: %w", err)
	}
	// Queue depth cap: best effort. Not all kernel paths obey it the
	// same way. If it fails, the kernel default applies.
	maxlen := uint32(1024)
	q.sendConfig(cfgFields{maxlen: &maxlen}, true)

	// After the config steps. The code reads their acks with no deadline.
	if err := setRecvWait(fd); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return q, nil
}

func setRecvWait(fd int) error {
	tv := syscall.NsecToTimeval(recvWait.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("nfq: receive timeout: %w", err)
	}
	return nil
}

// sendConfig sends one NFQNL_MSG_CONFIG message and waits for its ack.
// ignoreErr ignores the send/recv error and a nonzero-errno ack. It is for
// steps that only old kernels need, which do not have them.
func (q *Queue) sendConfig(f cfgFields, ignoreErr bool) error {
	msg := encodeConfig(q.nextSeq(), q.num, f)
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(q.fd, msg, 0, dst); err != nil {
		if ignoreErr {
			return nil
		}
		return fmt.Errorf("nfq: send config: %w", err)
	}
	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(q.fd, buf, 0)
	if err != nil {
		if ignoreErr {
			return nil
		}
		return fmt.Errorf("nfq: recv ack: %w", err)
	}
	if _, err := parseMessages(buf[:n]); err != nil && !ignoreErr {
		return err
	}
	return nil
}

func (q *Queue) nextSeq() uint32 {
	q.mu.Lock()
	q.seq++
	s := q.seq
	q.mu.Unlock()
	return s
}

// Recv blocks for the next packet. It skips non-packet netlink messages.
// It logs and skips an NLMSG_ERROR with nonzero errno (an asynchronous
// verdict error, parseRecv). It uses ENOBUFS as "continue" (log nothing;
// the kernel dropped some packets). A malformed message is an error. Recv
// returns it after it gives out the packets that it decoded before the
// message in the same read.
func (q *Queue) Recv() (Packet, error) {
	buf := make([]byte, 65536+4096) // room for a full-size IPv4 payload plus headers/attrs
	for {
		if len(q.pending) > 0 {
			p := q.pending[0]
			q.pending = q.pending[1:]
			return p, nil
		}
		if q.pendingErr != nil {
			err := q.pendingErr
			q.pendingErr = nil
			return Packet{}, err
		}
		if q.stopping.Load() {
			return Packet{}, ErrClosed
		}
		q.life.RLock()
		if q.closed {
			q.life.RUnlock()
			return Packet{}, ErrClosed
		}
		n, _, err := syscall.Recvfrom(q.fd, buf, 0)
		q.life.RUnlock()
		if err != nil {
			if err == syscall.ENOBUFS || err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return Packet{}, fmt.Errorf("nfq: recv: %w", err)
		}
		pkts, nlErrs, err := parseRecv(buf[:n])
		for _, e := range nlErrs {
			logf("nfq: queue %d: %v (a verdict the kernel refused; skipped)", q.num, e)
		}
		q.pending, q.pendingErr = pkts, err
	}
}

// Verdict sends NFQNL_MSG_VERDICT for id. mark != nil also sends NFQA_MARK.
// Many goroutines can call it safely at the same time as Recv. Sequence
// allocation is the only shared state, and a mutex guards it. Each verdict
// is one complete datagram write. The kernel does not interleave it with
// other writes on the same socket.
func (q *Queue) Verdict(id uint32, verdict uint32, mark *uint32) error {
	msg := encodeVerdict(q.nextSeq(), q.num, id, verdict, mark)
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	q.life.RLock()
	defer q.life.RUnlock()
	if q.closed {
		return ErrClosed
	}
	if err := syscall.Sendto(q.fd, msg, 0, dst); err != nil {
		return fmt.Errorf("nfq: verdict: %w", err)
	}
	return nil
}

// Close closes the netlink socket. The kernel unbinds the queue when the
// owner fd closes, and drops what it still held (fail closed). All
// goroutines can call it, more than one time. It waits for a Recv in
// progress, a maximum of recvWait, and for each Verdict in progress.
func (q *Queue) Close() error {
	q.stopping.Store(true)
	q.life.Lock()
	defer q.life.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	return syscall.Close(q.fd)
}
