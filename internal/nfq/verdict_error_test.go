package nfq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func mkPacketMsg(id uint32) []byte {
	body := append(mkNfgenmsg(afInet, 1), mkAttr(attrPacketHdr, mkPacketHdr(id, 0x0800, 0))...)
	return mkNlmsg(nfqMsgType(msgPacket), 0, id, body)
}

func mkErrMsg(errno syscall.Errno) []byte {
	body := make([]byte, 4+16)
	e := int32(errno)
	binary.NativeEndian.PutUint32(body[0:4], uint32(-e))
	return mkNlmsg(syscall.NLMSG_ERROR, 0, 9, body)
}

// A verdict that the kernel refuses comes back as an NLMSG_ERROR between
// packets. Before, it ended the read with an error that restarted the
// queue. That lost the packets beside it and all flows the kernel held.
func TestParseRecvSkipsVerdictErrorsAndKeepsPackets(t *testing.T) {
	buf := append(append(mkPacketMsg(1), mkErrMsg(syscall.ENOENT)...), mkPacketMsg(2)...)
	pkts, nlErrs, err := parseRecv(buf)
	if err != nil {
		t.Fatalf("parseRecv: %v", err)
	}
	if len(pkts) != 2 || pkts[0].ID != 1 || pkts[1].ID != 2 {
		t.Fatalf("packets %+v, want ids 1 and 2", pkts)
	}
	if len(nlErrs) != 1 || !errors.Is(nlErrs[0], syscall.ENOENT) {
		t.Fatalf("nlErrs %v, want one ENOENT", nlErrs)
	}
	// The config path still fails on the same error.
	if _, err := parseMessages(buf); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("parseMessages: %v, want ENOENT", err)
	}
}

// pairQueue is a Queue with an fd that is one end of a datagram socketpair.
// Thus a test writes exactly the bytes that one Recvfrom returns.
func pairQueue(t *testing.T) (*Queue, int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	if err := setRecvWait(fds[0]); err != nil {
		t.Fatal(err)
	}
	q := &Queue{fd: fds[0], num: 7}
	t.Cleanup(func() { q.Close(); syscall.Close(fds[1]) })
	return q, fds[1]
}

func TestRecvLogsAVerdictErrorAndDeliversBothPackets(t *testing.T) {
	var logged []string
	old := logf
	logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { logf = old })
	q, peer := pairQueue(t)
	buf := append(append(mkPacketMsg(1), mkErrMsg(syscall.ENOENT)...), mkPacketMsg(2)...)
	if _, err := syscall.Write(peer, buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint32{1, 2} {
		p, err := q.Recv()
		if err != nil || p.ID != want {
			t.Fatalf("Recv = %+v, %v; want id %d", p, err, want)
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "queue 7") || !strings.Contains(logged[0], syscall.ENOENT.Error()) {
		t.Fatalf("logged %q", logged)
	}
}

// A malformed message still ends Recv, but only after Recv gives out the
// packets that came before it in the same read.
func TestRecvDeliversPacketsBeforeAMalformedMessage(t *testing.T) {
	q, peer := pairQueue(t)
	buf := append(mkPacketMsg(1), 0xff, 0xff)
	if _, err := syscall.Write(peer, buf); err != nil {
		t.Fatal(err)
	}
	if p, err := q.Recv(); err != nil || p.ID != 1 {
		t.Fatalf("Recv = %+v, %v; want id 1", p, err)
	}
	if _, err := q.Recv(); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("Recv after the packet: %v, want the truncation error", err)
	}
}
