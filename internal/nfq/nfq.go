// Package nfq is a minimal Linux NFQUEUE client. It binds a queue, receives
// the packets that a nftables/iptables NFQUEUE rule sends to it, and returns
// a verdict. It uses only the standard library: no cgo, no netlink helper
// library. The wire format is small, so the code encodes it manually. A
// dependency is not worth it for a few hundred bytes of nlattr framing.
package nfq

import (
	"sync"
	"sync/atomic"
)

// Netfilter verdicts (linux/netfilter.h), not specific to NFQUEUE.
const (
	Drop   = 0 // NF_DROP
	Accept = 1 // NF_ACCEPT
	Repeat = 4 // NF_REPEAT: re-inject at the start of the same hook
)

// Packet is one packet that the kernel gives for a verdict.
type Packet struct {
	ID      uint32 // packet id from NFQA_PACKET_HDR (host order after decoding)
	Mark    uint32 // NFQA_MARK, 0 if absent
	Payload []byte // NFQA_PAYLOAD: the full IPv4 packet (copied, safe to keep)
}

// Queue is one bound NFQUEUE instance: one netlink socket, one queue number.
// The config has no FAIL_OPEN flag. Thus, when no caller is in Recv, the
// kernel drops all packets sent to this queue. The caller relies on that
// fail-closed behavior. It does not use a switch on the queue.
type Queue struct {
	fd  int
	num uint16

	mu  sync.Mutex // guards seq: Verdict and Open's config steps share one counter
	seq uint32

	pending    []Packet // packets parsed out of the last Recvfrom, not yet returned
	pendingErr error    // a malformed message in that read, returned after pending

	// life guards the fd. Recv and Verdict hold it shared for one
	// syscall. Close holds it exclusively. Thus the code never closes
	// the fd during a syscall and never uses it after Close, when its
	// number can name a different file. stopping lets a Recv that waits
	// for its timeout see a Close that is queued behind it.
	life     sync.RWMutex
	closed   bool
	stopping atomic.Bool
}
