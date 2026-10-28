package netgate

// wire.go is the message format. It has pure functions and no socket.
// Thus a test, and a fuzz target, can give it any bytes.
//
// Each message is one SOCK_SEQPACKET record, so the kernel keeps the
// edges of each message. The first byte is the verb. All integers are
// big-endian. Each message has a fixed layout. A message with a length
// or a field that its verb does not allow is a protocol error, and the
// receiver closes the connection.

import (
	"errors"
	"fmt"
	"net/netip"

	"pi-fortress/internal/gateset"
)

// Verbs: the first byte of each message.
const (
	verbGate  = 'G' // client -> netgate: a gate set write
	verbReply = 'R' // netgate -> client: the result of a request
)

// Operations of a GATE request.
const (
	opAdd     = 1 // gateset.Cmd.Add
	opRefresh = 2 // gateset.Cmd.Refresh
)

// Status of a reply.
const (
	statusOK      = 0
	statusRefused = 1 // a check of netgate refused the request
	statusFailed  = 2 // the request passed the checks, and the work failed
)

const (
	// gateHead is the fixed part of a GATE request:
	//
	//	0      'G'
	//	1      op (opAdd, opRefresh)
	//	2      n, the number of addresses, 0 to gateset.MaxA
	//	3      0
	//	4:36   set name, NUL padded
	//	36:    n IPv4 addresses, 4 bytes each
	gateHead = 4 + maxSetName
	// maxGate is the largest GATE request.
	maxGate = gateHead + 4*gateset.MaxA
	// maxReplyText limits the reason in a reply:
	//
	//	0   'R'
	//	1   status
	//	2:  reason, at most maxReplyText bytes, empty when ok
	maxReplyText = 200
)

var errProto = errors.New("netgate: protocol error")

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errProto}, args...)...)
}

// gateReq is one GATE request.
type gateReq struct {
	op    byte
	set   string
	addrs []netip.Addr
}

// encodeGate builds a GATE request. Each address must be IPv4.
func encodeGate(r gateReq) ([]byte, error) {
	if r.op != opAdd && r.op != opRefresh {
		return nil, fmt.Errorf("netgate: GATE op %d", r.op)
	}
	if r.set == "" || len(r.set) > maxSetName {
		return nil, fmt.Errorf("netgate: set name %q does not fit a GATE request", r.set)
	}
	if len(r.addrs) > gateset.MaxA {
		return nil, fmt.Errorf("netgate: %d addresses in one GATE request, the limit is %d", len(r.addrs), gateset.MaxA)
	}
	b := make([]byte, gateHead, gateHead+4*len(r.addrs))
	b[0], b[1], b[2] = verbGate, r.op, byte(len(r.addrs))
	copy(b[4:gateHead], r.set)
	for _, a := range r.addrs {
		if !a.Is4() {
			return nil, fmt.Errorf("netgate: %s is not IPv4", a)
		}
		v := a.As4()
		b = append(b, v[:]...)
	}
	return b, nil
}

// decodeGate reads a GATE request. It refuses each form that encodeGate
// does not make. Thus one request has exactly one encoding.
func decodeGate(b []byte) (gateReq, error) {
	if len(b) < gateHead || b[0] != verbGate {
		return gateReq{}, protoErr("GATE request of %d bytes", len(b))
	}
	op, n := b[1], int(b[2])
	if op != opAdd && op != opRefresh {
		return gateReq{}, protoErr("GATE op %d", op)
	}
	if n > gateset.MaxA || b[3] != 0 || len(b) != gateHead+4*n {
		return gateReq{}, protoErr("GATE request of %d bytes for %d addresses", len(b), n)
	}
	name := b[4:gateHead]
	end := 0
	for end < len(name) && name[end] != 0 {
		end++
	}
	for _, c := range name[end:] {
		if c != 0 {
			return gateReq{}, protoErr("GATE set name has bytes after its end")
		}
	}
	if end == 0 {
		return gateReq{}, protoErr("GATE set name is empty")
	}
	r := gateReq{op: op, set: string(name[:end]), addrs: make([]netip.Addr, 0, n)}
	for i := gateHead; i < len(b); i += 4 {
		r.addrs = append(r.addrs, netip.AddrFrom4([4]byte(b[i:i+4])))
	}
	return r, nil
}

// encodeReply builds a reply. The reason is cut to maxReplyText bytes.
func encodeReply(status byte, reason string) []byte {
	if len(reason) > maxReplyText {
		reason = reason[:maxReplyText]
	}
	return append([]byte{verbReply, status}, reason...)
}

// decodeReply reads a reply.
func decodeReply(b []byte) (byte, string, error) {
	if len(b) < 2 || b[0] != verbReply || len(b) > 2+maxReplyText {
		return 0, "", protoErr("reply of %d bytes", len(b))
	}
	if b[1] > statusFailed {
		return 0, "", protoErr("reply status %d", b[1])
	}
	return b[1], string(b[2:]), nil
}

// replyErr is the error of a reply that is not ok.
func replyErr(status byte, reason string) error {
	if status == statusOK {
		return nil
	}
	if status == statusRefused {
		return fmt.Errorf("netgate refused: %s", reason)
	}
	return fmt.Errorf("netgate: %s", reason)
}
