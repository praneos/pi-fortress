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
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"pi-fortress/internal/gateset"
	"pi-fortress/internal/nfq"
)

// Verbs: the first byte of each message.
const (
	verbGate    = 'G' // client -> netgate: a gate set write
	verbReply   = 'R' // netgate -> client: the result of a request
	verbSNI     = 'S' // pf dns -> netgate: relay this SNI queue to me
	verbPacket  = 'P' // netgate -> pf dns: one queued packet
	verbVerdict = 'V' // pf dns -> netgate: the verdict for one packet
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

// The SNI marks: bits 20-23 of the packet mark (internal/render, houseSNI).
// A Repeat verdict carries ok or bad in them. netgate sets only these
// bits. It keeps the other bits of the mark of the packet as the kernel
// gave them (the WireGuard bypass bit).
const (
	SNIBits = 0x00f00000
	SNIOK   = 0x00200000
	SNIBad  = 0x00300000
)

// The SNI bits of a verdict, as one byte on the wire.
const (
	bitsNone = 0 // Drop or Accept: the mark does not change
	bitsOK   = 1 // Repeat with SNIOK
	bitsBad  = 2 // Repeat with SNIBad
)

const (
	// sniHelloLen is an SNI request, the first message of a connection
	// that then carries the relay:
	//
	//	0     'S'
	//	1     0
	//	2:4   queue number
	sniHelloLen = 4
	// packetHead is the fixed part of a packet message:
	//
	//	0      'P'
	//	1:4    0
	//	4:8    packet id
	//	8:12   mark
	//	12:    payload, the copy that the kernel gave (copy range 0xffff)
	packetHead = 12
	maxPayload = 0xffff
	maxPacket  = packetHead + maxPayload
	// verdictLen is a verdict message:
	//
	//	0     'V'
	//	1     verdict: nfq.Drop, nfq.Accept or nfq.Repeat
	//	2     bits: bitsNone, bitsOK or bitsBad
	//	3     0
	//	4:8   packet id
	verdictLen = 8
)

func encodeSNIHello(queue uint16) []byte {
	b := []byte{verbSNI, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:4], queue)
	return b
}

func decodeSNIHello(b []byte) (uint16, error) {
	if len(b) != sniHelloLen || b[0] != verbSNI || b[1] != 0 {
		return 0, protoErr("SNI request of %d bytes", len(b))
	}
	q := binary.BigEndian.Uint16(b[2:4])
	if q == 0 {
		return 0, protoErr("SNI request for queue 0")
	}
	return q, nil
}

func encodePacket(p nfq.Packet) ([]byte, error) {
	if len(p.Payload) > maxPayload {
		return nil, fmt.Errorf("netgate: packet %d has %d bytes", p.ID, len(p.Payload))
	}
	b := make([]byte, packetHead, packetHead+len(p.Payload))
	b[0] = verbPacket
	binary.BigEndian.PutUint32(b[4:8], p.ID)
	binary.BigEndian.PutUint32(b[8:12], p.Mark)
	return append(b, p.Payload...), nil
}

// decodePacket reads a packet message. The payload is a copy: the caller
// reads the next message into the same buffer.
func decodePacket(b []byte) (nfq.Packet, error) {
	if len(b) < packetHead || len(b) > maxPacket || b[0] != verbPacket || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return nfq.Packet{}, protoErr("packet message of %d bytes", len(b))
	}
	return nfq.Packet{
		ID:      binary.BigEndian.Uint32(b[4:8]),
		Mark:    binary.BigEndian.Uint32(b[8:12]),
		Payload: append([]byte(nil), b[packetHead:]...),
	}, nil
}

// verdict is one verdict message.
type verdict struct {
	id      uint32
	verdict uint32
	bits    byte
}

// valid: Drop and Accept leave the mark as it is. Repeat sends the packet
// back into forward with ok or bad in the SNI bits, which ends its wait
// (render, houseSNI). A Repeat with no SNI bit would put the packet back
// in the queue, so it is refused.
func (v verdict) valid() bool {
	switch v.verdict {
	case nfq.Drop, nfq.Accept:
		return v.bits == bitsNone
	case nfq.Repeat:
		return v.bits == bitsOK || v.bits == bitsBad
	}
	return false
}

func encodeVerdict(v verdict) ([]byte, error) {
	if !v.valid() {
		return nil, fmt.Errorf("netgate: verdict %d with SNI bits %d", v.verdict, v.bits)
	}
	b := []byte{verbVerdict, byte(v.verdict), v.bits, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:8], v.id)
	return b, nil
}

func decodeVerdict(b []byte) (verdict, error) {
	if len(b) != verdictLen || b[0] != verbVerdict || b[3] != 0 {
		return verdict{}, protoErr("verdict message of %d bytes", len(b))
	}
	v := verdict{id: binary.BigEndian.Uint32(b[4:8]), verdict: uint32(b[1]), bits: b[2]}
	if !v.valid() {
		return verdict{}, protoErr("verdict %d with SNI bits %d", v.verdict, v.bits)
	}
	return v, nil
}

// mark is the mark that a Repeat verdict gives a packet that came with
// old: old with only its SNI bits replaced. nil for Drop and Accept,
// which keep the mark.
func (v verdict) mark(old uint32) *uint32 {
	if v.verdict != nfq.Repeat {
		return nil
	}
	m := old &^ SNIBits
	if v.bits == bitsOK {
		m |= SNIOK
	} else {
		m |= SNIBad
	}
	return &m
}
