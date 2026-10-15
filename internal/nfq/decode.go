package nfq

// decode.go parses inbound netlink messages: acks/errors and NFQUEUE packet
// messages. It has pure functions and no socket calls. Thus tests can give
// it hand-built or randomly truncated byte slices without root or a queue.

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// parseAttrs reads a TLV attribute stream (len, type, value, padded to 4
// bytes) into a type -> value map. It masks NLA_F_NESTED and
// NLA_F_NET_BYTEORDER out of the type before indexing. This code nests no
// attributes. The protocol sets the byte order of each field. No flag sets it.
func parseAttrs(b []byte) (map[uint16][]byte, error) {
	attrs := make(map[uint16][]byte)
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("nfq: truncated attribute header (%d bytes left)", len(b))
		}
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return nil, fmt.Errorf("nfq: truncated attribute: len %d, %d bytes left", l, len(b))
		}
		atype := binary.NativeEndian.Uint16(b[2:4]) & nlaTypeMask
		attrs[atype] = b[4:l]
		adv := nlaAlign(l)
		if adv > len(b) {
			adv = len(b) // final attribute in the buffer, no trailing pad present
		}
		b = b[adv:]
	}
	return attrs, nil
}

// parsePacket decodes the body of an NFQNL_MSG_PACKET message: an nfgenmsg
// and then attributes. It ignores unknown attributes.
func parsePacket(body []byte) (Packet, error) {
	if len(body) < nfgenmsgLen {
		return Packet{}, fmt.Errorf("nfq: truncated nfgenmsg (%d bytes)", len(body))
	}
	attrs, err := parseAttrs(body[nfgenmsgLen:])
	if err != nil {
		return Packet{}, err
	}
	var p Packet
	if hdr, ok := attrs[attrPacketHdr]; ok {
		if len(hdr) < 4 {
			return Packet{}, fmt.Errorf("nfq: truncated NFQA_PACKET_HDR (%d bytes)", len(hdr))
		}
		p.ID = binary.BigEndian.Uint32(hdr[0:4])
	}
	if m, ok := attrs[attrMark]; ok {
		if len(m) < 4 {
			return Packet{}, fmt.Errorf("nfq: truncated NFQA_MARK (%d bytes)", len(m))
		}
		p.Mark = binary.BigEndian.Uint32(m[0:4])
	}
	if pl, ok := attrs[attrPayload]; ok {
		p.Payload = append([]byte(nil), pl...) // copy: the recv buffer gets reused on the next read
	}
	return p, nil
}

// parseMessages reads one or more nlmsghdrs in buf (one Recvfrom can return
// more than one) and returns the NFQUEUE packets in them. An NLMSG_ERROR with
// errno 0 is a plain ack. The function drops it silently. For a nonzero
// errno, it returns an error that wraps the syscall.Errno. Thus callers can
// use errors.Is on it. It skips all other messages (NLMSG_DONE, other
// subsystems). They are not errors. A malformed message returns an error and
// the packets that it already decoded. It does not panic.
func parseMessages(buf []byte) ([]Packet, error) {
	return walkMessages(buf, nil)
}

// parseRecv is parseMessages for Recv. Recv waits for no NLMSG_ERROR as an
// answer. Verdicts go out without NLM_F_ACK. Thus an NLMSG_ERROR that
// arrives is the kernel that refuses an earlier verdict, asynchronously
// (ENOENT for a packet id that it does not hold now). parseRecv returns it
// in nlErrs and continues. Thus it keeps the packets in the same read. It
// does not lose them in a queue restart that drops all flows still held.
func parseRecv(buf []byte) (pkts []Packet, nlErrs []error, err error) {
	pkts, err = walkMessages(buf, func(e error) { nlErrs = append(nlErrs, e) })
	return pkts, nlErrs, err
}

// walkMessages is the walk that the two functions share. If skip is nil,
// it returns at the first nonzero NLMSG_ERROR. If not, that error goes to
// skip and the walk continues.
func walkMessages(buf []byte, skip func(error)) ([]Packet, error) {
	var pkts []Packet
	for len(buf) > 0 {
		if len(buf) < nlmsgHdrLen {
			return pkts, fmt.Errorf("nfq: truncated nlmsghdr (%d bytes)", len(buf))
		}
		msgLen := binary.NativeEndian.Uint32(buf[0:4])
		msgType := binary.NativeEndian.Uint16(buf[4:6])
		if msgLen < nlmsgHdrLen || int(msgLen) > len(buf) {
			return pkts, fmt.Errorf("nfq: truncated netlink message: len %d, %d bytes left", msgLen, len(buf))
		}
		body := buf[nlmsgHdrLen:msgLen]
		switch msgType {
		case syscall.NLMSG_ERROR:
			if len(body) < 4 {
				return pkts, fmt.Errorf("nfq: truncated NLMSG_ERROR")
			}
			if errno := int32(binary.NativeEndian.Uint32(body[0:4])); errno != 0 {
				nlErr := fmt.Errorf("nfq: netlink: %w", syscall.Errno(-errno))
				if skip == nil {
					return pkts, nlErr
				}
				skip(nlErr)
			}
		case nfqMsgType(msgPacket):
			p, err := parsePacket(body)
			if err != nil {
				return pkts, err
			}
			pkts = append(pkts, p)
		}
		adv := nlaAlign(int(msgLen))
		if adv > len(buf) {
			adv = len(buf) // last message, no trailing pad present
		}
		buf = buf[adv:]
	}
	return pkts, nil
}
