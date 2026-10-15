package nfq

// encode.go builds outgoing netlink messages. It has no socket calls. Thus
// unit tests can use plain byte slices.

import (
	"encoding/binary"
	"syscall"
)

// nlaAlign rounds n up to the next 4-byte boundary (NLA_ALIGNTO). nlattrs
// and full netlink messages pad to this unit.
func nlaAlign(n int) int {
	return (n + 3) &^ 3
}

// appendAttr appends one nlattr — len, type, value, then padding — to b.
func appendAttr(b []byte, atype uint16, val []byte) []byte {
	l := 4 + len(val)
	var hdr [4]byte
	binary.NativeEndian.PutUint16(hdr[0:2], uint16(l))
	binary.NativeEndian.PutUint16(hdr[2:4], atype)
	b = append(b, hdr[:]...)
	b = append(b, val...)
	return append(b, make([]byte, nlaAlign(l)-l)...)
}

// newMsg starts an nlmsghdr (length at 0, finishMsg patches it) and then an
// nfgenmsg. family and version are host-order bytes. res_id is big-endian,
// as the nfnetlink wire format requires. The rest of the header is host
// order.
func newMsg(msgType, flags uint16, seq uint32, family uint8, resID uint16) []byte {
	b := make([]byte, nlmsgHdrLen, 64)
	binary.NativeEndian.PutUint16(b[4:6], msgType)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	// b[12:16] (pid) stays 0. The code sends to the kernel directly, not
	// to a multicast group. Thus the kernel does not check it.
	b = append(b, family, nfnetlinkV0, 0, 0)
	binary.BigEndian.PutUint16(b[nlmsgHdrLen+2:nlmsgHdrLen+4], resID)
	return b
}

// finishMsg patches nlmsg_len now that the message is complete.
func finishMsg(b []byte) []byte {
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b
}

// encodeVerdict builds NFQNL_MSG_VERDICT for id. Flags have only
// NLM_F_REQUEST. Verdicts are fire-and-forget, one for each packet. A wait
// for an ack on each would decrease throughput by approximately half, for a
// message that almost never fails.
func encodeVerdict(seq uint32, queueNum uint16, id, verdict uint32, mark *uint32) []byte {
	b := newMsg(nfqMsgType(msgVerdict), syscall.NLM_F_REQUEST, seq, 0, queueNum)
	var vh [8]byte
	binary.BigEndian.PutUint32(vh[0:4], verdict)
	binary.BigEndian.PutUint32(vh[4:8], id)
	b = appendAttr(b, attrVerdictHdr, vh[:])
	if mark != nil {
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], *mark)
		b = appendAttr(b, attrMark, m[:])
	}
	return finishMsg(b)
}

// cfgFields is the optional attribute set for one NFQNL_MSG_CONFIG message.
// Open sends more than one of these in sequence (cmd, then params, then
// flags, then maxlen). It does not send one message with all of them. Thus
// each step gets its own ack and its own error.
type cfgFields struct {
	cmd uint8  // cfgCmdNone omits NFQA_CFG_CMD
	pf  uint16 // AF_xxx; only meaningful together with cmd

	copyMode  uint8 // 0 omits NFQA_CFG_PARAMS
	copyRange uint32

	flags  *uint32 // non-nil sets NFQA_CFG_MASK and NFQA_CFG_FLAGS to *flags
	maxlen *uint32 // non-nil sets NFQA_CFG_QUEUE_MAXLEN
}

// encodeConfig builds NFQNL_MSG_CONFIG for queueNum and requests an ack.
// Each config step must know if the kernel accepted it.
func encodeConfig(seq uint32, queueNum uint16, f cfgFields) []byte {
	b := newMsg(nfqMsgType(msgConfig), syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq, 0, queueNum)
	if f.cmd != cfgCmdNone {
		var cmd [4]byte // {command u8, _pad u8, pf u16 BE}
		cmd[0] = f.cmd
		binary.BigEndian.PutUint16(cmd[2:4], f.pf)
		b = appendAttr(b, attrCfgCmd, cmd[:])
	}
	if f.copyMode != 0 {
		var p [5]byte // {copy_range u32 BE, copy_mode u8}, packed
		binary.BigEndian.PutUint32(p[0:4], f.copyRange)
		p[4] = f.copyMode
		b = appendAttr(b, attrCfgParams, p[:])
	}
	if f.flags != nil {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], *f.flags)
		b = appendAttr(b, attrCfgMask, v[:])  // which bits to change...
		b = appendAttr(b, attrCfgFlags, v[:]) // ...to these values: set exactly *flags
	}
	if f.maxlen != nil {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], *f.maxlen)
		b = appendAttr(b, attrCfgQueueMaxlen, v[:])
	}
	return finishMsg(b)
}
