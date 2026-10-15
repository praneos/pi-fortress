package nfq

// Wire constants from linux/netfilter/nfnetlink.h and
// linux/netfilter/nfnetlink_queue.h. They are unexported and separate from
// the public API. Thus encode.go/decode.go are easy to compare with the
// kernel headers that they copy.
const (
	afInet      = 2 // AF_INET: the pf carried in NFQA_CFG_CMD
	nfnetlinkV0 = 0 // nfgenmsg.version

	nfnlSubsysQueue = 3 // NFNL_SUBSYS_QUEUE: top byte of nlmsg_type

	msgPacket  = 0 // NFQNL_MSG_PACKET
	msgVerdict = 1 // NFQNL_MSG_VERDICT
	msgConfig  = 2 // NFQNL_MSG_CONFIG

	cfgCmdNone     = 0 // not a real command; means "omit NFQA_CFG_CMD"
	cfgCmdBind     = 1 // NFQNL_CFG_CMD_BIND
	cfgCmdPfBind   = 3 // NFQNL_CFG_CMD_PF_BIND
	cfgCmdPfUnbind = 4 // NFQNL_CFG_CMD_PF_UNBIND

	copyPacket = 2 // NFQNL_COPY_PACKET

	attrCfgCmd         = 1 // NFQA_CFG_CMD
	attrCfgParams      = 2 // NFQA_CFG_PARAMS
	attrCfgQueueMaxlen = 3 // NFQA_CFG_QUEUE_MAXLEN
	attrCfgMask        = 4 // NFQA_CFG_MASK
	attrCfgFlags       = 5 // NFQA_CFG_FLAGS

	cfgFGSO = 1 << 2 // NFQA_CFG_F_GSO

	attrPacketHdr  = 1  // NFQA_PACKET_HDR
	attrVerdictHdr = 2  // NFQA_VERDICT_HDR
	attrMark       = 3  // NFQA_MARK
	attrPayload    = 10 // NFQA_PAYLOAD

	nlaFNested       = 0x8000 // NLA_F_NESTED
	nlaFNetByteorder = 0x4000 // NLA_F_NET_BYTEORDER
	nlaTypeMask      = ^uint16(nlaFNested | nlaFNetByteorder)

	nlmsgHdrLen = 16 // struct nlmsghdr
	nfgenmsgLen = 4  // struct nfgenmsg
)

// nfqMsgType puts a NFQNL_MSG_* into the two-byte nlmsg_type: subsystem in
// the high byte, operation in the low byte (NFNL_SUBSYS_ID / NFNL_MSG_TYPE).
func nfqMsgType(msg uint8) uint16 {
	return uint16(nfnlSubsysQueue)<<8 | uint16(msg)
}
