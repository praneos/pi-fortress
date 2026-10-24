package nfq

// These tests use no root and no live socket. They test all code through the
// pure encode/decode functions with hand-built or randomly mangled byte slices.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
)

// --- hand-built wire fixtures, independent of appendAttr/newMsg. Thus the
// decode tests do not only copy the encoder that they must check. ---

func mkAttr(t uint16, v []byte) []byte {
	l := 4 + len(v)
	b := make([]byte, 4)
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], t)
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func mkNlmsg(msgType, flags uint16, seq uint32, body []byte) []byte {
	total := 16 + len(body)
	b := make([]byte, 16)
	binary.NativeEndian.PutUint32(b[0:4], uint32(total))
	binary.NativeEndian.PutUint16(b[4:6], msgType)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	b = append(b, body...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func mkNfgenmsg(family uint8, resID uint16) []byte {
	b := make([]byte, 4)
	b[0] = family
	binary.BigEndian.PutUint16(b[2:4], resID)
	return b
}

func mkPacketHdr(id uint32, hwProto uint16, hook uint8) []byte {
	v := make([]byte, 7)
	binary.BigEndian.PutUint32(v[0:4], id)
	binary.BigEndian.PutUint16(v[4:6], hwProto)
	v[6] = hook
	return v
}

func mkU32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func requireLittleEndian(t *testing.T) {
	t.Helper()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("exact-byte test assumes a little-endian host (amd64/arm64, both targets)")
	}
}

// --- decode: packet messages ---

func TestParseMessages_PacketRoundTrip(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x00} // 5 bytes on purpose: not attr-aligned
	body := mkNfgenmsg(afInet, 5)
	body = append(body, mkAttr(attrPacketHdr, mkPacketHdr(100, 0x0800, 0))...)
	body = append(body, mkAttr(attrMark, mkU32BE(42))...)
	body = append(body, mkAttr(attrPayload, payload)...)
	msg := mkNlmsg(nfqMsgType(msgPacket), 0, 1, body)

	pkts, err := parseMessages(msg)
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	p := pkts[0]
	if p.ID != 100 {
		t.Errorf("ID = %d, want 100", p.ID)
	}
	if p.Mark != 42 {
		t.Errorf("Mark = %d, want 42", p.Mark)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Errorf("Payload = %x, want %x", p.Payload, payload)
	}
}

func TestParseAttrs_FlagBitsIgnored(t *testing.T) {
	raw := mkAttr(attrMark|nlaFNested|nlaFNetByteorder, mkU32BE(7))
	attrs, err := parseAttrs(raw)
	if err != nil {
		t.Fatalf("parseAttrs: %v", err)
	}
	got, ok := attrs[attrMark]
	if !ok {
		t.Fatalf("attrMark not found among %v", attrs)
	}
	if binary.BigEndian.Uint32(got) != 7 {
		t.Errorf("value = %x, want 7", got)
	}
}

func TestParseAttrs_TruncatedIsError(t *testing.T) {
	// Declares an 8-byte attribute (4 header + 4 value), but only the
	// header is present.
	b := make([]byte, 4)
	binary.NativeEndian.PutUint16(b[0:2], 8)
	binary.NativeEndian.PutUint16(b[2:4], attrMark)
	if _, err := parseAttrs(b); err == nil {
		t.Fatal("want error, got nil")
	}
}

func TestParseMessages_Multiple(t *testing.T) {
	body1 := append(mkNfgenmsg(afInet, 1), mkAttr(attrPacketHdr, mkPacketHdr(1, 0x0800, 0))...)
	body2 := append(mkNfgenmsg(afInet, 1), mkAttr(attrPacketHdr, mkPacketHdr(2, 0x0800, 0))...)
	buf := append(mkNlmsg(nfqMsgType(msgPacket), 0, 1, body1),
		mkNlmsg(nfqMsgType(msgPacket), 0, 2, body2)...)

	pkts, err := parseMessages(buf)
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2", len(pkts))
	}
	if pkts[0].ID != 1 || pkts[1].ID != 2 {
		t.Errorf("IDs = %d, %d, want 1, 2", pkts[0].ID, pkts[1].ID)
	}
}

func TestParseMessages_AckSkipped(t *testing.T) {
	// nlmsgerr{error: 0, msg: <replicated nlmsghdr>}: a plain ack.
	body := make([]byte, 4+16)
	msg := mkNlmsg(syscall.NLMSG_ERROR, 0, 1, body)

	pkts, err := parseMessages(msg)
	if err != nil {
		t.Fatalf("want nil error for a bare ack, got %v", err)
	}
	if len(pkts) != 0 {
		t.Fatalf("want no packets, got %d", len(pkts))
	}
}

func TestParseMessages_NegativeErrno(t *testing.T) {
	body := make([]byte, 4+16)
	errno := int32(syscall.EINVAL) // force a runtime value: negating the untyped constant overflows uint32 at compile time
	binary.NativeEndian.PutUint32(body[0:4], uint32(-errno))
	msg := mkNlmsg(syscall.NLMSG_ERROR, 0, 1, body)

	_, err := parseMessages(msg)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("err = %v, want it to wrap EINVAL", err)
	}
}

// FuzzWalkMessages: no recv buffer makes the walk panic. Each message has
// a 16-byte header, so there are at most len/16 packets. A payload is a
// copy: the next read reuses the buffer. parseMessages stops at the first
// netlink error, so its packets are the start of the packets of parseRecv.
func FuzzWalkMessages(f *testing.F) {
	body := mkNfgenmsg(afInet, 5)
	body = append(body, mkAttr(attrPacketHdr, mkPacketHdr(100, 0x0800, 0))...)
	body = append(body, mkAttr(attrMark, mkU32BE(42))...)
	body = append(body, mkAttr(attrPayload, []byte{1, 2, 3, 4, 5})...)
	pkt := mkNlmsg(nfqMsgType(msgPacket), 0, 1, body)
	errMsg := mkNlmsg(syscall.NLMSG_ERROR, 0, 2, mkU32BE(0xffffffea))
	f.Add(pkt)
	f.Add(append(append(append([]byte(nil), pkt...), errMsg...), pkt...))
	f.Add(pkt[:len(pkt)-3])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		all, nlErrs, _ := parseRecv(buf)
		if len(all) > len(buf)/nlmsgHdrLen {
			t.Fatalf("%d packets from %d bytes", len(all), len(buf))
		}
		if len(nlErrs) > len(buf)/nlmsgHdrLen {
			t.Fatalf("%d errors from %d bytes", len(nlErrs), len(buf))
		}
		first, err := parseMessages(buf)
		if len(first) > len(all) {
			t.Fatalf("parseMessages %d packets, parseRecv %d", len(first), len(all))
		}
		for i := range first {
			if first[i].ID != all[i].ID || first[i].Mark != all[i].Mark || !bytes.Equal(first[i].Payload, all[i].Payload) {
				t.Fatalf("packet %d differs", i)
			}
		}
		if len(nlErrs) == 0 && err == nil && len(first) != len(all) {
			t.Fatalf("no error, but %d of %d packets", len(first), len(all))
		}
		want := make([][]byte, len(all))
		for i, p := range all {
			want[i] = append([]byte(nil), p.Payload...)
		}
		for i := range buf {
			buf[i] ^= 0xff
		}
		for i, p := range all {
			if !bytes.Equal(p.Payload, want[i]) {
				t.Fatalf("payload %d shares the recv buffer", i)
			}
		}
	})
}

// FuzzParseAttrs: no attribute stream makes parseAttrs panic. Each value
// lies inside the stream, after its 4-byte header.
func FuzzParseAttrs(f *testing.F) {
	f.Add(append(mkAttr(attrMark, mkU32BE(42)), mkAttr(attrPayload, []byte{1, 2, 3, 4, 5})...))
	f.Add(mkAttr(attrMark|0x8000, nil))
	f.Add([]byte{3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		attrs, err := parseAttrs(b)
		if err != nil {
			if attrs != nil {
				t.Fatalf("error with attributes: %v", err)
			}
			return
		}
		if len(attrs) > len(b)/4 {
			t.Fatalf("%d attributes from %d bytes", len(attrs), len(b))
		}
		for typ, v := range attrs {
			if typ&^nlaTypeMask != 0 {
				t.Fatalf("type %#x keeps flag bits", typ)
			}
			if len(v)+4 > len(b) {
				t.Fatalf("value of %d bytes in %d", len(v), len(b))
			}
		}
	})
}

func TestParseMessages_NoPanicOnTruncatedPrefixes(t *testing.T) {
	body := mkNfgenmsg(afInet, 5)
	body = append(body, mkAttr(attrPacketHdr, mkPacketHdr(100, 0x0800, 0))...)
	body = append(body, mkAttr(attrMark, mkU32BE(42))...)
	body = append(body, mkAttr(attrPayload, []byte{1, 2, 3, 4, 5})...)
	full := mkNlmsg(nfqMsgType(msgPacket), 0, 1, body)

	for i := 0; i <= len(full); i++ {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic at truncation %d: %v", i, p)
				}
			}()
			parseMessages(full[:i])
		}()
	}
}

// --- encode: exact bytes ---

func TestEncodeVerdict_NoMark(t *testing.T) {
	requireLittleEndian(t)
	got := encodeVerdict(7 /* seq */, 3 /* queue */, 100 /* id */, Accept, nil)
	want := []byte{
		0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
		0x01, 0x03, // nlmsg_type = NFNL_SUBSYS_QUEUE<<8 | NFQNL_MSG_VERDICT
		0x01, 0x00, // nlmsg_flags = NLM_F_REQUEST
		0x07, 0x00, 0x00, 0x00, // nlmsg_seq = 7
		0x00, 0x00, 0x00, 0x00, // nlmsg_pid = 0
		0x00,       // nfgen_family = AF_UNSPEC
		0x00,       // version = NFNETLINK_V0
		0x00, 0x03, // res_id (BE) = queue 3
		0x0c, 0x00, // nla_len = 12 (4 header + 8 value)
		0x02, 0x00, // nla_type = NFQA_VERDICT_HDR
		0x00, 0x00, 0x00, 0x01, // verdict (BE) = NF_ACCEPT
		0x00, 0x00, 0x00, 0x64, // id (BE) = 100
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}
}

func TestEncodeVerdict_WithMark(t *testing.T) {
	requireLittleEndian(t)
	mark := uint32(42)
	got := encodeVerdict(7, 3, 100, Accept, &mark)
	want := []byte{
		0x28, 0x00, 0x00, 0x00, // nlmsg_len = 40 (32 base + 8 mark attr)
		0x01, 0x03, // nlmsg_type
		0x01, 0x00, // nlmsg_flags = NLM_F_REQUEST
		0x07, 0x00, 0x00, 0x00, // nlmsg_seq = 7
		0x00, 0x00, 0x00, 0x00, // nlmsg_pid = 0
		0x00,       // nfgen_family = AF_UNSPEC
		0x00,       // version = NFNETLINK_V0
		0x00, 0x03, // res_id (BE) = queue 3
		0x0c, 0x00, // nla_len = 12
		0x02, 0x00, // nla_type = NFQA_VERDICT_HDR
		0x00, 0x00, 0x00, 0x01, // verdict (BE) = NF_ACCEPT
		0x00, 0x00, 0x00, 0x64, // id (BE) = 100
		0x08, 0x00, // nla_len = 8 (4 header + 4 value)
		0x03, 0x00, // nla_type = NFQA_MARK
		0x00, 0x00, 0x00, 0x2a, // mark (BE) = 42
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}
}
