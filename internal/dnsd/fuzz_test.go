package dnsd

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzParseTCP4: parseTCP4 reads packets from the queue, which any LAN
// device can fill. It never panics. It accepts a packet only when the
// IPv4 and TCP header lengths fit in the IPv4 total length, and the total
// length fits in the packet. Then the key, sequence number and flags are
// the bytes at their header offsets, and the payload is exactly the bytes
// between the end of the TCP header and the total length.
func FuzzParseTCP4(f *testing.F) {
	base := tcp4("93.184.216.34", 7, []byte("hello"))
	mut := func(m func(p []byte) []byte) []byte {
		return m(append([]byte(nil), base...))
	}
	seeds := [][]byte{
		base,
		tcp4("93.184.216.34", 0, nil),
		tcp4f("93.184.216.34", 0xffffffff, tcpSYN, []byte("tfo")),
		mut(func(p []byte) []byte { // IPv4 options: IHL 6
			p = append(p[:20:20], append([]byte{1, 1, 1, 0}, p[20:]...)...)
			p[0] = 0x46
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			return p
		}),
		mut(func(p []byte) []byte { // TCP options: data offset 6
			p = append(p[:40:40], append([]byte{1, 1, 1, 0}, p[40:]...)...)
			p[32] = 6 << 4
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			return p
		}),
		mut(func(p []byte) []byte { p[0] = 0x44; return p }),                            // IHL < 5
		mut(func(p []byte) []byte { p[0] = 0x4f; return p }),                            // IHL past the packet
		mut(func(p []byte) []byte { p[32] = 4 << 4; return p }),                         // data offset < 5
		mut(func(p []byte) []byte { p[32] = 15 << 4; return p }),                        // data offset past the packet
		mut(func(p []byte) []byte { p[2], p[3] = 0xff, 0xff; return p }),                // total > len
		mut(func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], 39); return p }), // total < headers
		mut(func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], 42); return p }), // total < len
		mut(func(p []byte) []byte { p[9] = 17; return p }),                              // UDP
		mut(func(p []byte) []byte { p[0] = 0x65; return p }),                            // version 6
		base[:19],
		base[:39],
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		key, seq, flags, payload, ok := parseTCP4(pkt)
		ihl, total, doff := 0, 0, 0
		want := len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 6
		if want {
			ihl = int(pkt[0]&0x0f) * 4
			total = int(binary.BigEndian.Uint16(pkt[2:4]))
			want = ihl >= 20 && total >= ihl+20 && total <= len(pkt)
		}
		if want {
			doff = int(pkt[ihl+12]>>4) * 4
			want = doff >= 20 && ihl+doff <= total
		}
		if ok != want {
			t.Fatalf("ok=%v, headers say %v (len=%d ihl=%d total=%d doff=%d)", ok, want, len(pkt), ihl, total, doff)
		}
		if !ok {
			if key != (sniFlowKey{}) || seq != 0 || flags != 0 || payload != nil {
				t.Fatalf("refused packet gives values: %v %d %#x %d bytes", key, seq, flags, len(payload))
			}
			return
		}

		tcp := pkt[ihl:]
		wantKey := sniFlowKey{
			src: netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(tcp[0:2])),
			dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[16:20])), binary.BigEndian.Uint16(tcp[2:4])),
		}
		if key != wantKey {
			t.Fatalf("key %v, bytes say %v", key, wantKey)
		}
		if s := binary.BigEndian.Uint32(tcp[4:8]); seq != s || flags != tcp[13] {
			t.Fatalf("seq=%d flags=%#x, bytes say %d %#x", seq, flags, s, tcp[13])
		}

		// The payload is pkt[ihl+doff:total], in the same memory. It
		// never includes bytes past the IPv4 total length.
		start := ihl + doff
		if len(payload) != total-start {
			t.Fatalf("payload has %d bytes, headers say %d", len(payload), total-start)
		}
		if cap(payload) > cap(pkt)-start {
			t.Fatalf("payload cap %d is past the end of pkt (cap %d, start %d)", cap(payload), cap(pkt), start)
		}
		if cap(payload) > 0 && &payload[:1][0] != &pkt[:start+1][start] {
			t.Fatalf("payload does not start at byte %d of pkt", start)
		}
	})
}
