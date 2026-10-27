package main

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"
)

// A reply that copies the transmit timestamp parses. One that does not, or
// that is not mode 4, is refused.
func TestParseReply(t *testing.T) {
	now := time.Now()
	tx := ntpTime(now)
	reply := make([]byte, 48)
	reply[0] = 4<<3 | 4
	reply[1] = 3
	copy(reply[12:], []byte{192, 0, 2, 9})
	binary.BigEndian.PutUint64(reply[24:], tx)
	binary.BigEndian.PutUint64(reply[32:], ntpTime(now.Add(time.Second)))
	binary.BigEndian.PutUint64(reply[40:], ntpTime(now.Add(time.Second)))
	r, err := parseReply(reply, tx, now)
	if err != nil || r.Stratum != 3 || r.RefID != "192.0.2.9" || r.Mode != 4 || r.Version != 4 {
		t.Fatalf("%+v %v", r, err)
	}
	if d := r.Offset - time.Second; d < -time.Millisecond || d > time.Millisecond {
		t.Errorf("offset %s, want 1s", r.Offset)
	}
	if _, err := parseReply(reply, tx+1, now); err == nil {
		t.Error("a reply to a different request parsed")
	}
	reply[0] = 4<<3 | 3
	if _, err := parseReply(reply, tx, now); err == nil {
		t.Error("a mode 3 packet parsed as a reply")
	}
	if _, err := parseReply(reply[:47], tx, now); err == nil {
		t.Error("a short reply parsed")
	}
}

// Each kind comes out, no packet is over 1500 bytes, the mode 6 and mode 7
// kinds have those modes, and each packet of 48 bytes or more is
// remembered by its transmit timestamp.
func TestPackets(t *testing.T) {
	f := &fuzzer{rng: rand.New(rand.NewPCG(1, 2)), byTx: map[uint64]sent{}, stats: Stats{ByKind: map[string]int64{}}}
	kinds := map[string]int{}
	for i := 0; i < 20000; i++ {
		kind, b := f.packet()
		f.seq++
		kinds[kind]++
		if len(b) > 1500 {
			t.Fatalf("%s: %d bytes", kind, len(b))
		}
		if (kind == "mode6" && b[0]&7 != 6) || (kind == "mode7" && b[0]&7 != 7) {
			t.Fatalf("%s: mode %d", kind, b[0]&7)
		}
		if len(b) >= 48 {
			if s, ok := f.lookup(binary.BigEndian.Uint64(b[40:])); !ok || s.size != len(b) {
				t.Fatalf("%s: not remembered", kind)
			}
		}
	}
	for _, k := range []string{"random", "header", "truncated", "extension", "nts", "oversized", "mutated", "mac", "mode6", "mode7"} {
		if kinds[k] == 0 {
			t.Errorf("no %s packet in 20000", k)
		}
	}
	if len(f.byTx) > 1<<16 {
		t.Errorf("%d remembered, the cap is %d", len(f.byTx), 1<<16)
	}
}
