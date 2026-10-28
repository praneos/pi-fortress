package netgate

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"pi-fortress/internal/gateset"
)

func v4s(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestGateRequestRoundTrip(t *testing.T) {
	for _, r := range []gateReq{
		{op: opAdd, set: "resolved_v4", addrs: v4s("93.184.216.34", "1.1.1.1")},
		{op: opRefresh, set: "resolved_house_v4", addrs: v4s("8.8.8.8")},
		{op: opAdd, set: "resolved_v4"},
		{op: opAdd, set: strings.Repeat("s", maxSetName), addrs: v4s("9.9.9.9")},
	} {
		b, err := encodeGate(r)
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		if len(b) != gateHead+4*len(r.addrs) {
			t.Fatalf("%+v: %d bytes", r, len(b))
		}
		got, err := decodeGate(b)
		if err != nil {
			t.Fatalf("%+v: decode: %v", r, err)
		}
		if got.op != r.op || got.set != r.set || len(got.addrs) != len(r.addrs) {
			t.Fatalf("round trip %+v -> %+v", r, got)
		}
		for i := range r.addrs {
			if got.addrs[i] != r.addrs[i] {
				t.Fatalf("round trip %+v -> %+v", r, got)
			}
		}
	}
}

func TestEncodeGateRefuses(t *testing.T) {
	many := make([]netip.Addr, gateset.MaxA+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{1, 1, byte(i >> 8), byte(i)})
	}
	for _, r := range []gateReq{
		{op: 0, set: "resolved_v4"},
		{op: 3, set: "resolved_v4"},
		{op: opAdd, set: ""},
		{op: opAdd, set: strings.Repeat("s", maxSetName+1)},
		{op: opAdd, set: "resolved_v4", addrs: many},
		{op: opAdd, set: "resolved_v4", addrs: v4s("2001:db8::1")},
	} {
		if _, err := encodeGate(r); err == nil {
			t.Errorf("encodeGate(%q, op %d, %d addrs) passed", r.set, r.op, len(r.addrs))
		}
	}
}

// Each form that encodeGate never makes is a protocol error.
func TestDecodeGateRefuses(t *testing.T) {
	good, err := encodeGate(gateReq{op: opAdd, set: "resolved_v4", addrs: v4s("1.1.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	for name, b := range map[string][]byte{
		"empty":             {},
		"short":             good[:gateHead-1],
		"verb":              edit(func(b []byte) []byte { b[0] = 'X'; return b }),
		"op 0":              edit(func(b []byte) []byte { b[1] = 0; return b }),
		"op 3":              edit(func(b []byte) []byte { b[1] = 3; return b }),
		"count high":        edit(func(b []byte) []byte { b[2] = 2; return b }),
		"count low":         edit(func(b []byte) []byte { b[2] = 0; return b }),
		"count over max":    edit(func(b []byte) []byte { b[2] = gateset.MaxA + 1; return b }),
		"pad byte":          edit(func(b []byte) []byte { b[3] = 1; return b }),
		"name empty":        edit(func(b []byte) []byte { clear(b[4:gateHead]); return b }),
		"bytes after name":  edit(func(b []byte) []byte { b[gateHead-1] = 'x'; return b }),
		"trailing byte":     append(bytes.Clone(good), 0),
		"half an address":   good[:len(good)-2],
		"reply as request":  encodeReply(statusOK, ""),
		"name with NUL gap": edit(func(b []byte) []byte { b[4+3] = 0; return b }),
	} {
		if _, err := decodeGate(b); !errors.Is(err, errProto) {
			t.Errorf("%s: decodeGate gave %v, want a protocol error", name, err)
		}
	}
}

func TestReplyRoundTrip(t *testing.T) {
	for _, c := range []struct {
		status byte
		why    string
	}{{statusOK, ""}, {statusRefused, "set \"x\" is not a gate set"}, {statusFailed, strings.Repeat("e", maxReplyText+50)}} {
		b := encodeReply(c.status, c.why)
		status, why, err := decodeReply(b)
		if err != nil || status != c.status {
			t.Fatalf("reply %d %q: %d %q %v", c.status, c.why, status, why, err)
		}
		if want := c.why[:min(len(c.why), maxReplyText)]; why != want {
			t.Fatalf("reason %q, want %q", why, want)
		}
	}
	for _, b := range [][]byte{{}, {verbReply}, {'X', 0}, {verbReply, statusFailed + 1}, append([]byte{verbReply, 0}, make([]byte, maxReplyText+1)...)} {
		if _, _, err := decodeReply(b); !errors.Is(err, errProto) {
			t.Errorf("decodeReply(%q) gave %v, want a protocol error", b, err)
		}
	}
	if replyErr(statusOK, "") != nil || replyErr(statusRefused, "x") == nil || replyErr(statusFailed, "x") == nil {
		t.Fatal("replyErr")
	}
}

// FuzzDecodeGate: no input panics the decoder. Each input that it takes
// is the one encoding of what it decoded, and stays in the limits.
func FuzzDecodeGate(f *testing.F) {
	for _, r := range []gateReq{
		{op: opAdd, set: "resolved_v4", addrs: v4s("93.184.216.34", "1.1.1.1")},
		{op: opRefresh, set: "resolved_house_v4"},
		{op: opAdd, set: strings.Repeat("s", maxSetName), addrs: v4s("10.0.0.1")},
	} {
		b, err := encodeGate(r)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{verbGate, opAdd, 255, 0})
	f.Add(encodeReply(statusOK, ""))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeGate(b)
		if err != nil {
			if !errors.Is(err, errProto) {
				t.Fatalf("error %v is not a protocol error", err)
			}
			return
		}
		if len(r.addrs) > gateset.MaxA || r.set == "" || len(r.set) > maxSetName || strings.IndexByte(r.set, 0) >= 0 {
			t.Fatalf("decoded out of the limits: %+v", r)
		}
		again, err := encodeGate(r)
		if err != nil {
			t.Fatalf("decoded %+v does not encode: %v", r, err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("two encodings of one request:\n%x\n%x", b, again)
		}
	})
}

func TestPeerAllows(t *testing.T) {
	p := Peer{UID: 101, GID: 202}
	for _, c := range []struct {
		uid, gid uint32
		ok       bool
	}{
		{101, 202, true},
		{101, 203, false}, // the stub: same account, other group
		{102, 202, false},
		{0, 0, false}, // root is not the client either
		{0, 202, false},
		{101, 0, false},
	} {
		if got := p.allows(c.uid, c.gid); got != c.ok {
			t.Errorf("allows(%d, %d) = %v, want %v", c.uid, c.gid, got, c.ok)
		}
	}
}
