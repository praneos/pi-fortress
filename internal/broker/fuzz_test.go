package broker

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

func fuzzSlots() map[string]secrets.Slot {
	a, b := "a1b2c3d4e5f67890", "b0b1b2b3b4b5b6b7"
	return map[string]secrets.Slot{
		secrets.EnvKey(a, "GITHUB_TOKEN"): {ID: a, Kind: "GITHUB_TOKEN", Dummy: secrets.Placeholder(a, "GITHUB_TOKEN"), Live: "ghp_" + strings.Repeat("A", 36)},
		secrets.EnvKey(b, "CLAUDE_OAT"):   {ID: b, Kind: "CLAUDE_OAT", Dummy: secrets.Placeholder(b, "CLAUDE_OAT"), Live: "sk-ant-oat01-" + strings.Repeat("B", 64)},
		secrets.EnvKey(b, "CLAUDE_ORT"):   {ID: b, Kind: "CLAUDE_ORT", Dummy: secrets.Placeholder(b, "CLAUDE_ORT"), Live: ""},
	}
}

// FuzzRewriteResponse: after the rewrite, no live value stays in a header
// or in the body. Each occurrence changed to the placeholder of its slot.
// The hit list names each slot that occurred.
func FuzzRewriteResponse(f *testing.F) {
	f.Add("text/plain", "ok ", "body ", uint8(1))
	f.Fuzz(func(t *testing.T, h1, h2, body string, where uint8) {
		if strings.ContainsAny(h1+h2, "\r\n") {
			return
		}
		slots := fuzzSlots()
		var lives []secrets.Slot
		for _, sl := range slots {
			if sl.Live != "" {
				lives = append(lives, sl)
			}
		}
		l0, l1 := lives[0], lives[1]
		if l0.Kind > l1.Kind {
			l0, l1 = l1, l0
		}
		pos := int(where) % (len(body) + 1)
		body = body[:pos] + l0.Live + body[pos:] + l1.Live
		h2 += l1.Live
		resp := &httpwire.Response{Proto: "HTTP/1.1", Status: "200 OK", Code: 200, Body: []byte(body)}
		resp.SetInPlace("Content-Type", h1)
		resp.SetInPlace("Set-Cookie", "a="+h2)
		resp.SetInPlace("Set-Cookie", "b="+h2)
		hit, err := rewriteResponse(resp, slots)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if _, err := resp.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		o := out.Bytes()
		for _, sl := range lives {
			if bytes.Contains(o, []byte(sl.Live)) {
				t.Fatalf("live %s survived rewrite\n%q", sl.Kind, o)
			}
		}
		if bytes.Count(o, []byte(l0.Dummy)) < 1 || bytes.Count(o, []byte(l1.Dummy)) < 2 {
			t.Fatalf("placeholders missing\n%q", o)
		}
		seen := map[string]bool{}
		for _, k := range hit {
			seen[k] = true
		}
		if !seen[secrets.EnvKey(l0.ID, l0.Kind)] || !seen[secrets.EnvKey(l1.ID, l1.Kind)] {
			t.Fatalf("hit list %v misses a slot", hit)
		}
	})
}

func sameWSHeader(a, b wsHeader) bool {
	return a.fin == b.fin && a.opcode == b.opcode && a.masked == b.masked && a.length == b.length && a.key == b.key
}

// FuzzWSHeader: the frame parser never panics, and a header that it
// accepts round-trips. h.raw must be exactly the bytes that the parser
// consumed, because the server-to-client leg puts these bytes back on the
// wire. A second parse of h.raw must give the same header. The minimal
// form that the client leg writes must also parse back to the same frame.
func FuzzWSHeader(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x81},
		{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x82, 0x7e, 0x01, 0x00},
		{0x82, 0xfe, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04},
		{0x82, 0x7f, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00},
		{0x82, 0xff, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
		// 64-bit length with the reserved high bit set.
		{0x82, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0},
		// One seed per RSV bit.
		{0xc1, 0x00},
		{0xa1, 0x00},
		{0x91, 0x00},
		// Reserved opcode, fragmented control, oversized control, ping.
		{0x83, 0x00},
		{0x08, 0x00},
		{0x88, 0x7e, 0x00, 0x7e},
		{0x89, 0x04, 'p', 'i', 'n', 'g'},
		{0x80, 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		br := bufio.NewReader(r)
		h, err := readWSHeader(br, 0)
		if err != nil {
			return
		}
		used := len(data) - r.Len() - br.Buffered()
		if used != len(h.raw) || !bytes.Equal(h.raw, data[:used]) {
			t.Fatalf("raw %x is not the %d bytes consumed of %x", h.raw, used, data)
		}
		again, err := readWSHeader(bufio.NewReader(bytes.NewReader(h.raw)), 0)
		if err != nil || !sameWSHeader(again, h) {
			t.Fatalf("raw round-trip: %v %+v vs %+v", err, again, h)
		}
		if h.length < 0 || (h.control() && (!h.fin || h.length > maxControlPayload)) {
			t.Fatalf("accepted an illegal frame: %+v", h)
		}
		if h.length > 1<<20 {
			return
		}
		var key *[4]byte
		if h.masked {
			k := h.key
			key = &k
		}
		mine := appendWSHeader(nil, h.fin, h.opcode, key, int(h.length))
		back, err := readWSHeader(bufio.NewReader(bytes.NewReader(mine)), 0)
		if err != nil || !sameWSHeader(back, h) {
			t.Fatalf("serialize round-trip: %v %+v vs %+v", err, back, h)
		}
	})
}
