package preamble

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
	"unicode/utf8"
)

func FuzzDecodeGarbage(f *testing.F) {
	f.Add([]byte(`{"src":"1.2.3.4:5","orig_dst":"5.6.7.8:443","sni":"a.b"}` + "\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Decode(bufio.NewReader(bytes.NewReader(raw)))
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(uint16(1234), uint16(443), "api.anthropic.com", "http/1.1")
	f.Fuzz(func(t *testing.T, sport, dport uint16, sni, alpn string) {
		// JSON changes invalid UTF-8 to U+FFFD. The engine sends the ALPN that
		// crypto/tls negotiated, which is one of the names of the engine.
		if !utf8.ValidString(alpn) || len(alpn) > 128 {
			return
		}
		in := &Preamble{
			Src:     netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 77, 0, 10}), sport),
			OrigDst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), dport),
			SNI:     sni,
			ALPN:    alpn,
		}
		var buf bytes.Buffer
		if err := Encode(&buf, in); err != nil {
			if ValidSNI(sni) {
				t.Fatalf("encode refused a valid sni %q: %v", sni, err)
			}
			return
		}
		out, err := Decode(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("encode then decode failed: %v (%q)", err, buf.Bytes())
		}
		if out.Src != in.Src || out.OrigDst != in.OrigDst || out.SNI != in.SNI || out.ALPN != in.ALPN {
			t.Fatalf("round trip %+v -> %+v", in, out)
		}
	})
}
