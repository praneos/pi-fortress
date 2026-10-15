package hello

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add(helloWithExts(append(sniExt("example.com"), alpnExt("h2")...), len(sniExt("example.com"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := Parse(b)
		if err != nil {
			return
		}
		if h == nil {
			t.Fatal("nil hello without error")
		}
		for _, c := range h.SNI {
			if c == 0 || c == '\n' || c == '\r' {
				t.Fatalf("control byte in SNI %q", h.SNI)
			}
		}
	})
}

func TestSNIMustBeHostname(t *testing.T) {
	for _, bad := range []string{"\x82", "a b", "x\n", "ü.de", string(make([]byte, 254)), ".a.example", "a..example", "x..a.example.com"} {
		if ValidHostName(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, good := range []string{"api.anthropic.com", "Example.COM", "a-b_c.d1"} {
		if !ValidHostName(good) {
			t.Fatalf("%q rejected", good)
		}
	}
}
