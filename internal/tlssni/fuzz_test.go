package tlssni

import (
	"crypto/tls"
	"testing"
)

// FuzzParse: each byte stream gives a parsed Hello, a request for more
// bytes, or one of ErrNotTLS/ErrMalformed. It never gives a panic.
func FuzzParse(f *testing.F) {
	hello := captureClientHello(f, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	f.Add(hello)
	for i := 0; i < len(hello); i += 7 {
		f.Add(hello[:i])
	}
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, need, err := Parse(data)
		if err != nil {
			if err != ErrNotTLS && err != ErrMalformed {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if need > 0 && h.ServerName != "" {
			t.Fatalf("need>0 but ServerName set: %q", h.ServerName)
		}
	})
}
