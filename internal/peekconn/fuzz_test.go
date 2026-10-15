package peekconn

import (
	"net"
	"testing"

	"pi-fortress/internal/hello"
)

// FuzzWrap: each byte stream gives a Conn with a prefix that parses as a
// Client Hello, or an error. It never gives a panic or a hang.
func FuzzWrap(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxPeek {
			return
		}
		client, server := net.Pipe()
		go func() {
			_, _ = client.Write(data)
			_ = client.Close()
		}()
		c, err := Wrap(server, 0)
		if err != nil {
			_ = server.Close()
			return
		}
		if _, perr := hello.Parse(c.Prefix()); perr != nil {
			t.Fatalf("Wrap succeeded but prefix does not parse: %v", perr)
		}
		_ = c.Close()
	})
}
