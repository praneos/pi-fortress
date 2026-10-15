package peekconn

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// chunkConn gives a stream that can never parse as a Client Hello: a TLS
// record header that announces 65535 bytes of handshake, then filler. Each
// Parse over each prefix of it gives ErrIncomplete. Thus Wrap continues to
// read until it gets to its cap. The first Read returns a maximum of `first`
// bytes. Each later Read fills all of the buffer that it gets. This is how a
// peer selects the segmentation that Wrap sees.
type chunkConn struct {
	first int
	used  bool
	total int
}

func (c *chunkConn) byteAt(i int) byte {
	hdr := [...]byte{0x16, 0x03, 0x03, 0xff, 0xff}
	if i < len(hdr) {
		return hdr[i]
	}
	return 0
}

func (c *chunkConn) Read(p []byte) (int, error) {
	n := len(p)
	if !c.used {
		c.used = true
		if c.first < n {
			n = c.first
		}
	}
	if n == 0 {
		return 0, io.EOF
	}
	for i := 0; i < n; i++ {
		p[i] = c.byteAt(c.total + i)
	}
	c.total += n
	return n, nil
}

func (c *chunkConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *chunkConn) Close() error                { return nil }
func (c *chunkConn) LocalAddr() net.Addr         { return nil }
func (c *chunkConn) RemoteAddr() net.Addr        { return nil }
func (c *chunkConn) SetDeadline(time.Time) error { return nil }
func (c *chunkConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *chunkConn) SetWriteDeadline(t time.Time) error { return nil }

// TestWrapCapIsExactRegardlessOfSegmentation pins the admission bound. For a
// peer that never completes a Client Hello, Wrap reads a maximum of MaxPeek
// bytes of it. The number of bytes that the peer can use does not change with
// how it splits its writes. A budget that changes with the segmentation of the
// peer is not a budget.
func TestWrapCapIsExactRegardlessOfSegmentation(t *testing.T) {
	var totals []int
	for _, first := range []int{1, 7, 1023, 1024} {
		c := &chunkConn{first: first}
		_, err := Wrap(c, MaxPeek)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("first=%d: err=%v, want ErrTooLarge", first, err)
		}
		if c.total > MaxPeek {
			t.Errorf("first=%d: read %d bytes, cap is %d", first, c.total, MaxPeek)
		}
		totals = append(totals, c.total)
	}
	for i := range totals {
		if totals[i] != totals[0] {
			t.Fatalf("bytes read depend on peer segmentation: %v", totals)
		}
	}
}
