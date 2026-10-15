// Package peekconn wraps an accepted connection. Thus the code can read the
// ClientHello and then replay it to the TLS server behind it. Only
// internal/engine calls it.
package peekconn

import (
	"errors"
	"io"
	"net"

	"pi-fortress/internal/hello"
)

const MaxPeek = 16 << 10

var ErrTooLarge = errors.New("peekconn: client hello too large")

type Conn struct {
	net.Conn
	prefix []byte
	off    int
}

func Wrap(c net.Conn, max int) (*Conn, error) {
	if max <= 0 {
		max = MaxPeek
	}
	var buf []byte
	tmp := make([]byte, 1024)
	for len(buf) < max {
		// Read into the remaining budget, never into the full scratch buffer.
		// If the code reads 1 KiB when 1 byte of budget remains, the accepted
		// prefix can go past max by as much as 1023 bytes. The exact quantity
		// depends on where the peer splits its writes. Admission that changes
		// with the segmentation of the peer is not admission control.
		want := tmp
		if rem := max - len(buf); rem < len(want) {
			want = tmp[:rem]
		}
		n, err := c.Read(want)
		if n > 0 {
			buf = append(buf, want[:n]...)
			if _, perr := hello.Parse(buf); perr == nil {
				return &Conn{Conn: c, prefix: buf}, nil
			} else if !errors.Is(perr, hello.ErrIncomplete) {
				return nil, perr
			}
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return nil, hello.ErrIncomplete
			}
			return nil, err
		}
		if n == 0 {
			return nil, hello.ErrIncomplete
		}
	}
	return nil, ErrTooLarge
}

func (c *Conn) Prefix() []byte {
	return c.prefix
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}
