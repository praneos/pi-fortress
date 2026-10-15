package broker

import (
	"net"
	"time"
)

// idleConn makes Idle mean what its name says on both legs: the gap
// between bytes, not a fixed moment after the request arrived. Before, one
// SetDeadline on the client connection had to be both, and the two cannot
// be the same number. A completion that streams for a minute, or a download
// that takes one minute, is a connection that does exactly its job. It
// stopped at thirty seconds, while bytes still moved. The origin leg had
// the opposite half of the problem: nothing bounded it at all. An origin
// could complete the handshake, take the request and then go quiet. The
// connection then stayed in a read until the kernel stopped it. The slot
// that it holds is capacity that this fence does not get back. An agent
// that can send a few requests to such origins empties the pool, and then
// the fence serves no client.
//
// A refresh before each read and each write separates the two bounds: the
// broker still cuts silence at Idle, but never cuts progress. The broker
// always sets the read deadline and the write deadline separately, never
// through SetDeadline. Reason: a websocket relay runs both directions over
// the one connection at the same time. A blanket deadline that the writer
// sets would silently become the deadline of the reader. engine.copyIdle
// uses the same shape for the splice in front of us, for the same reasons.
type idleConn struct {
	net.Conn
	idle time.Duration
	// idleRead is off while the broker reads the request head of a client.
	// There, the absolute deadline of the caller is the purpose. A client that
	// sends one header byte every twenty seconds is the slow loris that the
	// fence must not host, and a refresh on each byte would make that free.
	// idleRead goes on after the head is in and the exchange that the client
	// asked for has started. The origin leg sets it from the start. An origin
	// answers a request that we already sent, so the bound is on its silence.
	idleRead bool
	// by, when set, is an absolute cap on the read deadline: the moment when
	// the response head of the origin must be in (upstream.headBy). Progress
	// refreshes the idle deadline, but never moves it past by.
	by time.Time
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.idleRead && c.idle > 0 {
		dl := time.Now().Add(c.idle)
		if !c.by.IsZero() && c.by.Before(dl) {
			dl = c.by
		}
		_ = c.Conn.SetReadDeadline(dl)
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
}

// idleOrigin wraps a new origin connection. Each read and write that the
// broker makes on that leg goes through it. Thus a stall at any point in
// the exchange ends the connection, and does not hold a slot on it.
func (b *Broker) idleOrigin(c net.Conn) net.Conn {
	return &idleConn{Conn: c, idle: b.idle(), idleRead: true}
}
