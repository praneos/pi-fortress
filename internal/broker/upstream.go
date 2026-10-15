package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"time"

	"pi-fortress/internal/httpwire"
)

type dialResult struct {
	conn net.Conn
	dst  netip.AddrPort
	err  error
}

// upstream owns the connection from the broker to the origin for one
// client connection. The origin is fixed (OrigDst + SNI from the
// preamble). So the broker reuses a live connection across requests and
// never shares it with another client connection or SNI. A pre-dial
// starts on the preamble. It does the origin TLS handshake at the same
// time as the parse of the first request of the client.
type upstream struct {
	b *Broker
	// dst is the real address of the origin connection. For a fake
	// destination, dst is unset until the first dial resolves name. After
	// that, it is the address that connected. A redial on this client
	// connection reuses that address, as it reuses OrigDst otherwise.
	dst netip.AddrPort
	sni string
	// name, port and ip are set only for a fake destination. name is the name
	// that the broker resolves itself. port is the port that the agent
	// dialled. ip is the client, for the row that a resolve writes when it
	// finds nothing dialable.
	name string
	port uint16
	ip   string

	conn    net.Conn
	br      *bufio.Reader
	pending chan dialResult
	// cancel stops the predial. close calls it for a client that left
	// before its first request. So the broker abandons an origin that is
	// still in its handshake at once, and does not wait for it.
	cancel context.CancelFunc
}

// originDialTimeout is the full budget to reach one origin address: the
// TCP connect and the TLS handshake together, on one clock. Before, only
// the connect had ten seconds, and the handshake had no limit. So a host
// that accepts TCP and then never sends a ServerHello held the broker
// goroutine, one of its 256 slots and two descriptors for as long as the
// kernel kept the socket. The keepalives of the dialer keep the socket for
// ever. The agent picks the origin (its own domain, or an address that it
// resolved), so the agent can run that host. With 256 connections to it,
// the broker refuses every agent until a restart. Ten seconds is several
// times the time that a slow origin across the world on a bad link needs.
// A handshake that is not complete by then will not complete.
const originDialTimeout = 10 * time.Second

// predialCloseWait is the maximum time that close waits for a cancelled
// predial to return its connection. A cancelled dial returns within a
// scheduler tick. The wait makes sure that a descriptor closes before the
// slot is released, not some time after. The bound makes sure that a dial
// that ignores its context (a DialTLS hook) cannot hold the slot either.
const predialCloseWait = 2 * time.Second

func (u *upstream) startPredial(ctx context.Context) {
	ctx, u.cancel = context.WithCancel(ctx)
	// The goroutine sends on its own copy: close and acquire clear
	// u.pending, and a send on the nil channel that remains blocks for ever.
	ch := make(chan dialResult, 1)
	u.pending = ch
	go func() {
		c, dst, err := u.dialOrigin(ctx)
		ch <- dialResult{conn: c, dst: dst, err: err}
	}()
}

// dialOrigin dials dst. For a fake destination that is not dialled yet,
// it resolves name and dials the result. It reads the upstream and never
// writes it: a predial runs it off the Handle goroutine, and acquire
// stores the returned address, on that goroutine.
func (u *upstream) dialOrigin(ctx context.Context) (net.Conn, netip.AddrPort, error) {
	if u.name == "" || u.dst.IsValid() {
		c, err := u.b.dial(ctx, u.dst, u.sni)
		return c, u.dst, err
	}
	return u.b.dialName(ctx, u.name, u.port, u.sni, u.ip)
}

// acquire returns the connection to write the next request on. reused is
// true only when the connection already carried a response on this client
// connection. Only in that case may the caller transparently redial after
// a failed write or an empty read.
func (u *upstream) acquire(ctx context.Context) (net.Conn, *bufio.Reader, bool, error) {
	if u.conn != nil {
		return u.conn, u.br, true, nil
	}
	if u.pending != nil {
		select {
		case <-ctx.Done():
			return nil, nil, false, ctx.Err()
		case r := <-u.pending:
			u.pending = nil
			// The dial is over; the context only held the predial's
			// place in its parent's list of children.
			u.cancel()
			if r.err != nil {
				return nil, nil, false, r.err
			}
			u.dst = r.dst
			u.conn = u.b.idleOrigin(r.conn)
			u.br = bufio.NewReader(u.conn)
			return u.conn, u.br, false, nil
		}
	}
	c, dst, err := u.dialOrigin(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	u.dst = dst
	u.conn = u.b.idleOrigin(c)
	u.br = bufio.NewReader(u.conn)
	return u.conn, u.br, false, nil
}

// discard closes the current connection so the next acquire dials afresh.
func (u *upstream) discard() {
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
		u.br = nil
	}
}

// close releases the connection and any pre-dial that was never consumed.
// Thus a client that ends before its first request leaks nothing. Before,
// close waited for the predial for all the time that it took. With no
// handshake deadline, that was for ever. The deferred close of Handle
// releases the slot, so a stalled origin kept the slot here even after
// the client had left. close cancels the predial first and waits for it
// for a maximum of predialCloseWait. If the predial still runs after
// that, a goroutine closes whatever it returns. The deadline of the dial
// itself bounds that goroutine.
func (u *upstream) close() {
	u.discard()
	if u.pending == nil {
		return
	}
	ch := u.pending
	u.pending = nil
	u.cancel()
	t := time.NewTimer(predialCloseWait)
	defer t.Stop()
	select {
	case r := <-ch:
		if r.conn != nil {
			_ = r.conn.Close()
		}
	case <-t.C:
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
	}
}

// originHeadIdles is the number of Idle budgets that the origin gets to
// send a full response head. The count starts when the request is written.
// Idle alone bounds silence, and a byte resets it. So an origin that sent
// its head one byte every Idle-less-a-second held the slot for the 64 KiB
// head limit times that interval: weeks. The origin that the agent chose
// can do that as easily as it can stall a handshake. A legitimate origin
// is silent for a maximum of Idle while it works (anything longer is cut
// anyway). Then it sends its head in one piece. So two Idles never cut an
// origin that the idle bound would have let through.
const originHeadIdles = 2

// headBy caps the read deadline of the origin leg at t until the caller
// calls the returned func. So the response head has an absolute deadline,
// and the body after it keeps the idle deadline. headBy does not change a
// connection that is not the idle wrapper of the broker (never, today).
func (u *upstream) headBy(t time.Time) func() {
	ic, ok := u.conn.(*idleConn)
	if !ok {
		return func() {}
	}
	ic.by = t
	return func() { ic.by = time.Time{} }
}

func connClose(v string) bool {
	for tok := range strings.SplitSeq(strings.ToLower(v), ",") {
		if strings.TrimSpace(tok) == "close" {
			return true
		}
	}
	return false
}

// reusableResp reports whether the upstream may carry another request
// after this response: neither side asked to close, and an HTTP/1.0 origin
// did not default to close.
func reusableResp(req *httpwire.Request, resp *httpwire.Response) bool {
	if connClose(req.Get("Connection")) || connClose(resp.Get("Connection")) {
		return false
	}
	if resp.Proto == "HTTP/1.0" {
		for tok := range strings.SplitSeq(strings.ToLower(resp.Get("Connection")), ",") {
			if strings.TrimSpace(tok) == "keep-alive" {
				return true
			}
		}
		return false
	}
	return true
}

// replayBytes serializes a request whose body can be replayed on a fresh
// connection (no body, or a body already buffered in memory). The broker
// cannot rewind a streamed body. So it writes those requests straight
// through and never retries them.
func replayBytes(req *httpwire.Request) ([]byte, bool) {
	switch req.Body.(type) {
	case nil, *bytes.Reader:
	default:
		return nil, false
	}
	var buf bytes.Buffer
	if _, err := req.WriteTo(&buf); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// idempotent is RFC 9110 9.2.2. The origin may already have executed a
// request. The broker can send it a second time only when the second
// request has the same effect as the first. For any other request, an
// ambiguous completion is a failure to report, not a request to repeat.
func idempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return false
}

// dial connects to dst and completes the TLS handshake inside one
// originDialTimeout budget. dial sets the deadline on the raw connection,
// and the context also carries it. HandshakeContext obeys a cancelled
// context: it closes the connection from another goroutine. The socket
// deadline is the bound that holds even if that behavior ever changes.
func (b *Broker) dial(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
	budget := b.dialTimeout
	if budget <= 0 {
		budget = originDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if b.DialTLS != nil {
		return b.DialTLS(ctx, dst, sni)
	}
	var raw net.Conn
	var err error
	if b.dialTCP != nil {
		raw, err = b.dialTCP(ctx, dst.String())
	} else {
		var d net.Dialer
		raw, err = d.DialContext(ctx, "tcp", dst.String())
	}
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		RootCAs:    b.Roots,
		NextProtos: []string{"http/1.1"},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	// Cleared: from here idleOrigin bounds the leg by silence instead.
	_ = raw.SetDeadline(time.Time{})
	return tc, nil
}
