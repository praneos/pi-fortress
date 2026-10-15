package dnsd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DNS over TLS is DNS over TCP inside TLS, and nothing more: RFC 7858
// port 853, the two-byte length prefix that TCP already uses, the same
// messages. This file is all of it. Thus the encrypted leg is code that
// we own, logged and fail-closed like the rest. It is not a second
// daemon with a second packaging story.
//
// There is no plaintext fallback in this file. A blocked 853 is an
// outage, not a downgrade. A fallback would give an observer the
// queries that the pins are there to hide.

const (
	dotPort = "853"
	// All callers that wait for the same address share one dial. So the
	// dial gets a shorter budget than the query. One slow handshake must
	// not use all of the deadline of a caller. It must also not stop the
	// queries in the queue behind it.
	dotDialTO = 3 * time.Second
	// The read deadline closes idle connections. A silence of this length
	// while queries are still pending is a dead connection in all cases.
	dotIdleTO = 30 * time.Second
	// Addresses tried per query. Two is enough when one pinned resolver is
	// down. It does not turn a global outage into a long stall.
	dotTries    = 2
	dotBackoff0 = 2 * time.Second
	dotBackoffM = 30 * time.Second
)

var errConnGone = errors.New("dot: connection closed while waiting")

// dotClient is the DoT leg for a segment: a pinned set of addresses,
// one pooled connection for each, round robin with a per-address
// backoff.
//
// The addresses are pinned IPs, not a name, because a lookup of the
// name of the resolver itself would be a loop. The name is still
// necessary, because the certificate must be valid for a name.
type dotClient struct {
	name   string
	addrs  []netip.Addr
	port   string
	iface  string // SO_BINDTODEVICE when set: the WireGuard house's tunnel
	tlsCfg *tls.Config
	now    func() time.Time

	mu    sync.Mutex
	conns map[netip.Addr]*dotConn
	dials map[netip.Addr]*dialing
	fails map[netip.Addr]int
	until map[netip.Addr]time.Time
	next  int
}

func newDoT(name string, addrs []netip.Addr, now func() time.Time) *dotClient {
	if now == nil {
		now = time.Now
	}
	return &dotClient{
		name:  name,
		addrs: append([]netip.Addr(nil), addrs...),
		port:  dotPort,
		tlsCfg: &tls.Config{
			// The client dials the pinned address, but the certificate must
			// be valid for the name from the operator. The pin says where. The
			// name says who. System roots, because a key pin would make
			// the next key rotation of the provider an outage.
			ServerName:         name,
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(8),
		},
		now:   now,
		conns: map[netip.Addr]*dotConn{},
		dials: map[netip.Addr]*dialing{},
		fails: map[netip.Addr]int{},
		until: map[netip.Addr]time.Time{},
	}
}

func (d *dotClient) exchange(ctx context.Context, req []byte) ([]byte, error) {
	if len(d.addrs) == 0 {
		return nil, errors.New("dot: no upstream addresses")
	}
	// One budget for the full query, not one for each attempt. In the past,
	// the response timer started after the dial and after the write. It
	// started again for the next address. So a caller with no deadline of
	// its own could spend the handshake of each attempt plus the wait of
	// each attempt on a silent upstream. For all of that time, the query
	// goroutine held a slot.
	caller := ctx
	ctx, cancel := context.WithTimeout(ctx, upstreamTO)
	defer cancel()
	var err error
	for try := 0; try < dotTries && try < len(d.addrs); try++ {
		var a netip.Addr
		a, err = d.pick()
		if err != nil {
			return nil, err
		}
		var c *dotConn
		if c, err = d.conn(ctx, a); err != nil {
			if caller.Err() != nil {
				return nil, err
			}
			d.failed(a)
			continue
		}
		var resp []byte
		if resp, err = c.roundtrip(ctx, req); err != nil {
			// A caller that ran out of time says nothing about the
			// connection or the address. In the past, the code took it as
			// evidence. It closed the shared connection, and so released every
			// query pipelined behind it. It also put the address in backoff. So one
			// impatient client cost the whole segment its upstream.
			if caller.Err() != nil {
				return nil, err
			}
			// Otherwise the connection is suspect, not only this query:
			// a framing error or a half-open socket would make every
			// query after it fail too.
			d.drop(a, c)
			d.failed(a)
			continue
		}
		if !isAnswerTo(req, resp) {
			// The id matched, but the message is not an answer to the question.
			// It can be a late reply to a query whose caller has already
			// stopped, a confused upstream, or a message whose
			// counts promise records that it does not have. This is not a reason
			// to distrust the connection, but it is also not an answer.
			err = errors.New("dot: reply does not answer the question asked")
			continue
		}
		d.worked(a)
		return resp, nil
	}
	return nil, err
}

// pick takes the next address in rotation that is not in backoff. When
// all addresses are in backoff, it returns the one whose backoff ends
// first, and lets the caller try it anyway. A total outage must be able
// to heal. If pick refused to dial, the outage would never heal.
func (d *dotClient) pick() (netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var best netip.Addr
	var bestAt time.Time
	for i := 0; i < len(d.addrs); i++ {
		a := d.addrs[d.next%len(d.addrs)]
		d.next++
		if u, ok := d.until[a]; !ok || !now.Before(u) {
			return a, nil
		} else if best == (netip.Addr{}) || u.Before(bestAt) {
			best, bestAt = a, u
		}
	}
	if best == (netip.Addr{}) {
		return netip.Addr{}, errors.New("dot: no upstream addresses")
	}
	return best, nil
}

func (d *dotClient) failed(a netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fails[a]++
	back := dotBackoff0 << (d.fails[a] - 1)
	if back > dotBackoffM || back <= 0 {
		back = dotBackoffM
	}
	d.until[a] = d.now().Add(back)
}

func (d *dotClient) worked(a netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.fails, a)
	delete(d.until, a)
}

func (d *dotClient) drop(a netip.Addr, c *dotConn) {
	d.mu.Lock()
	if d.conns[a] == c {
		delete(d.conns, a)
	}
	d.mu.Unlock()
	c.shutdown()
}

// dialing is a dial in progress. With it, a second query for the same
// address can wait for the connection of the first query. The second
// query holds no lock while it waits.
type dialing struct {
	done chan struct{}
	c    *dotConn
	err  error
}

// conn returns the pooled connection for a. If there is none, it dials
// one.
//
// In the past, the dial ran under the client-wide lock. This stopped two
// queries in a race on a cold address from opening two connections. It
// also made one cold address a problem for the whole segment. A
// handshake that hangs held the lock for its full dotDialTO, so every
// query behind it stopped. This included the queries for an address
// that answered correctly. Now the other queries only wait on a
// per-address dial. This keeps the one-connection guarantee, and it
// costs only the address that it is about.
func (d *dotClient) conn(ctx context.Context, a netip.Addr) (*dotConn, error) {
	d.mu.Lock()
	if c, ok := d.conns[a]; ok {
		if !c.gone() {
			d.mu.Unlock()
			return c, nil
		}
		delete(d.conns, a)
	}
	if dl, ok := d.dials[a]; ok {
		d.mu.Unlock()
		select {
		case <-dl.done:
			return dl.c, dl.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	dl := &dialing{done: make(chan struct{})}
	d.dials[a] = dl
	d.mu.Unlock()

	// The dial has its own context, separate from the context of this
	// caller, because other callers share the connection that it makes. A
	// caller that leaves must not cancel the dial, and the connection, for
	// all callers that wait behind it. dotDialTO bounds the dial instead.
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dotDialTO)
	defer cancel()
	dialer := &tls.Dialer{Config: d.tlsCfg, NetDialer: udpExchanger{iface: d.iface}.dialer()}
	nc, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(a.String(), d.port))

	d.mu.Lock()
	delete(d.dials, a)
	if err == nil {
		dl.c = &dotConn{c: nc, wait: map[uint16]chan []byte{}}
		d.conns[a] = dl.c
	}
	dl.err = err
	d.mu.Unlock()
	close(dl.done)
	if err != nil {
		return nil, err
	}
	go dl.c.read()
	return dl.c, nil
}

// close drops every pooled connection. Only tests call it. The daemon
// keeps its client for the life of the process.
func (d *dotClient) close() {
	d.mu.Lock()
	conns := make([]*dotConn, 0, len(d.conns))
	for a, c := range d.conns {
		conns = append(conns, c)
		delete(d.conns, a)
	}
	d.mu.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
}

// dotConn is one TLS connection that carries many queries at the same
// time. A single reader goroutine owns Read. It gives each answer to the
// caller that waits on its id. Writers serialise on mu. This also stops
// two queries from mixing their bytes into one TLS record.
type dotConn struct {
	c net.Conn

	mu     sync.Mutex
	closed bool
	wait   map[uint16]chan []byte
}

func (c *dotConn) gone() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *dotConn) roundtrip(ctx context.Context, req []byte) ([]byte, error) {
	// Each query gets a new random id, as on the UDP path. The id must
	// also be free on this connection, because pipelining is what makes a
	// collision possible.
	ch := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errConnGone
	}
	var id uint16
	for {
		var err error
		if id, err = randomID(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if _, taken := c.wait[id]; !taken {
			break
		}
	}
	c.wait[id] = ch
	out := patchID(req, id)
	frame := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(out)))
	copy(frame[2:], out)
	_ = c.c.SetWriteDeadline(c.deadline(ctx))
	_, err := c.c.Write(frame)
	c.mu.Unlock()
	if err != nil {
		c.forget(id)
		return nil, err
	}

	timer := time.NewTimer(upstreamTO)
	defer timer.Stop()
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errConnGone
		}
		return resp, nil
	case <-ctx.Done():
		c.forget(id)
		return nil, ctx.Err()
	case <-timer.C:
		c.forget(id)
		return nil, errors.New("dot: upstream did not answer")
	}
}

func (c *dotConn) deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(upstreamTO)
}

// forget removes a caller that has abandoned its query. Then a late
// answer does not leave its entry, and its channel, in the map forever.
func (c *dotConn) forget(id uint16) {
	c.mu.Lock()
	delete(c.wait, id)
	c.mu.Unlock()
}

func (c *dotConn) read() {
	defer c.shutdown()
	var hdr [2]byte
	for {
		_ = c.c.SetReadDeadline(time.Now().Add(dotIdleTO))
		if _, err := io.ReadFull(c.c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		// Anything shorter than a header is not a message, and the
		// length prefix cannot describe one longer than maxMsg.
		if n < 12 || n > maxMsg {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c.c, msg); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(msg[:2])
		c.mu.Lock()
		if ch, ok := c.wait[id]; ok {
			delete(c.wait, id)
			// Buffered, and the only send, so this cannot block even
			// if the caller has already left.
			ch <- msg
		}
		c.mu.Unlock()
	}
}

// shutdown closes the connection and releases every caller that still
// waits on it. So a dead upstream costs them an error, not their full
// deadline.
func (c *dotConn) shutdown() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	for id, ch := range c.wait {
		delete(c.wait, id)
		close(ch)
	}
	c.mu.Unlock()
	_ = c.c.Close()
}
