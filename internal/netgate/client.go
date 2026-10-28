package netgate

// client.go is the client side, for pf dns and pf observe. It speaks the
// same messages (wire.go) as the server.

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"pi-fortress/internal/gateset"
)

const (
	// gateConns is the number of GATE requests that one pf dns can have
	// in progress at one time, each on its own connection. A request over
	// it waits for a free connection.
	gateConns = 16
	// gateWait limits one GATE request: the nft timeout of netgate, plus
	// time for the round trip and a full queue of forks.
	gateWait = gateset.Timeout + 2*time.Second
)

// GateClient is the GATE side of pf dns. Add and Refresh have the meaning
// of gateset.Cmd, and netgate does the write. When netgate is down, or
// it refuses the write, the error goes to the caller: pf dns then
// answers SERVFAIL, as it did for a failed nft.
type GateClient struct {
	path  string
	idle  chan *net.UnixConn
	slots chan struct{}
	wait  time.Duration
}

// NewGateClient makes a client for the socket at path. It dials nothing
// until the first request.
func NewGateClient(path string) *GateClient {
	return &GateClient{
		path:  path,
		idle:  make(chan *net.UnixConn, gateConns),
		slots: make(chan struct{}, gateConns),
		wait:  gateWait,
	}
}

// Add puts addrs into set. It skips each address that is not IPv4.
func (g *GateClient) Add(set string, addrs []netip.Addr) error {
	return g.do(opAdd, set, addrs)
}

// Refresh restarts the timeout of each of addrs in set (gateset.Cmd).
func (g *GateClient) Refresh(set string, addrs []netip.Addr) error {
	return g.do(opRefresh, set, addrs)
}

func (g *GateClient) do(op byte, set string, addrs []netip.Addr) error {
	v4 := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a)
		}
	}
	// As gateset.Cmd: no IPv4 address, no write.
	if len(v4) == 0 {
		return nil
	}
	msg, err := encodeGate(gateReq{op: op, set: set, addrs: v4})
	if err != nil {
		return err
	}
	g.slots <- struct{}{}
	defer func() { <-g.slots }()
	reply, err := g.roundTrip(msg)
	if err != nil {
		return err
	}
	status, why, err := decodeReply(reply)
	if err != nil {
		return err
	}
	return replyErr(status, why)
}

// roundTrip sends msg and reads the reply. A connection from the pool can
// be from a netgate that restarted since it was used last. If such a
// connection fails, one new connection is tried. A request that timed out
// is not tried again: netgate is there, but slow.
func (g *GateClient) roundTrip(msg []byte) ([]byte, error) {
	for tried := false; ; tried = true {
		c, reused, err := g.conn()
		if err != nil {
			return nil, err
		}
		reply, err := exchange(c, msg, g.wait)
		if err == nil {
			g.put(c)
			return reply, nil
		}
		c.Close()
		if !reused || tried || errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, err
		}
	}
}

func (g *GateClient) conn() (*net.UnixConn, bool, error) {
	select {
	case c := <-g.idle:
		return c, true, nil
	default:
	}
	c, err := dial(g.path)
	return c, false, err
}

func (g *GateClient) put(c *net.UnixConn) {
	select {
	case g.idle <- c:
	default:
		c.Close()
	}
}

func dial(path string) (*net.UnixConn, error) {
	return net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
}

// exchange writes msg on c and reads one reply, within wait.
func exchange(c *net.UnixConn, msg []byte, wait time.Duration) ([]byte, error) {
	if err := c.SetDeadline(time.Now().Add(wait)); err != nil {
		return nil, err
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	reply, err := readMsg(c, make([]byte, 2+maxReplyText+1))
	if err != nil {
		return nil, err
	}
	return reply, c.SetDeadline(time.Time{})
}

// Ping sends a GATE request with no address for set. netgate checks the
// peer and the set, uses one token of its rate, and runs no nft. It is
// the check that a client reaches netgate and passes its peer check.
func Ping(path, set string) error {
	msg, err := encodeGate(gateReq{op: opAdd, set: set})
	if err != nil {
		return err
	}
	c, err := dial(path)
	if err != nil {
		return err
	}
	defer c.Close()
	reply, err := exchange(c, msg, gateWait)
	if err != nil {
		return err
	}
	status, why, err := decodeReply(reply)
	if err != nil {
		return err
	}
	return replyErr(status, why)
}
