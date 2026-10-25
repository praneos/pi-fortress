package dnsd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"pi-fortress/internal/srclimit"
)

const rebindWait = 3 * time.Second

// bindLogEvery is the interval at which an isolated segment that never
// bound reports the failure again, after it has the BROKEN mark.
const bindLogEvery = time.Minute

// bindGrace is how long a transport can fail to start at all before Run
// stops the attempts for it and ends the process.
//
// It applies only to the initial bind. The two cases are different
// failures. A socket that never bound one time has a configuration that
// cannot work: an address that is not on this box, a port that is
// already in use, an interface that will never exist, or no CAP_NET_RAW.
// More time does not fix it. Meanwhile, the process stays up and the unit
// stays healthy, with no resolver behind it. A socket that served and
// then lost its address has a cable, adapter or reconfiguration problem.
// To kill a resolver that still serves its other segments, for a problem
// that heals in seconds, is the worse trade. That socket retries forever,
// as it always did.
//
// A minute is longer than the time an interface needs to start after the
// unit starts. It is also short enough that an operator who just made a
// bad segment configuration sees the unit fail, not a silence.
const bindGrace = 60 * time.Second

// Run serves every segment until ctx is done.
//
// Each segment gets one UDP socket and one TCP listener. Each is bound to
// the address of that segment and pinned to its interface with
// SO_BINDTODEVICE. The first proposal was one wildcard socket, with
// IP_PKTINFO to demultiplex. That needs x/net/ipv4, which needs x/sys,
// but the message codec alone needs nothing outside the standard library.
// A bind to the address is also the stricter of the two. No socket can
// answer on the uplink at all. The other design has a socket that must
// remember not to answer there. The reply then leaves from the address
// that the query went to, without an instruction.
//
// The wildcard socket gave one advantage: it survived an address that
// appears and disappears. NetworkManager keeps the address of a segment
// on the interface when the interface has no carrier. Thus a pulled cable
// does not remove the address. For an interface that is really absent, a
// timer rebinds the socket. An interface that comes back with a new index
// (a USB adapter that was plugged in again) gets its listeners opened again
// by watchLinks (linkwatch.go).
func (s *Server) Run(ctx context.Context) error {
	if err := s.OpenLogs(); err != nil {
		return err
	}
	defer s.CloseLogs()
	// Deferred after CloseLogs, so it runs before CloseLogs. Both wait for
	// the s.queries.Wait below, so no query can assign at that time. It is
	// before the open, so if a second pool fails, the first still closes.
	defer s.closeFake()
	if err := s.openFake(); err != nil {
		return err
	}
	// This code reports a transport that never started. It does not retry it
	// in silence. Before, the loops returned nothing and this code collected
	// nothing. Thus a resolver that could not bind kept the process alive and
	// the unit healthy. The only evidence that a segment had no resolver was
	// that nothing on it resolved. All that is downstream waits on DNS. Thus
	// the failure must reach systemd, which restarts the unit and continues
	// to report it in the journal.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2*len(s.segs))
	fail := func(err error) {
		if err == nil {
			return
		}
		errs <- err
		// One dead transport stops all the others. Half a resolver, for example
		// TCP without UDP or one segment of three, is the failure that looks like
		// a working resolver. The unit that starts again either serves all of it
		// or fails again visibly.
		cancel()
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.sweepLogs(ctx) }()
	if s.watchesLinks() {
		wg.Add(1)
		go func() { defer wg.Done(); s.watchLinks(ctx) }()
	}
	for _, seg := range s.segs {
		wg.Add(2)
		go func() { defer wg.Done(); fail(s.udpLoop(ctx, seg)) }()
		go func() { defer wg.Done(); fail(s.tcpLoop(ctx, seg)) }()
		if seg.SNIQueue != 0 {
			wg.Add(1)
			go func() { defer wg.Done(); s.sniLoop(ctx, seg) }()
		}
	}
	<-ctx.Done()
	wg.Wait()
	// The end of the loops is not the end of the work that they started. A
	// query goroutine can continue after its listener stops, for as long as
	// its upstream needs. The CloseLogs deferred above would then remove the
	// log from under it. The result is an unsynchronised write against reads
	// that are still in progress, and a lost reply line at each shutdown.
	s.queries.Wait()
	close(errs)
	// The first failure explains the others. The others are the effect of
	// the cancel above on the other loops. An empty channel is a clean
	// shutdown and gives nil.
	return <-errs
}

func (s *Server) addr(seg *Segment) string {
	return net.JoinHostPort(seg.IP.String(), strconv.Itoa(s.cfg.Listen))
}

// control pins a socket to the interface of the segment, so the socket
// does not serve a packet that reached the address by a different path.
// The refusal goes into pinErr, and refusePin changes it into a closed
// socket. On Linux, a bind to the address alone does not authorize the
// ingress interface. Thus an unpinned socket listens wider than the
// segment asked for.
func (s *Server) control(seg *Segment, pinErr *error) func(string, string, syscall.RawConn) error {
	if seg.Iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			*pinErr = s.pinDev(int(fd), seg.Iface)
		})
	}
}

// refusePin fails a bind when it could not pin the socket to its
// interface. An unpinned socket would answer all that reaches the address
// by any route. The segment exists to draw that boundary. Thus this
// function fails closed and lets retry try again. An interface that is
// not up yet heals. A box without CAP_NET_RAW never heals, and must
// report it loudly, not quietly serve wider than asked. retry does not
// log, so this function writes the line here, on each attempt.
func (s *Server) refusePin(seg *Segment, network string, err error) error {
	if err == nil {
		return nil
	}
	s.logf("dns %s %s: refusing to serve %s unpinned: SO_BINDTODEVICE failed (needs CAP_NET_RAW): %v",
		seg.Iface, network, s.addr(seg), err)
	return fmt.Errorf("segment %q: cannot pin %s to %s: %w", seg.Name, network, seg.Iface, err)
}

// retry runs bind until ctx is done, with a wait between attempts. An
// interface that is not up yet, or one with an unplugged adapter, is the
// expected reason for a failure and for a new attempt.
//
// retry reports each failure. Silent retries made a transport that never
// started look the same as one that serves. Examples are a typo in the
// address, a port that is already in use, or an interface that will
// never return. The process stays up, so systemd sees a healthy unit. The
// only evidence that the segment has no resolver is that nothing
// resolves. One line for each attempt is the cheapest signal that cannot
// look like a working resolver.
//
// But a line in the journal is evidence only for a person who reads it.
// bind calls up when the listener starts to serve. If a transport does
// not get there in bindGrace, retry stops and returns an error. The error
// ends the process, and systemd restarts the unit. After the call to up,
// retry continues for the socket while ctx lasts: a rebind that heals
// must not stop a working resolver.
//
// An isolatable segment (a house segment or a plain segment, when the
// daemon runs) is the exception. Without this exception, a desk adapter
// that is missing at boot would stop the DNS of the agent and of all
// other networks. The restart would fail the same way. retry tries this
// segment while ctx lasts and marks it BROKEN in Segments until it binds.
// After the grace, it writes its failures once a minute, not once for
// each attempt.
//
// A listener that the watcher closed for a new interface index returns
// errRebind. retry does not log it and binds again at once. A sweep of the
// watcher also wakes a retry that waits after a failure, for example for an
// address that is not back yet. Each of these fast binds comes at least
// rebindGap after the bind before it.
func (s *Server) retry(ctx context.Context, seg *Segment, network string, bind func(up func()) error) error {
	start := time.Now()
	served := false
	isolate := s.isolates(seg)
	kick := seg.pins.kicker(network)
	var said time.Time
	for {
		began := time.Now()
		err := bind(func() {
			served = true
			if seg.setUnbound(network, nil) {
				s.logf("pf dns: segment %q %s %s is serving", seg.Name, network, s.addr(seg))
			}
		})
		if ctx.Err() != nil {
			return nil
		}
		rebind := errors.Is(err, errRebind)
		marked := seg.unboundWhy(network) != nil
		if err != nil && !rebind && (!marked || time.Since(said) >= bindLogEvery) {
			s.logf("dns %s %s: %s is not serving: %v; retrying in %s", seg.Iface, network, s.addr(seg), err, s.rebindWait)
			if marked {
				said = time.Now()
			}
		}
		if !served && time.Since(start) >= s.bindGrace {
			if err == nil {
				err = errors.New("listener closed without serving")
			}
			gave := fmt.Errorf("segment %q: %s %s never came up in %s: %w", seg.Name, network, s.addr(seg), s.bindGrace, err)
			if !isolate {
				return gave
			}
			why := err.Error()
			if seg.setUnbound(network, &why) {
				said = time.Now()
				s.logf("pf dns: %v; the other segments keep serving and this one is retried (BROKEN until it binds)", gave)
			}
		}
		wait, fast := s.rebindWait, rebind
		if rebind {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		case <-kick:
			fast = true
		}
		if d := s.rebindGap - time.Since(began); fast && d > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(d):
			}
		}
	}
}

func (s *Server) udpLoop(ctx context.Context, seg *Segment) error {
	slots := make(chan struct{}, s.udpSlots)
	return s.retry(ctx, seg, "udp", func(up func()) error {
		idx := s.ifIndex(seg)
		var pinErr error
		lc := net.ListenConfig{Control: s.control(seg, &pinErr)}
		pc, err := lc.ListenPacket(ctx, "udp4", s.addr(seg))
		if err != nil {
			return err
		}
		if err := s.refusePin(seg, "udp", pinErr); err != nil {
			pc.Close()
			return err
		}
		defer pc.Close()
		p, err := s.hold(seg, "udp", idx, pc.Close)
		if err != nil {
			return err
		}
		defer seg.pins.release("udp", p)
		// Bound and pinned. From here, each failure of this socket is a rebind,
		// not a transport that never started.
		up()
		s.noteServing(seg, idx)
		// AfterFunc, not a goroutine that waits on ctx: a goroutine stays for
		// each rebind until the process stops.
		defer context.AfterFunc(ctx, func() { _ = pc.Close() })()
		uc := pc.(*net.UDPConn)
		buf := make([]byte, maxMsg)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return p.why(err)
			}
			if n < 12 {
				continue
			}
			// One goroutine for each query: the forward step waits on the upstream
			// and on nft. A serial loop would make the latency of one slow name the
			// latency of the whole segment. The count is bounded, so a flood costs
			// dropped queries that the clients retry, not a heap without limit.
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			src, _ := netip.AddrFromSlice(from.IP.To4())
			req := make([]byte, n)
			copy(req, buf[:n])
			s.queries.Add(1)
			go func() {
				defer s.queries.Done()
				defer func() { <-slots }()
				msg := s.answer(ctx, seg, src, req, clientUDPSize(req))
				if msg == nil {
					return
				}
				_, _ = uc.WriteToUDP(msg, from)
			}()
		}
	})
}

func (s *Server) tcpLoop(ctx context.Context, seg *Segment) error {
	slots := make(chan struct{}, s.tcpSlots)
	// Made here with slots, outside the retry closure. A rebind must not give
	// a client a new count while the server still serves its old
	// connections. In the same way, a rebind does not give out new slots.
	perSrc := srclimit.New(s.tcpPerSource)
	return s.retry(ctx, seg, "tcp", func(up func()) error {
		idx := s.ifIndex(seg)
		var pinErr error
		lc := net.ListenConfig{Control: s.control(seg, &pinErr)}
		ln, err := lc.Listen(ctx, "tcp4", s.addr(seg))
		if err != nil {
			return err
		}
		if err := s.refusePin(seg, "tcp", pinErr); err != nil {
			ln.Close()
			return err
		}
		defer ln.Close()
		p, err := s.hold(seg, "tcp", idx, ln.Close)
		if err != nil {
			return err
		}
		defer seg.pins.release("tcp", p)
		up()
		s.noteServing(seg, idx)
		defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
		for {
			c, err := ln.Accept()
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				return p.why(err)
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = c.Close()
				continue
			}
			// After the segment slot, so a refusal gives the slot back immediately.
			// The code closes the connection at once and does not log it. A line for
			// each refused connection is exactly what a flood would change into
			// journal volume. This path has no limiter of its own, but the query log
			// has one.
			release, ok := perSrc.Acquire(c.RemoteAddr())
			if !ok {
				<-slots
				_ = c.Close()
				continue
			}
			s.queries.Add(1)
			go func() {
				defer s.queries.Done()
				defer func() { <-slots }()
				defer release()
				s.serveConn(ctx, seg, c)
			}()
		}
	})
}

func (s *Server) serveConn(ctx context.Context, seg *Segment, c net.Conn) {
	defer c.Close()
	// A close of the listener does not affect a connection that it already
	// accepted. Without this, the loop would wait on its read deadline for
	// one more tcpReadTO after the server got the stop signal.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	var src netip.Addr
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		src, _ = netip.AddrFromSlice(ra.IP.To4())
	}
	for {
		if err := c.SetDeadline(time.Now().Add(tcpReadTO)); err != nil {
			return
		}
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < 12 {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		// Over TCP there is nothing to truncate for.
		msg := s.answer(ctx, seg, src, req, 0)
		if msg == nil {
			return
		}
		out := tcpFrame(msg)
		if out == nil {
			return
		}
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// tcpFrame is msg with its two-byte length prefix. It is nil for a
// message that the prefix cannot count. The low 16 bits of the length
// would tell the client to read a different message.
func tcpFrame(msg []byte) []byte {
	if len(msg) > maxMsg {
		return nil
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}
