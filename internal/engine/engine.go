// Package engine is the pf engine daemon. It terminates redirected agent TLS,
// mints a leaf for the SNI, and gives the connection to the broker over the
// unix socket behind a preamble. internal/cli starts it.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/ca"
	"pi-fortress/internal/hello"
	"pi-fortress/internal/origdst"
	"pi-fortress/internal/peekconn"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/srclimit"
)

type Engine struct {
	Sock    string
	CA      *ca.Store
	OrigDst func(net.Conn) (netip.AddrPort, error)
	// Blocked is the compiled domain list. It is refused here, before a leaf
	// is minted. So a client that skipped the resolver gets the same nothing
	// that the sinkhole would give it.
	Blocked *blocklist.Set
	// Forward, when set, is paranoid mode (docs/paranoid_mode.md): an SNI
	// the oracle does not accept gets no leaf. It is the posture of the
	// agent network, so it does not apply on the inspect listeners. A
	// segment has its own PARANOID, in its resolver.
	Forward Forward
	// KeyShape, when set, names the rule for a key or a placeholder in an
	// SNI, or returns "" for neither. It is the check of pf dns
	// (internal/keyshape). An SNI that it flags gets no leaf, on all
	// listeners and in both DNS modes. It is a function, not the rules: as
	// with Forward, the engine never sees the kind column of the rules.
	KeyShape func(name string) string
	// LabEcho lets pf-core-echo.test through the oracle. Lab VM only.
	LabEcho   bool
	Handshake time.Duration
	Idle      time.Duration
	// MaxLife is the absolute ceiling, measured from accept. The default is
	// MaxLifetime. It is injectable so that a test need not wait an hour.
	// Production leaves it zero and gets the constant.
	MaxLife  time.Duration
	MaxConns int
	// MaxPerSource caps the connections that one agent address may hold inside
	// MaxConns. 0 is DefaultMaxPerSource, and a negative value disables the
	// cap. See DefaultMaxPerSource for the number.
	MaxPerSource int
	// InspectMaxPerSource is the same cap for the inspect listeners, with
	// its own table. 0 is DefaultInspectMaxPerSource, and a negative value
	// disables it.
	InspectMaxPerSource int
	Log                 *log.Logger
	sem                 chan struct{}
	perSrc              *srclimit.PerSource
	perSrcInspect       *srclimit.PerSource
	wg                  sync.WaitGroup
}

// DefaultMaxPerSource is a quarter of the global 256. With the global cap
// alone, one agent could pin each slot: a 10 s handshake window, then one
// byte per idle period, holds a connection up to the one-hour ceiling. Then
// no other agent on the segment gets HTTPS at all. 64 is still well past
// what one real agent opens at once: npm uses 16-50 sockets, and a headless
// browser six per host. The nft ct count of 128 per address on 80 and 8080
// is above it. So the daemon refuses first with a clean close, and the
// kernel rule is the backstop for flows that the daemon never holds. Four
// agents at the cap fill the engine, and that is the point. The rest is not
// reserved for any agent: it is only no longer for one address to take.
const DefaultMaxPerSource = 64

// DefaultInspectMaxPerSource is the cap for one address on a segment with
// INSPECT=on. One desk address carries a whole browser: many tabs, each
// with its own connections, and the tools of the operator. 64 is for one
// agent, and a busy browser goes above it. The global cap still holds.
const DefaultInspectMaxPerSource = 256

// MaxLifetime is the hard ceiling on how long one accepted connection may
// live, whatever it does. Idle bounds silence, and this bounds age. The two
// are intentionally separate limits. Without it, the only bound left was
// MaxConns, which caps concurrency, not lifetime. A hostile agent that
// moves one byte per idle period refreshes the idle deadline forever, and
// 256 such connections are each slot on the gateway.
//
// One hour is generous for real work: approximately 4.5 GB at 10 Mbit. That
// is much more than any model weight or container layer that an agent has
// a reason to pull. And it is finite, which is the full point.
//
// The accepted consequence: a long-lived WebSocket or SSE subscription is
// cut at one hour, and must connect again. That is not a bug, and not an
// oversight. A subscription no longer dies of idleness, because each
// direction refreshes the gap, as the relay of the broker does. So age is
// the only thing left that ends it. A fence for a hostile agent does not
// offer an unbounded hold on a finite slot. Do not "fix" this with a
// removal of the ceiling. The reconnect is the price of the bound.
const MaxLifetime = time.Hour

// Why a relay ended. There are three separate tokens, because an operator
// who reads the log must tell an imposed cut from a failure. A connection
// cut at exactly one hour with no explanation is a support ticket.
const (
	endClean    = ""                 // EOF: the peer closed, nothing to say
	endIdle     = "idle_timeout"     // nothing moved for Idle
	endCeiling  = "lifetime_ceiling" // age reached MaxLife
	endPeer     = "network"          // read or write failed on its own
	endShutdown = "shutdown"         // the engine is stopping, not the conn
)

// Forward is the paranoid-mode name oracle. It is an interface, not the
// corepolicy type that satisfies it: the engine is kept away from the kind
// tables and the secrets that they name (docs/privilege_split.md, K10).
type Forward interface {
	Allowed(name string, lab bool) bool
}

var errCertMismatch = errors.New("engine: tls server name does not match the parsed hello")

var errSNIKeyShape = errors.New("engine: tls server name has a key shape")

// keyShaped reports whether KeyShape flags name.
func (e *Engine) keyShaped(name string) bool {
	return e.KeyShape != nil && e.KeyShape(name) != ""
}

// testHookLeaf, when set, gets the name of each leaf that the engine asks
// the CA for. So a test can prove that a refused name never got a leaf. The
// log line that a test used to look for is written only when a handshake fails.
var testHookLeaf atomic.Pointer[func(sni string)]

// Serve accepts on ln, the agent address, and on inspect, the address of
// each segment with INSPECT=on. All listeners share MaxConns. The cap for
// each source is MaxPerSource on ln and InspectMaxPerSource on inspect.
// Serve returns when the context ends or when one listener is closed. Then
// it closes all of them. Other accept errors are retried with a backoff.
func (e *Engine) Serve(ctx context.Context, ln net.Listener, inspect ...net.Listener) error {
	if ln == nil {
		return errors.New("engine: no listener")
	}
	if e.Handshake <= 0 {
		e.Handshake = 10 * time.Second
	}
	if e.Idle <= 0 {
		e.Idle = 30 * time.Second
	}
	if e.MaxLife <= 0 {
		e.MaxLife = MaxLifetime
	}
	if e.MaxConns <= 0 {
		e.MaxConns = 256
	}
	if e.sem == nil {
		e.sem = make(chan struct{}, e.MaxConns)
	}
	if e.MaxPerSource == 0 {
		e.MaxPerSource = DefaultMaxPerSource
	}
	if e.perSrc == nil {
		e.perSrc = srclimit.New(e.MaxPerSource)
	}
	if e.InspectMaxPerSource == 0 {
		e.InspectMaxPerSource = DefaultInspectMaxPerSource
	}
	if e.perSrcInspect == nil {
		e.perSrcInspect = srclimit.New(e.InspectMaxPerSource)
	}
	lns := append([]net.Listener{ln}, inspect...)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		for _, ln := range lns {
			ln.Close()
		}
	}()
	defer e.wg.Wait()
	errs := make(chan error, len(lns))
	for i, ln := range lns {
		lim := e.perSrc
		if i > 0 {
			lim = e.perSrcInspect
		}
		go func() { errs <- e.accept(ctx, ln, lim, i > 0) }()
	}
	err := <-errs
	cancel()
	for range len(lns) - 1 {
		<-errs
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}

// Backoff after a failed accept, as in net/http: 5 ms, then double up to 1 s.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func (e *Engine) accept(ctx context.Context, ln net.Listener, perSrc *srclimit.PerSource, inspect bool) error {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A closed listener never accepts again, and a retry would only
			// spin. Return, and Serve stops the others: systemd restarts
			// the whole engine.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Other errors (EMFILE, ENFILE, ENOBUFS, ENOMEM, ECONNABORTED)
			// can pass. A return here would cut each live splice, so wait
			// and accept again.
			delay = min(max(2*delay, acceptBackoffMin), acceptBackoffMax)
			e.logf("accept: %v; retry in %v", err, delay)
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
			continue
		}
		delay = 0
		// The ceiling is measured from here, not from the first byte of
		// the relay. All that the connection costs the gateway starts at
		// accept. A client that stalls the handshake must not buy
		// itself a new hour.
		accepted := time.Now()
		select {
		case e.sem <- struct{}{}:
		default:
			e.logf("max_conns=%d drop src=%s", e.MaxConns, c.RemoteAddr())
			c.Close()
			continue
		}
		// Per source after the global slot, so a refused connection gives
		// its global slot back immediately. This is checked before any goroutine
		// or read. So an address at its cap costs the engine one accept and a
		// close, the same as the global-full path above.
		release, ok := perSrc.Acquire(c.RemoteAddr())
		if !ok {
			<-e.sem
			e.logf("max_conns_per_ip=%d drop src=%s", perSrc.Max(), c.RemoteAddr())
			c.Close()
			continue
		}
		e.wg.Add(1)
		go func(c net.Conn) {
			defer e.wg.Done()
			defer func() { <-e.sem }()
			defer release()
			defer func() {
				if r := recover(); r != nil {
					e.logf("panic src=%s: %v\n%s", c.RemoteAddr(), r, debug.Stack())
					c.Close()
				}
			}()
			e.handle(ctx, c, accepted, inspect)
		}(c)
	}
}

func (e *Engine) handle(ctx context.Context, c net.Conn, accepted time.Time, inspect bool) {
	defer c.Close()
	if e.CA == nil {
		return
	}
	dst, err := e.origDst(c)
	if err != nil {
		e.logf("origdst src=%s err=%v", c.RemoteAddr(), err)
		return
	}
	if dst.Port() != 443 {
		e.logf("origdst src=%s dst=%s refused: not port 443", c.RemoteAddr(), dst)
		return
	}
	_ = c.SetDeadline(time.Now().Add(e.Handshake))
	pc, err := peekconn.Wrap(c, peekconn.MaxPeek)
	if err != nil {
		e.logf("peek src=%s dst=%s err=%v", c.RemoteAddr(), dst, err)
		return
	}
	h, err := hello.Parse(pc.Prefix())
	if err != nil {
		e.logf("hello src=%s dst=%s err=%v", c.RemoteAddr(), dst, err)
		return
	}
	// A key in the SNI goes to the origin when the broker dials it. This
	// check runs before all lines that log the SNI. Thus the key also stays
	// out of the log. The hello is in lower case, and the placeholder check
	// is exact. Thus GetCertificate runs the check again on the name as sent.
	if e.keyShaped(h.SNI) {
		e.logf("sni key_shape refused src=%s dst=%s", c.RemoteAddr(), dst)
		return
	}
	if h.H2Only {
		e.logf("alpn_h2_only refused: engine speaks http/1.1 only sni=%s src=%s", h.SNI, c.RemoteAddr())
	}
	if h.SNI == "" {
		e.logf("sni empty refused src=%s dst=%s", c.RemoteAddr(), dst)
		return
	}
	if e.Blocked.Has(h.SNI) {
		e.logf("sni blocked refused sni=%s src=%s dst=%s", h.SNI, c.RemoteAddr(), dst)
		return
	}
	if e.Forward != nil && !inspect && !e.Forward.Allowed(h.SNI, e.LabEcho) {
		e.logf("sni paranoid refused sni=%s src=%s dst=%s", h.SNI, c.RemoteAddr(), dst)
		return
	}
	cfg := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi.ServerName == "" || !hello.ValidHostName(chi.ServerName) || !strings.EqualFold(chi.ServerName, h.SNI) {
				return nil, errCertMismatch
			}
			if e.keyShaped(chi.ServerName) {
				return nil, errSNIKeyShape
			}
			if hook := testHookLeaf.Load(); hook != nil {
				(*hook)(chi.ServerName)
			}
			return e.CA.LeafFor(chi.ServerName, dst.Addr())
		},
		NextProtos:             []string{"http/1.1"},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	tc := tls.Server(pc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		if errors.Is(err, errSNIKeyShape) {
			e.logf("sni key_shape refused src=%s dst=%s", c.RemoteAddr(), dst)
			return
		}
		e.logf("handshake sni=%s dst=%s err=%v", h.SNI, dst, err)
		return
	}
	defer tc.Close()
	// Dial the broker only for a client that finished a handshake, so a
	// flood of bare ClientHellos never holds broker connections.
	var broker net.Conn
	if e.Sock != "" {
		if broker, err = net.DialTimeout("unix", e.Sock, 2*time.Second); err != nil {
			broker = nil
		}
	}
	if broker != nil {
		defer broker.Close()
	}
	if broker == nil {
		e.logf("broker down sni=%s dst=%s", h.SNI, dst)
		_, _ = io.WriteString(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbroker\n")
		return
	}
	_ = tc.SetDeadline(time.Time{})
	_ = c.SetDeadline(time.Time{})
	p := &preamble.Preamble{
		ConnID:  connID(),
		Src:     addrPort(c.RemoteAddr()),
		OrigDst: dst,
		SNI:     h.SNI,
		ALPN:    tc.ConnectionState().NegotiatedProtocol,
	}
	if err := preamble.Encode(broker, p); err != nil {
		e.logf("preamble sni=%s dst=%s err=%v", h.SNI, dst, err)
		_, _ = io.WriteString(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 9\r\nConnection: close\r\n\r\npreamble\n")
		return
	}
	hard := accepted.Add(e.MaxLife)
	reason, rerr := splice(ctx, tc, broker, e.Idle, hard)
	age := time.Since(accepted).Round(time.Millisecond)
	switch reason {
	case endCeiling:
		// Different on purpose: this cut is the decision of the fence, not a
		// failure and not silence. An operator who sees it knows that the
		// connection was healthy, and that its hour ended.
		e.logf("relay end=%s conn=%s sni=%s src=%s dst=%s age=%s limit=%s: connection reached the absolute lifetime ceiling; a subscription must reconnect",
			endCeiling, p.ConnID, h.SNI, c.RemoteAddr(), dst, age, e.MaxLife)
	case endIdle:
		e.logf("relay end=%s conn=%s sni=%s src=%s dst=%s age=%s idle=%s: nothing moved in either direction for the idle gap",
			endIdle, p.ConnID, h.SNI, c.RemoteAddr(), dst, age, e.Idle)
	case endPeer:
		e.logf("relay end=%s conn=%s sni=%s src=%s dst=%s age=%s err=%v",
			endPeer, p.ConnID, h.SNI, c.RemoteAddr(), dst, age, rerr)
	case endShutdown:
		e.logf("relay end=%s conn=%s sni=%s src=%s dst=%s age=%s",
			endShutdown, p.ConnID, h.SNI, c.RemoteAddr(), dst, age)
	}
}

func (e *Engine) origDst(c net.Conn) (netip.AddrPort, error) {
	if e.OrigDst != nil {
		return e.OrigDst(c)
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, origdst.ErrNotTCP
	}
	return origdst.Get(tc)
}

func (e *Engine) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func connID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func addrPort(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}

// splice runs the relay and reports why it ended. It takes the context,
// because the idle deadlines cannot carry a shutdown. Each successful read
// refreshes them. So a relay that still moves bytes never times out on
// silence, and the agent chooses whether to continue to move them. The
// watcher of Serve closes only the listener. That stops new connections
// and leaves the established ones. Without this, wg.Wait in Serve never
// returns, and the agent decides how long shutdown takes. Cancellation
// closes both conns, and does not set a past deadline. touch resets the
// deadline on each pass, and would overwrite a deadline set from here. A
// closed conn stays closed, and unblocks a copy already parked in Read or Write.
//
// hard is the absolute ceiling (accept + MaxLife), and is the second, separate
// bound: idle kills silence, hard kills age. Each deadline that touch sets is
// clamped to it. So a connection that continues to refresh the idle gap still
// ends at hard, and the error it ends with is a timeout at or after hard.
// That is exactly how endReason tells a ceiling cut from an idle cut.
func splice(ctx context.Context, a, b net.Conn, idle time.Duration, hard time.Time) (string, error) {
	type outcome struct {
		reason string
		err    error
	}
	done := make(chan outcome, 2)
	stop := make(chan struct{})
	defer close(stop)
	// Read and write are set apart, and never through SetDeadline. The relay
	// runs both directions over the one connection, so a blanket deadline
	// set for one direction silently becomes the deadline of the other. Both
	// legs are refreshed on any progress in either direction. The websocket
	// relay of the broker already uses this policy underneath (relayWS touch).
	// A one-way subscription that never sends upstream is a connection that
	// does its job, and it must not die of idleness. The ceiling bounds it
	// instead.
	touch := func() {
		var dl time.Time
		if idle > 0 {
			dl = time.Now().Add(idle)
		}
		if !hard.IsZero() && (dl.IsZero() || dl.After(hard)) {
			dl = hard
		}
		if dl.IsZero() {
			return
		}
		_ = a.SetReadDeadline(dl)
		_ = a.SetWriteDeadline(dl)
		_ = b.SetReadDeadline(dl)
		_ = b.SetWriteDeadline(dl)
	}
	go func() {
		select {
		case <-ctx.Done():
			a.Close()
			b.Close()
		case <-stop:
		}
	}()
	go func() {
		err := copyIdle(a, b, touch)
		closeWrite(a)
		done <- outcome{endReason(err, hard), err}
	}()
	go func() {
		err := copyIdle(b, a, touch)
		closeWrite(b)
		done <- outcome{endReason(err, hard), err}
	}()
	first, second := <-done, <-done
	if ctx.Err() != nil {
		return endShutdown, ctx.Err()
	}
	// The direction that was cut wins over the direction that only noticed.
	// When the ceiling fires, both time out. When one side half-closes, the
	// other side reports a plain EOF, and it should not get the blame for it.
	if rank(second.reason) > rank(first.reason) {
		first = second
	}
	return first.reason, first.err
}

// endReason names the cut. A timeout at or past hard is the ceiling. Each
// deadline is clamped to hard, so an idle timeout can only land before it.
func endReason(err error, hard time.Time) string {
	if err == nil || errors.Is(err, io.EOF) {
		return endClean
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		if !hard.IsZero() && !time.Now().Before(hard) {
			return endCeiling
		}
		return endIdle
	}
	return endPeer
}

func rank(reason string) int {
	switch reason {
	case endCeiling:
		return 3
	case endIdle:
		return 2
	case endPeer:
		return 1
	}
	return 0
}

// copyIdle takes dst as a net.Conn, not an io.Writer, so that the write can
// also carry a deadline. Without one, the idle bound was half a bound. A
// client that asks for a large response and then reads nothing more parks
// this goroutine in Write forever. Then splice never gets its second done,
// handle never returns, and the connection slot never comes back. 256
// sockets held open that way are each slot on the gateway, and the agent
// is hostile. The deadlines come from touch in splice. touch carries both
// the idle gap and the absolute ceiling, and refreshes both legs. So
// progress in either direction counts as progress for the connection.
func copyIdle(dst, src net.Conn, touch func()) error {
	buf := make([]byte, 32*1024)
	for {
		touch()
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func closeWrite(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
	}
}
