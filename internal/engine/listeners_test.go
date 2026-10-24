package engine

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func twoListeners(t *testing.T) (net.Listener, net.Listener) {
	t.Helper()
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	return a, b
}

// The agent address and the desk address share one cap. A desk that
// fills the engine must not get more than the cap by using a second
// listener.
func TestListenersShareTheCap(t *testing.T) {
	agent, desk := twoListeners(t)
	logs := &syncBuf{}
	e := &Engine{
		CA:        testStore(t),
		OrigDst:   func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.0.2.24:443"), nil },
		Handshake: 2 * time.Second,
		Idle:      time.Second,
		MaxConns:  1,
		Log:       log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, agent, desk) }()
	first, err := net.DialTimeout("tcp", agent.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.DialTimeout("tcp", desk.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("the second listener went past the cap: n=%d err=%v", n, err)
	}
	waitLog(t, logs, "max_conns=1 drop")
	cancel()
	first.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	for _, ln := range []net.Listener{agent, desk} {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Fatalf("%s still accepts after Serve returned", ln.Addr())
		}
	}
}

// When one listener fails, Serve stops the others and returns the error.
// systemd then restarts the whole engine, not half of it.
func TestOneListenerFailureStopsServe(t *testing.T) {
	agent, desk := twoListeners(t)
	e := &Engine{CA: testStore(t)}
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(context.Background(), agent, desk) }()
	time.Sleep(50 * time.Millisecond)
	desk.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after a listener failed")
	}
	if c, err := net.DialTimeout("tcp", agent.Addr().String(), time.Second); err == nil {
		c.Close()
		t.Fatal("the agent listener still accepts")
	}
}

func TestServeNeedsAListener(t *testing.T) {
	if err := (&Engine{}).Serve(context.Background(), nil); err == nil {
		t.Fatal("Serve with no listener returned nil")
	}
}

// A desk browser behind one address is not one agent. The inspect
// listener has its own cap for each source, and it does not use up the
// cap of the agent listener for the same address.
func TestInspectListenerHasItsOwnPerSourceCap(t *testing.T) {
	agent, desk := twoListeners(t)
	logs := &syncBuf{}
	e := &Engine{
		CA:                  testStore(t),
		OrigDst:             func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.0.2.24:443"), nil },
		Handshake:           5 * time.Second,
		MaxPerSource:        1,
		InspectMaxPerSource: 3,
		Log:                 log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, agent, desk) }()
	for i := range 3 {
		if !held(dialFrom(t, "127.0.0.1", desk.Addr().String())) {
			t.Fatalf("desk connection %d under the inspect cap was closed; log:\n%s", i+1, logs)
		}
	}
	if held(dialFrom(t, "127.0.0.1", desk.Addr().String())) {
		t.Fatal("fourth desk connection admitted over InspectMaxPerSource=3")
	}
	waitLog(t, logs, "max_conns_per_ip=3 drop")
	if !held(dialFrom(t, "127.0.0.1", agent.Addr().String())) {
		t.Fatal("the desk connections used up the agent cap of the same address")
	}
	if held(dialFrom(t, "127.0.0.1", agent.Addr().String())) {
		t.Fatal("second agent connection admitted over MaxPerSource=1")
	}
}

// flakyListener fails Accept with EMFILE while fails is above zero, then
// accepts on the real listener.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
	calls atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	if l.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

// An accept error that can pass (EMFILE, ENOBUFS) does not stop the
// engine. The loop waits, accepts again and serves the next agent.
func TestAcceptErrorIsRetried(t *testing.T) {
	agent, desk := twoListeners(t)
	ln := &flakyListener{Listener: agent}
	ln.fails.Store(3)
	logs := &syncBuf{}
	e := &Engine{
		CA:      testStore(t),
		OrigDst: func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.0.2.24:443"), nil },
		Log:     log.New(logs, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, ln, desk) }()
	c, err := net.DialTimeout("tcp", agent.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial after the accept errors: %v", err)
	}
	defer c.Close()
	if !held(c) {
		t.Fatalf("the connection after the accept errors was not served; log:\n%s", logs)
	}
	waitLog(t, logs, "too many open files")
	c.Close()
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

// A lasting accept error does not spin the loop: it backs off. A cancel
// during the backoff still stops Serve at once.
func TestAcceptErrorBacksOff(t *testing.T) {
	agent, desk := twoListeners(t)
	ln := &flakyListener{Listener: agent}
	ln.fails.Store(1 << 30)
	e := &Engine{CA: testStore(t), Log: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, ln, desk) }()
	select {
	case err := <-errc:
		t.Fatalf("Serve returned on an accept error: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// 5, 10, 20, 40, 80, 160 ms: about 7 calls in 300 ms.
	if n := ln.calls.Load(); n > 15 {
		t.Fatalf("%d accept calls in 300 ms; the loop does not back off", n)
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after cancel during the backoff")
	}
}
