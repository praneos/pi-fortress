package engine

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
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
