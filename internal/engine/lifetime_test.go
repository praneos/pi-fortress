package engine

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/preamble"
)

// heartbeatBroker is a stand-in for an origin server behind the broker that
// pushes a one-way stream: a websocket subscription or an SSE feed. It
// answers the preamble, then writes one byte downstream each period, and
// never reads anything useful from the client. upEOF reports whether the
// engine ever half-closed the upstream leg. That is how the client-to-origin
// copy direction announces that it stopped its wait for a silent client.
type heartbeatBroker struct {
	sock  string
	upEOF atomic.Bool
	beats atomic.Int64
}

func startHeartbeatBroker(t *testing.T, period time.Duration) *heartbeatBroker {
	t.Helper()
	hb := &heartbeatBroker{sock: filepath.Join(t.TempDir(), "hb.sock")}
	ln, err := net.Listen("unix", hb.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := preamble.Decode(br); err != nil {
					return
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					// A real broker ends the session when the
					// engine half-closes the leg that it reads requests on.
					buf := make([]byte, 1024)
					for {
						if _, err := c.Read(buf); err != nil {
							if err == io.EOF {
								hb.upEOF.Store(true)
							}
							return
						}
					}
				}()
				tick := time.NewTicker(period)
				defer tick.Stop()
				for {
					select {
					case <-done:
						return
					case <-t.Context().Done():
						return
					case <-tick.C:
						if _, err := c.Write([]byte{'.'}); err != nil {
							return
						}
						hb.beats.Add(1)
					}
				}
			}(c)
		}
	}()
	return hb
}

// TestOneWaySubscriptionSurvivesIdleGap: the client is a valid
// subscriber. It opened the stream, and then legitimately sends nothing
// upstream while the origin server pushes events down. Each copy direction
// used to refresh only the read deadline of its own source. So the silent
// client-to-origin direction timed out at Idle, and called closeWrite on
// the broker leg. That killed a session that moved bytes the full time.
// The websocket relay of the broker resets the gap in either direction
// (internal/broker/ws.go relayWS touch). The splice in front of it must
// agree.
func TestOneWaySubscriptionSurvivesIdleGap(t *testing.T) {
	const idle = 300 * time.Millisecond
	hb := startHeartbeatBroker(t, idle/4)
	orig := netip.MustParseAddrPort("192.0.2.50:443")
	addr, store, logs, _ := startEngineWith(t, hb.sock, orig, nil, func(e *Engine) {
		e.Idle = idle
	})
	tc := clientTLS(t, addr, "example.com", store, nil)
	buf := make([]byte, 64)
	got := 0
	deadline := time.Now().Add(6 * idle)
	for time.Now().Before(deadline) {
		_ = tc.SetReadDeadline(time.Now().Add(2 * idle))
		n, err := tc.Read(buf)
		got += n
		if err != nil {
			t.Fatalf("downstream died after %d bytes over a one-way subscription: %v, upstream_eof=%v, logs=%q",
				got, err, hb.upEOF.Load(), logs.String())
		}
	}
	if hb.upEOF.Load() {
		t.Fatalf("engine half-closed the upstream leg on a subscription that never went silent downstream; got %d bytes, logs=%q", got, logs.String())
	}
	if got < 10 {
		t.Fatalf("only %d bytes over %v, expected a steady stream", got, 6*idle)
	}
}

// TestLifetimeCeilingCutsMarginallyActiveConnection: a client that moves
// one byte inside each idle period refreshes the idle deadline forever.
// So nothing bounds how long it holds its slot. MaxConns caps concurrency,
// not lifetime, and 256 such connections are each slot on the gateway.
// There must be an absolute ceiling, measured from accept.
func TestLifetimeCeilingCutsMarginallyActiveConnection(t *testing.T) {
	const idle = 200 * time.Millisecond
	const life = 600 * time.Millisecond
	hb := startHeartbeatBroker(t, idle/4)
	orig := netip.MustParseAddrPort("192.0.2.51:443")
	addr, store, logs, _ := startEngineWith(t, hb.sock, orig, nil, func(e *Engine) {
		e.Idle = idle
		e.MaxLife = life
		e.MaxConns = 1
	})
	start := time.Now()
	tc := clientTLS(t, addr, "example.com", store, nil)
	buf := make([]byte, 64)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(4 * life))
		if _, err := tc.Read(buf); err != nil {
			break
		}
		if time.Since(start) > 4*life {
			t.Fatalf("connection still alive %v after accept, ceiling %v never fired, logs=%q", time.Since(start), life, logs.String())
		}
	}
	age := time.Since(start)
	if age < life/2 {
		t.Fatalf("connection ended after %v, well short of the %v ceiling: idle, not the ceiling, cut it", age, life)
	}
	// The slot must come back with the connection.
	time.Sleep(idle)
	if !slotFree(t, addr) {
		t.Fatalf("slot still held after the ceiling cut the connection, logs=%q", logs.String())
	}
}

// TestLifetimeCeilingLogsDistinctly is requirement 3: a connection cut at
// the ceiling must be legible as that cut, and must not look like silence
// or a broken network. The three reasons carry three different tokens.
func TestLifetimeCeilingLogsDistinctly(t *testing.T) {
	const idle = 200 * time.Millisecond
	const life = 500 * time.Millisecond
	hb := startHeartbeatBroker(t, idle/4)
	orig := netip.MustParseAddrPort("192.0.2.52:443")
	addr, store, logs, _ := startEngineWith(t, hb.sock, orig, nil, func(e *Engine) {
		e.Idle = idle
		e.MaxLife = life
	})
	tc := clientTLS(t, addr, "example.com", store, nil)
	buf := make([]byte, 64)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(4 * life))
		if _, err := tc.Read(buf); err != nil {
			break
		}
	}
	time.Sleep(idle)
	got := logs.String()
	if !strings.Contains(got, "relay end=lifetime_ceiling") {
		t.Fatalf("no ceiling line in the log: %q", got)
	}
	if strings.Contains(got, "relay end=idle_timeout") || strings.Contains(got, "relay end=network") {
		t.Fatalf("ceiling cut logged as idle or network: %q", got)
	}
	for _, want := range []string{"age=", "limit=", "sni=example.com", "conn="} {
		if !strings.Contains(got, want) {
			t.Fatalf("ceiling line missing %q: %q", want, got)
		}
	}
}

// TestIdleCutLogsDistinctly is the other half of the same requirement. A
// connection that went quiet in both directions is cut for silence, well
// inside its hour, and says so.
func TestIdleCutLogsDistinctly(t *testing.T) {
	const idle = 200 * time.Millisecond
	sock := startStreamBroker(t, 0)
	orig := netip.MustParseAddrPort("192.0.2.53:443")
	addr, store, logs, _ := startEngineWith(t, sock, orig, nil, func(e *Engine) {
		e.Idle = idle
		e.MaxLife = time.Hour
	})
	tc := clientTLS(t, addr, "example.com", store, nil)
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * idle)
	got := logs.String()
	if !strings.Contains(got, "relay end=idle_timeout") {
		t.Fatalf("no idle line in the log: %q", got)
	}
	if strings.Contains(got, "relay end=lifetime_ceiling") {
		t.Fatalf("idle cut logged as the ceiling: %q", got)
	}
}

// TestMaxLifetimeDefault pins the production default to the constant, so a
// deployment that never sets MaxLife still gets the hour.
func TestMaxLifetimeDefault(t *testing.T) {
	if MaxLifetime != time.Hour {
		t.Fatalf("MaxLifetime=%v, the owner decided one hour", MaxLifetime)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e := &Engine{CA: testStore(t), Log: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ctx, ln) }()
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}
	// Serve returned, so the writes that fill its defaults are visible here.
	if e.MaxLife != MaxLifetime {
		t.Fatalf("MaxLife=%v, want the %v default", e.MaxLife, MaxLifetime)
	}
}
