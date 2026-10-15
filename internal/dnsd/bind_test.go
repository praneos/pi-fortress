package dnsd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// unbindableServer is a one-segment server whose address is not on this
// box (RFC 5737 TEST-NET-1). Thus each bind fails with EADDRNOTAVAIL, and
// no listener ever starts.
func unbindableServer(t *testing.T) *Server {
	t.Helper()
	needUnbindable(t)
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   freePort(t),
		NFT:      discardNFT{},
		Segments: []Segment{{
			IP:            netip.MustParseAddr("192.0.2.1"),
			Iface:         "lo",
			Upstream:      "127.0.0.1:9",
			SinkholeFiles: []string{sink},
			NFTSet:        "resolved_v4",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.logf = func(string, ...any) {}
	srv.bindGrace = 200 * time.Millisecond
	srv.rebindWait = 10 * time.Millisecond
	return srv
}

// A transport that can never bind kept the process up and the unit
// healthy. retry ignored each failure, the loops returned nothing, and Run
// collected nothing. The only sign that a segment had no resolver was that
// no name resolved. The full fence waits on DNS. Thus a listener that
// never starts must stop the process, so that systemd restarts it.
func TestRunFailsWhenAListenerNeverBinds(t *testing.T) {
	srv := unbindableServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := srv.Run(ctx)
	if err == nil {
		t.Fatal("Run returned nil for a segment whose listener never bound: the unit stays healthy with no resolver")
	}
	if ctx.Err() != nil {
		t.Fatalf("Run only returned when the context expired: %v", err)
	}
	if !strings.Contains(err.Error(), "never came up") || !strings.Contains(err.Error(), "192.0.2.1") {
		t.Fatalf("error %q does not say which listener never came up", err)
	}
}

// Run is responsible for each transport of each segment, not only the
// first. A UDP socket that starts while TCP never starts is half a
// resolver. The half that works makes the failure look like success.
func TestRunFailsWhenOneTransportNeverBinds(t *testing.T) {
	srv := unbindableServer(t)
	seg := srv.segs[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.tcpLoop(ctx, seg); err == nil {
		t.Fatal("tcpLoop returned nil for a listener that never bound")
	}
	if err := srv.udpLoop(ctx, seg); err == nil {
		t.Fatal("udpLoop returned nil for a socket that never bound")
	}
}

// The two failures are different. A socket that never bound one time is a
// configuration that cannot work. A socket that served and then lost its
// address is a cable or a reconfiguration. To stop the process because of
// one would cost the segments that still serve.
func TestARebindAfterServingIsRetriedNotFatal(t *testing.T) {
	srv := unbindableServer(t)
	var attempts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.retry(ctx, srv.segs[0], "udp", func(up func()) error {
			// It binds and serves one time, then loses the address. This repeats for
			// longer than the grace period of a first bind.
			up()
			attempts.Add(1)
			return errors.New("bind: cannot assign requested address")
		})
	}()
	eventually(t, "several rebind attempts past the grace", func() bool { return attempts.Load() >= 3 })
	select {
	case err := <-done:
		t.Fatalf("a resolver that served and then lost its address was killed: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancel returned %v, want a clean stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retry did not return after cancel")
	}
}

// The other half: the retry stops for a bind that never serves. Thus the
// caller has something to return, and systemd has something to restart.
func TestAListenerThatNeverServesIsGivenUp(t *testing.T) {
	srv := unbindableServer(t)
	var attempts atomic.Int32
	err := srv.retry(context.Background(), srv.segs[0], "tcp", func(up func()) error {
		attempts.Add(1)
		return errors.New("listen: address already in use")
	})
	if err == nil {
		t.Fatal("retry returned nil for a listener that never served")
	}
	if attempts.Load() < 1 {
		t.Fatal("retry never tried to bind")
	}
}

// needUnbindable skips a test that needs bind(2) to refuse an address that
// this host does not own. With net.ipv4.ip_nonlocal_bind=1, the kernel
// accepts all addresses and 192.0.2.1 binds. Then the tests cannot cause
// the failure that they examine. Keepalived, some VPN clients and container
// setups enable it. A CI box or the Pi has it off.
func needUnbindable(t *testing.T) {
	t.Helper()
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_nonlocal_bind"); err == nil && strings.TrimSpace(string(b)) == "1" {
		t.Skip("net.ipv4.ip_nonlocal_bind=1 on this host: bind accepts an address it does not own, so a listener cannot be made to fail")
	}
}

// Before, a desk or house interface that was missing at boot stopped the
// process after the grace period. This took down DNS for the agent and for
// all other networks. The systemd restart then failed in the same way. Now
// the daemon retries an isolatable segment that does not bind for as long
// as the daemon runs, and shows it as BROKEN. The agent segment continues
// to answer. The listener of the agent itself still stops the process
// (TestRunFailsWhenAListenerNeverBinds).
func TestAnUnbindableDeskDoesNotTakeTheAgentDown(t *testing.T) {
	needUnbindable(t)
	up := newUpstream(t, map[string][4]byte{"example.com": {93, 184, 216, 34}}, nil, 300)
	port := freePort(t)
	srv, err := New(Config{
		NFTTable:        "inet fortress",
		Listen:          port,
		NFT:             discardNFT{},
		IsolateSegments: true,
		Segments: []Segment{
			{IP: netip.MustParseAddr("127.0.0.1"), Iface: "lo", Upstream: up.addr(), NFTSet: "resolved_v4"},
			{Name: "desk", IP: netip.MustParseAddr("192.0.2.1"), Iface: "lo-desk", Upstream: up.addr(), NFTSet: "resolved_desk_v4"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	srv.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(f, a...))
	}
	srv.bindGrace = 100 * time.Millisecond
	srv.rebindWait = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitFor(t, net.JoinHostPort("127.0.0.1", itoa(port)))
	eventually(t, "the desk shown broken on both transports", func() bool {
		segs := strings.Join(srv.Segments(), "\n")
		return strings.Contains(segs, "desk iface=lo-desk") && strings.Contains(segs, "BROKEN=not-serving(udp: ") && strings.Contains(segs, "tcp: ")
	})
	time.Sleep(10 * srv.bindGrace)
	select {
	case err := <-done:
		t.Fatalf("Run returned over the desk: %v", err)
	default:
	}
	if strings.Contains(srv.Segments()[0], "BROKEN") {
		t.Fatalf("the agent is marked broken: %s", srv.Segments()[0])
	}
	if rc := rcodeOf(t, srv, 0, "example.com"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("agent: %v", rc)
	}
	mu.Lock()
	n := len(lines)
	mu.Unlock()
	// Ten grace periods at a 10 ms rebind is 100 attempts for each transport.
	// After the grace period, it reports this one time, not one time for each
	// attempt.
	if n > 40 {
		t.Fatalf("%d journal lines for one missing interface", n)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// The daemon serves an isolated segment that starts later, and removes
// its mark.
func TestALateDeskIsServedAndUnmarked(t *testing.T) {
	srv := unbindableServer(t)
	seg := srv.segs[0]
	seg.Name = "desk"
	srv.cfg.IsolateSegments = true
	var attempts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- srv.retry(ctx, seg, "udp", func(up func()) error {
			if attempts.Add(1) < 40 {
				return errors.New("bind: cannot assign requested address")
			}
			up()
			<-ctx.Done()
			return nil
		})
	}()
	eventually(t, "the desk marked broken", func() bool { return strings.Contains(strings.Join(srv.Segments(), ""), "BROKEN=not-serving(udp: ") })
	eventually(t, "the desk unmarked once it binds", func() bool {
		return attempts.Load() >= 40 && !strings.Contains(strings.Join(srv.Segments(), ""), "BROKEN")
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("retry: %v", err)
	}
}
