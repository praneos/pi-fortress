package netgate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// harness runs a Server in a temporary directory. The test process is
// the client: its uid and gid are the peer, unless a test says otherwise.
// nft is a fake runner that records the text of each write.
type harness struct {
	t   *testing.T
	dir string

	// stop ends the server that start ran last.
	stop func()

	mu   sync.Mutex
	nft  []string
	fail error
	logs []string
	now  time.Time
}

func me() Peer { return Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} }

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	// Short: a unix socket path has a limit of 107 bytes.
	dir, err := os.MkdirTemp("", "ng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, dir: dir, now: time.Unix(1_800_000_000, 0)}
	h.start(mod)
	return h
}

// start runs one Server on h.dir until the test ends, or until h.stop
// runs.
func (h *harness) start(mod func(*Config)) {
	h.t.Helper()
	cfg := Config{
		Dir:       h.dir,
		DNSConfig: DNSConfig{Table: "inet fortress", Sets: []string{"resolved_v4", "resolved_house_v4"}, Queues: []uint16{1}},
		DNS:       me(),
		DNSGroup:  os.Getgid(),
		Run:       h.run,
		Now:       h.clock,
		Logf:      h.logf,
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	var once sync.Once
	h.stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				h.t.Errorf("Run: %v", err)
			}
		})
	}
	h.t.Cleanup(h.stop)
	h.waitSocket("dns.sock")
}

// waitSocket waits until name is open to the group: the last step of
// listen.
func (h *harness) waitSocket(name string) {
	h.t.Helper()
	for range 500 {
		if fi, err := os.Stat(h.sock(name)); err == nil && fi.Mode().Perm() == 0660 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("%s never opened", name)
}

func (h *harness) sock(name string) string { return filepath.Join(h.dir, name) }

func (h *harness) run(arg string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nft = append(h.nft, arg)
	return h.fail
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

func (h *harness) logf(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, fmt.Sprintf(format, args...))
}

func (h *harness) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.nft...)
}

// logged waits a short time for a log line with sub: the server can log
// after the client already has its answer.
func (h *harness) logged(sub string) bool {
	for range 200 {
		h.mu.Lock()
		for _, l := range h.logs {
			if strings.Contains(l, sub) {
				h.mu.Unlock()
				return true
			}
		}
		h.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// The writes are the nft text that pf dns ran before, byte for byte.
func TestGateWritesTheNftText(t *testing.T) {
	h := newHarness(t, nil)
	c := NewGateClient(h.sock("dns.sock"))
	in := v4s("93.184.216.34", "1.1.1.1")
	if err := c.Add("resolved_v4", in); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh("resolved_house_v4", in); err != nil {
		t.Fatal(err)
	}
	// An answer with no IPv4 address writes nothing and asks nothing.
	if err := c.Add("resolved_v4", v4s("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	el := "element inet fortress resolved_house_v4 { 93.184.216.34, 1.1.1.1 }"
	want := []string{
		"add element inet fortress resolved_v4 { 93.184.216.34, 1.1.1.1 }",
		"add " + el + "; delete " + el + "; add " + el,
	}
	got := h.calls()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("nft text:\n%q\nwant:\n%q", got, want)
	}
}

// netgate writes only a set that dns.json names, and only public
// addresses. Each refusal is an error for pf dns, and a log line here.
func TestGateRefusesSetsAndAddresses(t *testing.T) {
	h := newHarness(t, nil)
	c := NewGateClient(h.sock("dns.sock"))
	for _, tc := range []struct {
		set   string
		addrs []netip.Addr
		why   string
	}{
		{"resolved_desk_v4", v4s("1.1.1.1"), "not a gate set"},
		{"blacklist_v4", v4s("1.1.1.1"), "not a gate set"},
		{"resolved_v4", v4s("1.1.1.1", "10.0.0.1"), "10.0.0.1 is not a public address"},
		{"resolved_v4", v4s("127.0.0.1"), "not a public address"},
		{"resolved_v4", v4s("0.0.0.0"), "not a public address"},
		{"resolved_v4", v4s("100.64.0.9"), "not a public address"},
		{"resolved_v4", v4s("169.254.0.1"), "not a public address"},
		{"resolved_v4", v4s("224.0.0.251"), "not a public address"},
		{"resolved_v4", v4s("192.168.1.1"), "not a public address"},
	} {
		err := c.Add(tc.set, tc.addrs)
		if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("Add(%s, %v) = %v, want a refusal with %q", tc.set, tc.addrs, err, tc.why)
		}
	}
	if got := h.calls(); len(got) != 0 {
		t.Fatalf("a refused write ran nft: %q", got)
	}
	if !h.logged("GATE refused") {
		t.Fatal("no log line for a refused GATE")
	}
}

// 200 a second, a burst of 400, for all requests together.
func TestGateRateLimit(t *testing.T) {
	h := newHarness(t, nil)
	c := NewGateClient(h.sock("dns.sock"))
	for i := range gateBurst {
		if err := c.Add("resolved_v4", v4s("1.1.1.1")); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if err := c.Add("resolved_v4", v4s("1.1.1.1")); err == nil || !strings.Contains(err.Error(), "GATE requests a second") {
		t.Fatalf("request over the burst: %v", err)
	}
	if !h.logged("GATE refused: more than 200 GATE requests a second") {
		t.Fatal("no log line for the rate refusal")
	}
	h.advance(time.Second)
	for i := range gateRate {
		if err := c.Add("resolved_v4", v4s("1.1.1.1")); err != nil {
			t.Fatalf("request %d of the next second: %v", i, err)
		}
	}
	if err := c.Add("resolved_v4", v4s("1.1.1.1")); err == nil {
		t.Fatal("more than the rate in the next second")
	}
	if got := len(h.calls()); got != gateBurst+gateRate {
		t.Fatalf("%d nft calls, want %d", got, gateBurst+gateRate)
	}
}

// A failed nft (a full set) is an error for pf dns, with the nft text.
func TestGateNftFailureIsAnError(t *testing.T) {
	h := newHarness(t, nil)
	h.mu.Lock()
	h.fail = errors.New("Error: Could not process rule: No space left on device")
	h.mu.Unlock()
	err := NewGateClient(h.sock("dns.sock")).Add("resolved_v4", v4s("1.1.1.1"))
	if err == nil || !strings.Contains(err.Error(), "No space left on device") || strings.Contains(err.Error(), "refused") {
		t.Fatalf("Add = %v, want the nft error", err)
	}
}

// Only the client: a process with another uid, or the right uid with
// another primary group (a DoT stub runs as pf-dns too), gets nothing.
func TestGatePeerCheck(t *testing.T) {
	for _, peer := range []Peer{{UID: me().UID + 1, GID: me().GID}, {UID: me().UID, GID: me().GID + 1}} {
		h := newHarness(t, func(c *Config) { c.DNS = peer })
		err := NewGateClient(h.sock("dns.sock")).Add("resolved_v4", v4s("1.1.1.1"))
		if err == nil {
			t.Fatalf("peer %+v: a GATE from uid %d gid %d passed", peer, me().UID, me().GID)
		}
		if got := h.calls(); len(got) != 0 {
			t.Fatalf("peer %+v: nft ran: %q", peer, got)
		}
		if !h.logged(fmt.Sprintf("peer uid %d gid %d refused", me().UID, me().GID)) {
			t.Fatalf("peer %+v: no log line for the refused peer", peer)
		}
		if err := Ping(h.sock("dns.sock"), "resolved_v4"); err == nil {
			t.Fatalf("peer %+v: Ping passed", peer)
		}
	}
}

// The socket opens to its group, and only to it.
func TestSocketModeAndGroup(t *testing.T) {
	h := newHarness(t, nil)
	fi, err := os.Stat(h.sock("dns.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0660 {
		t.Fatalf("dns.sock mode %v, want a socket 0660", fi.Mode())
	}
	if gid := fi.Sys().(*syscall.Stat_t).Gid; gid != uint32(os.Getgid()) {
		t.Fatalf("dns.sock group %d, want %d", gid, os.Getgid())
	}
}

// A message that is not a GATE request closes the connection.
func TestBadMessageClosesTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	for _, tc := range []struct {
		name string
		msg  []byte
		log  string
	}{
		{"unknown verb", []byte{'X', 0, 0, 0}, "first message has verb 'X'"},
		{"short GATE", []byte{verbGate, opAdd, 0, 0}, "protocol error: GATE request of 4 bytes"},
		{"long", make([]byte, maxGate+10), "protocol error: a message longer than"},
	} {
		// Past the one line a second of the log limit.
		h.advance(time.Second)
		c, err := dial(h.sock("dns.sock"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exchange(c, tc.msg, 2*time.Second); err == nil {
			t.Errorf("%s: got a reply", tc.name)
		}
		c.Close()
		if !h.logged(tc.log) {
			t.Errorf("%s: no log line with %q", tc.name, tc.log)
		}
	}
	// A good request after a bad one, on the same connection, gets nothing.
	c, err := dial(h.sock("dns.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	good, _ := encodeGate(gateReq{op: opAdd, set: "resolved_v4", addrs: v4s("1.1.1.1")})
	if _, err := exchange(c, good, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(c, []byte{verbGate}, 2*time.Second); err == nil {
		t.Fatal("a short request got a reply")
	}
	if _, err := exchange(c, good, 2*time.Second); err == nil {
		t.Fatal("the connection served after a protocol error")
	}
}

func TestPing(t *testing.T) {
	h := newHarness(t, nil)
	if err := Ping(h.sock("dns.sock"), "resolved_v4"); err != nil {
		t.Fatal(err)
	}
	if err := Ping(h.sock("dns.sock"), "resolved_desk_v4"); err == nil || !strings.Contains(err.Error(), "not a gate set") {
		t.Fatalf("Ping of a set that dns.json does not name: %v", err)
	}
	if got := h.calls(); len(got) != 0 {
		t.Fatalf("Ping ran nft: %q", got)
	}
}

// netgate down: the write fails, and pf dns answers SERVFAIL.
func TestGateClientWithNoServer(t *testing.T) {
	dir := t.TempDir()
	err := NewGateClient(filepath.Join(dir, "dns.sock")).Add("resolved_v4", v4s("1.1.1.1"))
	if err == nil {
		t.Fatal("a GATE with no netgate passed")
	}
}

// A connection of the pool from a netgate that restarted is tried one
// time again on a new connection.
func TestGateClientAfterARestart(t *testing.T) {
	h := newHarness(t, nil)
	c := NewGateClient(h.sock("dns.sock"))
	if err := c.Add("resolved_v4", v4s("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	// The first server stops, and a second one takes its place.
	h.stop()
	h.start(nil)
	if err := c.Add("resolved_v4", v4s("8.8.8.8")); err != nil {
		t.Fatalf("Add after a restart: %v", err)
	}
}

// Requests at the same time each get their own answer.
func TestGateConcurrent(t *testing.T) {
	h := newHarness(t, nil)
	c := NewGateClient(h.sock("dns.sock"))
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 64 {
		wg.Go(func() {
			if err := c.Add("resolved_v4", []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, byte(i)})}); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := len(h.calls()); got != 64 {
		t.Fatalf("%d nft calls, want 64", got)
	}
}

func TestLogLimit(t *testing.T) {
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	var l logLimit
	t0 := time.Unix(1_800_000_000, 0)
	l.say(t0, logf, "one %d", 1)
	l.say(t0.Add(100*time.Millisecond), logf, "two")
	l.say(t0.Add(900*time.Millisecond), logf, "three")
	l.say(t0.Add(time.Second), logf, "four")
	want := []string{"pf netgate: one 1", "pf netgate: four (and 2 more since the last line)"}
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("lines %q, want %q", lines, want)
	}
}

func TestBucket(t *testing.T) {
	b := newBucket(2, 3)
	t0 := time.Unix(1_800_000_000, 0)
	for i := range 3 {
		if !b.take(t0) {
			t.Fatalf("token %d of the burst", i)
		}
	}
	if b.take(t0) {
		t.Fatal("a token past the burst")
	}
	if !b.take(t0.Add(500*time.Millisecond)) || b.take(t0.Add(500*time.Millisecond)) {
		t.Fatal("half a second at 2/s is one token")
	}
	// A clock that goes back gives nothing, and takes nothing.
	if b.take(t0) {
		t.Fatal("a clock that went back gave a token")
	}
	if !b.take(t0.Add(time.Hour)) {
		t.Fatal("no token after an hour")
	}
}
