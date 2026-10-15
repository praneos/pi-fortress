package dnsd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// freePort takes a port both a UDP and a TCP socket can have, since the
// server wants the same number on both.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	pc, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Skipf("port %d not free for udp: %v", port, err)
	}
	pc.Close()
	return port
}

func itoa(n int) string { return strconv.Itoa(n) }

func query(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestServesOverUDPAndTCP is the only test that goes through a socket.
// It binds loopback, not a segment interface. That is the one part of
// the real system that it cannot exercise.
func TestServesOverUDPAndTCP(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, map[string][4]byte{"example.com": {93, 184, 216, 34}}, nil, 300)
	port := freePort(t)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   port,
		NFT:      discardNFT{},
		Segments: []Segment{{
			IP:            netip.MustParseAddr("127.0.0.1"),
			Iface:         "lo",
			Upstream:      up.addr(),
			SinkholeFiles: []string{sink},
			NFTSet:        "resolved_v4",
			LogPath:       filepath.Join(dir, "dns.jsonl"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}()

	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	waitFor(t, addr)

	t.Run("udp", func(t *testing.T) {
		c, err := net.Dial("udp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(query(t, "example.com")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if m.Header.ID != 0x4242 {
			t.Fatalf("id %#x", m.Header.ID)
		}
		if got := firstA(t, m.Answers); got != "93.184.216.34" {
			t.Fatalf("answer %q", got)
		}
	})

	t.Run("tcp", func(t *testing.T) {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		req := query(t, "blocked.test")
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(req)))
		if _, err := c.Write(append(hdr[:], req...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil {
			t.Fatal(err)
		}
		if got := firstA(t, m.Answers); got != "0.0.0.0" {
			t.Fatalf("answer %q, want the sinkhole over tcp too", got)
		}
	})
}

func waitFor(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp4", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never came up", addr)
}

// stallUpstream holds each query until the test closes release. Then it
// answers each query with the query itself, flagged as a response. n
// counts arrivals.
type stallUpstream struct {
	pc      net.PacketConn
	n       atomic.Int32
	release chan struct{}
}

func newStallUpstream(t *testing.T) *stallUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &stallUpstream{pc: pc, release: make(chan struct{})}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u.n.Add(1)
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80
			go func() { <-u.release; _, _ = pc.WriteTo(resp, from) }()
		}
	}()
	return u
}

// serveLoopback runs a one-segment server on 127.0.0.1 with blocked.test
// sinkholed. It first gives the server to tweak, then returns its address.
func serveLoopback(t *testing.T, upstream string, tweak func(*Server)) string {
	t.Helper()
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   port,
		NFT:      discardNFT{},
		Segments: []Segment{{
			IP:            netip.MustParseAddr("127.0.0.1"),
			Iface:         "lo",
			Upstream:      upstream,
			SinkholeFiles: []string{sink},
			NFTSet:        "resolved_v4",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tweak(srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	waitFor(t, addr)
	return addr
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

// A segment answers a maximum of udpSlots queries at the same time. It
// drops the other queries before they use a goroutine or an upstream
// socket. A slot becomes free again when its query gets an answer.
func TestUDPQueriesPastTheBoundAreDropped(t *testing.T) {
	up := newStallUpstream(t)
	addr := serveLoopback(t, up.pc.LocalAddr().String(), func(s *Server) { s.udpSlots = 2 })
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 6 {
		if _, err := c.Write(query(t, "q"+itoa(i)+".example")); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "two queries upstream", func() bool { return up.n.Load() == 2 })
	time.Sleep(200 * time.Millisecond)
	if n := up.n.Load(); n != 2 {
		t.Fatalf("%d queries reached the upstream past a bound of 2", n)
	}
	close(up.release)
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := range 2 {
		if _, err := c.Read(buf); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
	eventually(t, "a query answered after the slots freed", func() bool {
		_, _ = c.Write(query(t, "after.example"))
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := c.Read(buf)
		return err == nil
	})
}

// A segment holds a maximum of tcpSlots connections. It closes one more
// connection at once, and does not wait for the read timeout. A slot
// becomes free again when its connection ends.
func TestTCPConnectionsPastTheBoundAreClosed(t *testing.T) {
	addr := serveLoopback(t, "127.0.0.1:9", func(s *Server) { s.tcpSlots = 1 })
	ask := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		req := query(t, "blocked.test")
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(req)))
		if _, err := c.Write(append(hdr[:], req...)); err != nil {
			return err
		}
		_, err := io.ReadFull(c, hdr[:])
		return err
	}
	var held net.Conn
	eventually(t, "a first connection served", func() bool {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			return false
		}
		if ask(c) != nil {
			c.Close()
			return false
		}
		held = c
		return true
	})
	over, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	start := time.Now()
	if err := ask(over); err == nil {
		t.Fatal("a connection past the bound was served")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("refused after %v, want at once", d)
	}
	held.Close()
	eventually(t, "a connection served after the slot freed", func() bool {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			return false
		}
		defer c.Close()
		return ask(c) == nil
	})
}

// logCapture collects what a Server logs, safely across its goroutines.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// A socket that bound its address but could not pin its interface does
// not serve. On Linux, a bind to the address alone does not authorize the
// ingress interface. Thus an unpinned socket would answer all that
// reaches the address by any route. The segment exists to draw that
// boundary. The socket continues to report it, because retry tries it
// again. An operator must be able to see why there is no resolver.
func TestUnpinnableSocketRefusesToServe(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	var logs logCapture
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   port,
		NFT:      discardNFT{},
		Segments: []Segment{{
			IP: netip.MustParseAddr("127.0.0.1"), Iface: "pf-nope0",
			Upstream: "127.0.0.1:9", SinkholeFiles: []string{sink}, NFTSet: "resolved_v4",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.logf = logs.logf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}()

	eventually(t, "both sockets refused", func() bool { return len(logs.get()) >= 2 })
	got := strings.Join(logs.get(), "\n")
	for _, want := range []string{"pf-nope0 udp", "pf-nope0 tcp", "refusing to serve"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log %q lacks %q", got, want)
		}
	}
	// And nothing listens on the address that it would serve.
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatalf("%s is serving despite an unpinnable interface", addr)
	}
}

func TestPinnedSocketQuiet(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := probe.(*net.UDPConn).SyscallConn()
	var perr error
	_ = rc.Control(func(fd uintptr) {
		perr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	})
	probe.Close()
	if perr != nil {
		t.Skipf("SO_BINDTODEVICE refused here: %v", perr)
	}
	var logs logCapture
	addr := serveLoopback(t, "127.0.0.1:9", func(s *Server) { s.logf = logs.logf })
	// Both transports answer. Thus each bind attempt already wrote its log
	// line. This is also true for an attempt that was refused and retried
	// before these.
	eventually(t, "a udp answer", func() bool {
		c, err := net.Dial("udp4", addr)
		if err != nil {
			return false
		}
		defer c.Close()
		return askConn(t, c, false) == nil
	})
	c, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := askConn(t, c, true); err != nil {
		t.Fatalf("tcp not answered: %v", err)
	}
	got := logs.get()
	for _, line := range got {
		for _, bad := range []string{"refusing to serve", "unpinned", "SO_BINDTODEVICE", "is not serving", "retrying"} {
			if strings.Contains(line, bad) {
				t.Fatalf("pinned socket logged %q (%q)", line, bad)
			}
		}
	}
	if len(got) != 0 {
		t.Fatalf("pinned, serving socket logged %q", got)
	}
}

// askConn sends one blocked.test query and expects a response with its
// ID. tcp adds the two-byte length prefix in both directions.
func askConn(t *testing.T, c net.Conn, tcp bool) error {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	req := query(t, "blocked.test")
	if tcp {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(req)))
		req = append(hdr[:], req...)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	buf := make([]byte, 512)
	var resp []byte
	if tcp {
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return err
		}
		resp = buf[:binary.BigEndian.Uint16(hdr[:])]
		if _, err := io.ReadFull(c, resp); err != nil {
			return err
		}
	} else {
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		resp = buf[:n]
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return err
	}
	if !h.Response || h.ID != 0x4242 {
		return fmt.Errorf("header %+v is not the answer to query 0x4242", h)
	}
	return nil
}

// One client address holds a maximum of tcpPerSource of the TCP
// connections of a segment. After that, the segment closes the connection
// at once, but it still serves a different address on the same segment.
// The slots of the segment are much higher. Thus only the per-source
// rule can explain the refusal.
func TestTCPPerSourceCapLeavesOtherClients(t *testing.T) {
	addr := serveLoopback(t, "127.0.0.1:9", func(s *Server) { s.tcpPerSource = 1 })
	_, port, _ := net.SplitHostPort(addr)
	ask := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		req := query(t, "blocked.test")
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(req)))
		if _, err := c.Write(append(hdr[:], req...)); err != nil {
			return err
		}
		_, err := io.ReadFull(c, hdr[:])
		return err
	}
	dialFrom := func(src string) (net.Conn, error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: time.Second}
		return d.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}
	var held net.Conn
	eventually(t, "a first connection served", func() bool {
		c, err := dialFrom("127.0.0.1")
		if err != nil {
			return false
		}
		if ask(c) != nil {
			c.Close()
			return false
		}
		held = c
		return true
	})
	defer held.Close()
	over, err := dialFrom("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	start := time.Now()
	if err := ask(over); err == nil {
		t.Fatal("a second connection from one address was served past a cap of 1")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("refused after %v, want at once", d)
	}
	other, err := dialFrom("127.0.0.2")
	if err != nil {
		t.Skipf("no 127.0.0.2 source on this host: %v", err)
	}
	defer other.Close()
	if err := ask(other); err != nil {
		t.Fatalf("another address refused while the first was at its cap: %v", err)
	}
	held.Close()
	eventually(t, "the first address served again after its connection closed", func() bool {
		c, err := dialFrom("127.0.0.1")
		if err != nil {
			return false
		}
		defer c.Close()
		return ask(c) == nil
	})
}

func TestTCPPerSourceDefault(t *testing.T) {
	const want = 8
	if tcpConnsPerSource != want || tcpConnsPerSource >= tcpConns {
		t.Fatalf("tcpConnsPerSource = %d, want %d and under tcpConns %d", tcpConnsPerSource, want, tcpConns)
	}
	var def int
	addr := serveLoopback(t, "127.0.0.1:9", func(s *Server) { def = s.tcpPerSource })
	if def != want {
		t.Fatalf("New set tcpPerSource = %d, want %d", def, want)
	}
	_, port, _ := net.SplitHostPort(addr)
	dialFrom := func(src string) (net.Conn, error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: time.Second}
		return d.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}
	for i := 1; i <= want; i++ {
		eventually(t, fmt.Sprintf("connection %d of %d served", i, want), func() bool {
			c, err := dialFrom("127.0.0.1")
			if err != nil {
				return false
			}
			if askConn(t, c, true) != nil {
				c.Close()
				return false
			}
			t.Cleanup(func() { c.Close() })
			return true
		})
	}
	over, err := dialFrom("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	if err := askConn(t, over, true); err == nil {
		t.Fatalf("connection %d from one address served past the default cap of %d", want+1, want)
	}
	other, err := dialFrom("127.0.0.2")
	if err != nil {
		t.Skipf("no 127.0.0.2 source on this host: %v", err)
	}
	defer other.Close()
	if err := askConn(t, other, true); err != nil {
		t.Fatalf("another address refused while the first held %d: %v", want, err)
	}
}
