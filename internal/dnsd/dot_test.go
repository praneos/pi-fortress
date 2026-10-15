package dnsd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// dotCert makes a self-signed certificate for name, and the pool that
// trusts it. The fixture resolver needs a real certificate, because the
// purpose of the client is to verify one.
func dotCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dotServer is a DoT resolver that is only real enough to answer: TLS on
// a loopback port, the two-byte length prefix, and an answer that echoes
// the query. Thus a test can see which id went out on the wire.
type dotServer struct {
	ln   net.Listener
	pool *x509.CertPool

	mu     sync.Mutex
	mangle bool
	conns  int
	msgs   int
	ids    []uint16
	silent bool
	// An id can be used again after its answer has gone back. But two
	// queries must never have the same id at the same time, because then
	// an answer cannot be attributed. inflight tracks that. peak proves
	// that the queries did overlap. Without peak, a client that serialised
	// everything would pass.
	inflight map[uint16]bool
	dup      int
	cur      int
	peak     int
}

func newDoTServer(t *testing.T, certName string) *dotServer {
	t.Helper()
	cert, pool := dotCert(t, certName)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	s := &dotServer{ln: ln, pool: pool, inflight: map[uint16]bool{}}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *dotServer) addr() netip.AddrPort {
	ap, _ := netip.ParseAddrPort(s.ln.Addr().String())
	return ap
}

func (s *dotServer) portStr() string {
	return strconv.Itoa(int(s.addr().Port()))
}

func (s *dotServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *dotServer) handle(c net.Conn) {
	defer c.Close()
	// Each query gets its answer in its own goroutine after a jittered
	// pause. So the answers come back in an order that is not related to
	// the order of the queries. A client that paired answers to callers
	// by position, not by id, would pass with a tidier fixture and fail
	// here. That is the purpose.
	var wmu sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(msg[:2])
		s.mu.Lock()
		s.msgs++
		s.ids = append(s.ids, id)
		if s.inflight[id] {
			s.dup++
		}
		s.inflight[id] = true
		s.cur++
		if s.cur > s.peak {
			s.peak = s.cur
		}
		silent := s.silent
		mangle := s.mangle
		s.mu.Unlock()
		if silent {
			continue
		}
		wg.Add(1)
		go func(msg []byte) {
			defer wg.Done()
			var b [1]byte
			_, _ = rand.Read(b[:])
			time.Sleep(time.Duration(b[0]%8) * time.Millisecond)
			// Echo with the QR bit set, so the answer is
			// distinguishable from the query but carries the same id.
			resp := append([]byte(nil), msg...)
			resp[2] |= 0x80
			// Right id, wrong question. A confused or hostile upstream sends this.
			// A late answer to a timed-out query also looks like this, after its
			// id goes out again on a different query.
			if mangle && len(resp) > 14 {
				// Inside the question name, so the reply answers a
				// different name than the one that was asked.
				resp[13] ^= 0x01
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			wmu.Lock()
			_, _ = c.Write(out)
			wmu.Unlock()
			s.mu.Lock()
			delete(s.inflight, binary.BigEndian.Uint16(msg[:2]))
			s.cur--
			s.mu.Unlock()
		}(msg)
	}
}

func (s *dotServer) stats() (conns, msgs int, ids []uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns, s.msgs, append([]uint16(nil), s.ids...)
}

// dialTo builds a client pinned at addrs. It trusts the root of the
// fixture and uses the port of the fixture instead of 853, which a test
// cannot bind.
func dialTo(name string, pool *x509.CertPool, port string, addrs ...netip.Addr) *dotClient {
	d := newDoT(name, addrs, nil)
	d.tlsCfg.RootCAs = pool
	d.port = port
	return d
}

// dotQuery builds a query with id in the header and the same value
// again in the body, where nothing rewrites it. A caller uses the
// echoed body to prove that it got the answer to its own question, and
// not the answer to the question of a different caller.
// A real query, not a blob: the client checks that a reply answers the
// question that was asked, so the question must be well formed. The
// query also has the id in the last two bytes. The pipelining test
// reads them back to tell the answer of one caller from another.
func dotQuery(id uint16) []byte {
	// Header, then one question of one five-byte label, A, IN. The tag
	// goes in the label, not after the question. After the question, it
	// would go on QTYPE or QCLASS. Also, the pipelining test needs a
	// different name for each caller. It reads the tag back from the
	// echoed question to see whose answer it got.
	req := []byte{
		0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		5, 0, 0, 'q', 'r', 'y', 0,
		0, 1, 0, 1,
	}
	binary.BigEndian.PutUint16(req[:2], id)
	binary.BigEndian.PutUint16(req[13:15], id)
	return req
}

func TestDoTAnswersAndRerollsTheID(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	defer d.close()

	req := dotQuery(0x1234)
	resp, err := d.exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("did not get the fixture's answer back")
	}
	_, _, ids := s.stats()
	if len(ids) != 1 {
		t.Fatalf("server saw %d queries, want 1", len(ids))
	}
	// The id on the wire gets a new random value, the same as on the UDP
	// path. forward() puts the id of the client back.
	if ids[0] == 0x1234 {
		t.Fatal("the client's id went out on the wire unchanged")
	}
	if got := binary.BigEndian.Uint16(resp[:2]); got != ids[0] {
		t.Fatalf("answer id %#x, wire id %#x", got, ids[0])
	}
}

func TestDoTFallsToTheSecondAddress(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	// A port nothing listens on: the first address refuses.
	dead := netip.MustParseAddr("127.0.0.2")
	d := dialTo("dns.test", s.pool, s.portStr(), dead, s.addr().Addr())
	defer d.close()

	if _, err := d.exchange(context.Background(), dotQuery(1)); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	d.mu.Lock()
	_, backed := d.until[dead]
	d.mu.Unlock()
	if !backed {
		t.Fatal("the refusing address was not backed off")
	}
}

func TestDoTRefusesAWrongCertificateName(t *testing.T) {
	// The fixture answers for "elsewhere.test". The client is pinned to
	// "dns.test" and must refuse. It must not try an alternative.
	s := newDoTServer(t, "elsewhere.test")
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	defer d.close()

	_, err := d.exchange(context.Background(), dotQuery(1))
	if err == nil {
		t.Fatal("accepted a certificate for the wrong name")
	}
	if _, msgs, _ := s.stats(); msgs != 0 {
		t.Fatalf("sent %d queries to an unverified upstream", msgs)
	}
}

func TestDoTGivesUpOnASilentUpstream(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	defer d.close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.exchange(ctx, dotQuery(1)); err == nil {
		t.Fatal("a silent upstream produced an answer")
	}
	if time.Since(start) > upstreamTO {
		t.Fatal("waited past the deadline")
	}
	// The client must release every caller. No caller may keep a channel.
	d.mu.Lock()
	conns := make([]*dotConn, 0, len(d.conns))
	for _, c := range d.conns {
		conns = append(conns, c)
	}
	d.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		n := len(c.wait)
		c.mu.Unlock()
		if n != 0 {
			t.Fatalf("%d callers left waiting", n)
		}
	}
}

func TestDoTPipelinesOverOneConnection(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	defer d.close()

	const n = 200
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := d.exchange(context.Background(), dotQuery(uint16(i)))
			if err != nil {
				errs <- err
				return
			}
			if got := binary.BigEndian.Uint16(resp[13:15]); got != uint16(i) {
				errs <- fmt.Errorf("caller %d got the answer to %d", i, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("exchange: %v", err)
	}
	s.mu.Lock()
	dup, peak := s.dup, s.peak
	s.mu.Unlock()
	if dup != 0 {
		t.Fatalf("%d ids were in flight twice at once", dup)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency %d: the queries never overlapped, so nothing about pipelining was tested", peak)
	}
	conns, msgs, _ := s.stats()
	if conns != 1 {
		t.Fatalf("opened %d connections for one address, want 1", conns)
	}
	if msgs != n {
		t.Fatalf("server saw %d queries, want %d", msgs, n)
	}
}

func TestDoTBacksOffAndHeals(t *testing.T) {
	now := time.Now()
	s := newDoTServer(t, "dns.test")
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	d.now = func() time.Time { return now }
	defer d.close()

	a := s.addr().Addr()
	d.failed(a)
	d.mu.Lock()
	until := d.until[a]
	d.mu.Unlock()
	if !until.After(now) {
		t.Fatal("a failure did not back the address off")
	}
	// The only address is in backoff, and it still must be reachable.
	// If not, a total outage could never heal.
	if _, err := d.exchange(context.Background(), dotQuery(1)); err != nil {
		t.Fatalf("a backed-off sole address was never retried: %v", err)
	}
	d.mu.Lock()
	_, still := d.until[a]
	d.mu.Unlock()
	if still {
		t.Fatal("a success did not clear the backoff")
	}
}

func TestDoTNeverSendsPlaintext(t *testing.T) {
	// A plain TCP listener: anything the client writes here in the
	// clear would be a downgrade. It must get nothing but a handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()

	ap, _ := netip.ParseAddrPort(ln.Addr().String())
	_, pool := dotCert(t, "dns.test")
	d := dialTo("dns.test", pool, strconv.Itoa(int(ap.Port())), ap.Addr())
	defer d.close()

	if _, err := d.exchange(context.Background(), dotQuery(0xbeef)); err == nil {
		t.Fatal("a plaintext listener produced an answer")
	}
	select {
	case b := <-got:
		if len(b) > 0 && b[0] != 0x16 {
			t.Fatalf("first byte %#x is not a TLS handshake record", b[0])
		}
		if strings.Contains(string(b), "query") {
			t.Fatal("the query went out in the clear")
		}
	case <-time.After(time.Second):
	}
}

// An answer with the right transaction id but a different question
// is not an answer to this query. Ids are 16 bits, and they get used
// again. Without this check, a reply that arrives after its caller left
// would go to the next holder of that id. Its addresses would then go
// into the nft set under the wrong name.
func TestDoTRefusesAnAnswerToADifferentQuestion(t *testing.T) {
	srv := newDoTServer(t, "dot.test")
	srv.mu.Lock()
	srv.mangle = true
	srv.mu.Unlock()
	d := dialTo("dot.test", srv.pool, srv.portStr(), srv.addr().Addr())
	defer d.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := d.exchange(ctx, dotQuery(0x1234)); err == nil {
		t.Fatalf("a reply to a different question was accepted: % x", resp)
	}
}

// A caller that cancels is not evidence about the connection. If the
// client takes that cancellation as a transport failure, it closes the
// shared connection and releases every other query pipelined on it. It
// also puts the address in backoff, so the next query goes elsewhere or
// nowhere. Then one impatient client costs the segment its upstream.
func TestDoTKeepsTheConnectionWhenOneCallerGivesUp(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	d := dialTo("dns.test", s.pool, s.portStr(), s.addr().Addr())
	defer d.close()
	a := s.addr().Addr()

	// One good exchange, so the connection is pooled and the address is
	// known to work.
	if _, err := d.exchange(context.Background(), dotQuery(1)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := d.exchange(ctx, dotQuery(2)); err == nil {
		t.Fatal("a silent upstream produced an answer")
	}

	d.mu.Lock()
	pooled := d.conns[a] != nil
	fails := d.fails[a]
	_, backed := d.until[a]
	d.mu.Unlock()
	if !pooled {
		t.Error("the caller's own deadline closed the shared connection")
	}
	if fails != 0 || backed {
		t.Errorf("the caller's own deadline marked the address failed: fails=%d backed=%v", fails, backed)
	}
	if conns, _, _ := s.stats(); conns != 1 {
		t.Errorf("%d connections to the upstream, want the one that was already open", conns)
	}
}

// The dial is held under the client-wide lock. So a cold
// address whose handshake hangs stops every other query on the
// segment. This includes the queries that would have gone to an
// address that answers.
func TestDoTDialDoesNotBlockTheHealthyAddress(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	dead := blackhole(t, s.portStr())
	d := dialTo("dns.test", s.pool, s.portStr(), dead, s.addr().Addr())
	defer d.close()

	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = d.exchange(context.Background(), dotQuery(1))
	}()
	<-started
	time.Sleep(50 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := d.exchange(context.Background(), dotQuery(2))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the healthy address: %v", err)
		}
	case <-time.After(dotDialTO - 500*time.Millisecond):
		t.Fatal("a hung dial to one address blocked the query for the other")
	}
}

// Nothing bounds a whole query. The response
// timer starts for each attempt and after the dial. So a silent
// upstream costs a caller with no deadline of its own the dial of
// each attempt plus the wait of each attempt.
func TestDoTBoundsTheWholeQuery(t *testing.T) {
	s := newDoTServer(t, "dns.test")
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
	dead := blackhole(t, s.portStr())
	d := dialTo("dns.test", s.pool, s.portStr(), dead, s.addr().Addr())
	defer d.close()

	start := time.Now()
	if _, err := d.exchange(context.Background(), dotQuery(1)); err == nil {
		t.Fatal("a silent upstream produced an answer")
	}
	if took := time.Since(start); took > upstreamTO+time.Second {
		t.Fatalf("a query with no deadline of its own took %s; nothing bounds the whole exchange", took)
	}
}
