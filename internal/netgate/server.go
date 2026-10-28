package netgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"pi-fortress/internal/nfq"
)

// Config is the setup of a Server.
type Config struct {
	// Dir is the directory of the sockets (Dir in production).
	Dir string
	// DNSConfig is the table, the gate sets and the SNI queues, from
	// dns.json.
	DNSConfig
	// DNS is the agent resolver, the one client of dns.sock. DNSGroup is
	// the group of that socket, a group that only that client has.
	DNS      Peer
	DNSGroup int
	// Run runs nft (gateset.Cmd.Run). Nil runs the nft command. A test
	// gives its own.
	Run func(arg string) error
	// OpenQueue binds an SNI queue. Nil is nfq.Open. A test gives a fake.
	OpenQueue func(num uint16) (Queue, error)
	// Now and Logf are time.Now and log.Printf, except in tests.
	Now  func() time.Time
	Logf func(format string, args ...any)
	// sniAge, sniHeld and sniSweep are the constants of relay.go. New
	// sets them. A test can make them small.
	sniAge   time.Duration
	sniHeld  int
	sniSweep time.Duration
}

// sock is one listening socket: its file, the one peer that may use it,
// the group of the file, and what a connection to it can ask.
type sock struct {
	name  string
	peer  Peer
	group int
	// conns limits the connections open at one time. A new connection
	// over the limit is closed at once.
	conns int
	// buf is the size of the read buffer: more than the largest message
	// that the peer may send. A longer message is a protocol error.
	buf int
	// serve handles a connection after the peer check, from its first
	// message on.
	serve func(c *net.UnixConn, first, buf []byte)
}

// Server is pf netgate.
type Server struct {
	cfg   Config
	socks []*sock
	gate  *gateVerb
	// refusals limits the log lines of the refusals that are not about
	// one verb: a peer that is not the client, a bad message.
	refusals logLimit

	mu    sync.Mutex
	conns map[*net.UnixConn]struct{}
	// queues are the SNI queues with a relay now: one client each.
	queues map[uint16]bool
	wg     sync.WaitGroup
}

// New checks cfg and makes a Server. It opens nothing.
func New(cfg Config) (*Server, error) {
	if cfg.Dir == "" {
		return nil, errors.New("netgate: no socket directory")
	}
	if !tableName.MatchString(cfg.Table) {
		return nil, fmt.Errorf("netgate: nft table %q", cfg.Table)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.OpenQueue == nil {
		cfg.OpenQueue = func(num uint16) (Queue, error) { return nfq.Open(num) }
	}
	if cfg.sniAge == 0 {
		cfg.sniAge, cfg.sniHeld, cfg.sniSweep = sniAge, sniHeld, sniSweep
	}
	s := &Server{
		cfg:    cfg,
		conns:  map[*net.UnixConn]struct{}{},
		queues: map[uint16]bool{},
	}
	s.gate = newGateVerb(&s.cfg)
	s.socks = []*sock{{
		name:  "dns.sock",
		peer:  cfg.DNS,
		group: cfg.DNSGroup,
		conns: dnsConns,
		buf:   maxGate + 1,
		serve: s.serveDNS,
	}}
	return s, nil
}

// dnsConns is the limit of connections on dns.sock: the GATE pool of
// pf dns (gateConns) and one SNI relay for each queue, with spare room
// for the connections of a pf dns that just stopped.
const dnsConns = 64

// Run listens until ctx ends. It returns an error if a socket does not
// open, or if an accept loop fails.
func (s *Server) Run(ctx context.Context) error {
	ls := make([]*net.UnixListener, 0, len(s.socks))
	closeAll := func() {
		for _, l := range ls {
			l.Close()
		}
		s.closeConns()
	}
	for _, k := range s.socks {
		l, err := listen(filepath.Join(s.cfg.Dir, k.name), k.group)
		if err != nil {
			closeAll()
			return err
		}
		ls = append(ls, l)
	}
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	errc := make(chan error, len(ls))
	for i, l := range ls {
		go func() { errc <- s.accept(l, s.socks[i]) }()
	}
	err := <-errc
	closeAll()
	for range len(ls) - 1 {
		<-errc
	}
	s.wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// listen opens one socket. The unit has UMask=0077, so the file starts
// with no access for the group or others. It opens to the group of its
// client only after the group is set.
func listen(path string, group int) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("netgate: %w", err)
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("netgate: %w", err)
	}
	if err := os.Chown(path, -1, group); err != nil {
		l.Close()
		return nil, fmt.Errorf("netgate: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		l.Close()
		return nil, fmt.Errorf("netgate: %w", err)
	}
	return l, nil
}

func (s *Server) accept(l *net.UnixListener, k *sock) error {
	slots := make(chan struct{}, k.conns)
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of file descriptors, or a connection that went away before
			// the accept. Neither ends the daemon.
			s.refuse("%s: accept: %v", k.name, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.refuse("%s: more than %d connections; the new one is closed", k.name, k.conns)
			c.Close()
			continue
		}
		if !s.track(c) {
			c.Close()
			<-slots
			continue
		}
		s.wg.Add(1)
		go func() {
			defer func() {
				s.untrack(c)
				c.Close()
				<-slots
				s.wg.Done()
			}()
			s.serve(k, c)
		}()
	}
}

// serve checks the peer of c, then gives its first message to the sock.
func (s *Server) serve(k *sock, c *net.UnixConn) {
	uid, gid, err := peerCred(c)
	if err != nil {
		s.refuse("%s: no peer credentials: %v", k.name, err)
		return
	}
	if !k.peer.allows(uid, gid) {
		s.refuse("%s: peer uid %d gid %d refused; the client is uid %d gid %d", k.name, uid, gid, k.peer.UID, k.peer.GID)
		return
	}
	buf := make([]byte, k.buf)
	first, err := readMsg(c, buf)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.refuse("%s: %v", k.name, err)
		}
		return
	}
	k.serve(c, first, buf)
}

// serveDNS is a connection of pf dns. Its first message chooses what the
// connection is for.
func (s *Server) serveDNS(c *net.UnixConn, first, buf []byte) {
	switch first[0] {
	case verbGate:
		s.gate.serve(c, first, buf, s.refuse)
	case verbSNI:
		s.serveSNI(c, first)
	default:
		s.refuse("dns.sock: first message has verb %q", first[0])
	}
}

// peerCred is the uid and gid of the process that connected c, as the
// kernel saw them at the connect.
func peerCred(c *net.UnixConn) (uid, gid uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if cerr != nil {
		return 0, 0, cerr
	}
	return cred.Uid, cred.Gid, nil
}

// readMsg reads one message into buf. A message that does not fit buf is
// a protocol error. A read of zero bytes is the close of the peer: no
// message of the protocol is empty.
func readMsg(c *net.UnixConn, buf []byte) ([]byte, error) {
	n, _, flags, _, err := c.ReadMsgUnix(buf, nil)
	if err != nil {
		return nil, err
	}
	if flags&syscall.MSG_TRUNC != 0 {
		return nil, protoErr("a message longer than %d bytes", len(buf)-1)
	}
	if n == 0 {
		return nil, io.EOF
	}
	return buf[:n], nil
}

func (s *Server) track(c *net.UnixConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

// closeConns closes each open connection. After it, track refuses new
// ones.
func (s *Server) closeConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func (s *Server) refuse(format string, args ...any) {
	s.refusals.say(s.cfg.Now(), s.cfg.Logf, format, args...)
}

// logLimit writes at most one line each second. The next line that it
// writes says how many it did not write. Each refusal is logged, but a
// flood of refusals cannot fill the journal.
type logLimit struct {
	mu      sync.Mutex
	last    time.Time
	skipped int
}

func (l *logLimit) say(now time.Time, logf func(string, ...any), format string, args ...any) {
	l.mu.Lock()
	if !l.last.IsZero() && now.Sub(l.last) < time.Second {
		l.skipped++
		l.mu.Unlock()
		return
	}
	l.last = now
	skipped := l.skipped
	l.skipped = 0
	l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	if skipped > 0 {
		msg += fmt.Sprintf(" (and %d more since the last line)", skipped)
	}
	logf("pf netgate: %s", msg)
}
