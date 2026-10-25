// Package www is the agent-facing HTTP server on port 80: setup.sh, ca.pem and
// the one-time /claim/<CODE> handoff with its ledger. pf www runs it and
// internal/admin issues the claims.
package www

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/base"
	"pi-fortress/internal/srclimit"
)

var allowed = map[string]string{
	"/setup.sh": "setup.sh",
	"/ca.pem":   "ca.pem",
}

type Server struct {
	Bind string
	Port int
	Dir  string
	// Audit is the admin log, when this process can reach it. A redeem is the
	// one state change that this server makes: the credentials of a slot leave
	// the gateway for an agent, and the claim is spent. A redeem never touches
	// admin.CallCtx. So without this, the redeem was only in the claims ledger,
	// beside the claims. Audit is nil in a test that does not care. Nil is not
	// an error: a www that cannot write the log must still serve the handoff.
	Audit *audit.Log
	lim   limiter
	seg   window
	seen  recent
}

func firstFile(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func Defaults() *Server {
	s := &Server{
		Port: 80,
		Dir:  "/var/lib/pi-fortress/www",
	}
	// The pair, not the base: apply builds the fence from net.env with
	// net.env.local over it. So a bind address from the base alone is an
	// address where the fence does not expect this server.
	env := base.LoadNetEnv()
	if v := strings.TrimSpace(os.Getenv("PI_IP")); v != "" {
		s.Bind = v
	} else if v := strings.TrimSpace(env["PI_IP"]); v != "" {
		s.Bind = v
	}
	if v := strings.TrimSpace(os.Getenv("PI_FORTRESS_WWW")); v != "" {
		s.Dir = v
	}
	return s
}

func (s *Server) Addr() string {
	bind := s.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	port := s.Port
	if port == 0 {
		port = 80
	}
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

func contentType(name string) string {
	switch name {
	case "ca.pem":
		return "application/x-pem-file"
	default:
		return "text/plain; charset=utf-8"
	}
}

func (s *Server) dir() string {
	if s.Dir == "" {
		return "/var/lib/pi-fortress/www"
	}
	return s.Dir
}

func (s *Server) pathFor(name string) string {
	dir := s.dir()
	switch name {
	case "setup.sh":
		return setupPath(dir)
	case "ca.pem":
		return caPath(dir)
	default:
		return filepath.Join(dir, name)
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims := ClaimsDir(s.Dir)
	if code, ok := strings.CutPrefix(r.URL.Path, "/claim/"); ok {
		s.serveClaim(w, r, claims, code)
		return
	}
	name, ok := allowed[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	ip := clientIP(r)
	if r.Method == http.MethodGet && s.seen.first(ip+" "+r.URL.Path) {
		_ = AppendEvent(claims, Event{Ev: "setup", IP: ip, Path: r.URL.Path})
	}
	path := s.pathFor(name)
	if path == "" || !s.servable(name, path) {
		http.NotFound(w, r)
		return
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// servable says that www may serve path for name. For ca.pem, path must
// be one of the files that caPath picks from. Their names are not all
// ca.pem. For each other name, path must have that name.
func (s *Server) servable(name, path string) bool {
	if name == "ca.pem" {
		return slices.Contains(caPaths(s.dir()), path)
	}
	return filepath.Base(path) == name
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// serveClaim answers GET /claim/<CODE> with the enrol script once. A wrong,
// used or expired code gets the same 404. Over limitPerMin tries a minute
// from one address, or over segmentPerMin from all addresses together, gets
// a 429, before serveClaim touches the directory. A try that the per-source
// limit refuses does not count against the segment.
func (s *Server) serveClaim(w http.ResponseWriter, r *http.Request, claims, code string) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	ip := clientIP(r)
	if !s.lim.allow(ip) || !s.seg.allow() {
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	c, err := RedeemClaim(claims, code)
	if err != nil {
		// The audit log does not record a refused code. This is the opposite of
		// the rule of the verb table, where a denial is the most useful entry.
		// The difference is who can reach it. A verb is refused to a user already
		// on the gateway. This path answers all clients on the agent segment, so a
		// record of each miss gives a scanner the admin log as a place to write.
		// A run of guesses shows in the ledger and in the rate limiter.
		http.NotFound(w, r)
		return
	}
	_ = AppendEvent(claims, Event{Ev: "redeemed", Code: c.Code, Slot: c.Slot, IP: ip})
	// The slot, never the code. The ledger keeps the code, because a ledger
	// line connects a claim to the issue that made it. The audit log answers a
	// question for a different reader: what changed on this gateway. The code
	// is the bearer token that the handoff accepts, so it stays out, on the
	// same principle as admin.Args.Secret. The actor is the address that
	// redeemed. Its label tells readers that it is not an operator: no
	// user signed in here, and an agent gave a code.
	_ = s.Audit.Append(audit.Entry{
		Verb:  "claim.redeem",
		Actor: "agent:" + ip,
		Args:  map[string]string{"slot": c.Slot},
		OK:    true,
	})
	pi := s.Bind
	if h, _, err := net.SplitHostPort(r.Host); err == nil && net.ParseIP(h) != nil {
		pi = h
	} else if net.ParseIP(r.Host) != nil {
		pi = r.Host
	}
	body := ClaimScript(pi, c)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, body)
}

// maxConns bounds the number of connections that the server accepts at
// once. Deadlines bound the work in one connection. They do not bound the
// number of connections. The agent on the other side of this listener can
// open connections faster than they expire.
//
// The anti-spoof rule keeps a source inside AGENT_NET, but a root agent can
// add an alias for each free address there. With a pool of 64, eight
// aliases held all of it, and the accept loop then waited while every
// other agent queued in the backlog. So the pool holds the share of each
// address of a /24 at once, and no set of addresses inside such a segment
// can fill it. That is 768 connections at most, inside LimitNOFILE and
// MemoryMax of www.service.
const maxConns = 256 * maxConnsPerSource

// maxConnsPerSource is how many connections one agent address can hold. The
// global cap alone let one agent take all of them with slowloris sockets,
// opened again each ReadHeaderTimeout. An honest enrolment is setup.sh,
// ca.pem and a claim, in sequence, from one curl: one connection at a time.
const maxConnsPerSource = 3

// This is the only listener that a hostile agent reaches without a
// credential. It used to bound one thing: the time for the request headers.
// All after that was unbounded. A client that sends a header and then reads
// nothing holds a handler, blocked on a write, for as long as it wants.
// The bodies here are a shell script and a certificate, so the numbers can
// be very short.
func (s *Server) httpServer() *http.Server {
	return &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// limitConns caps concurrent connections: n in total, and perSource from
// any one address (0 disables the per-source cap). The listener takes a
// slot before Accept and gives it back when the connection closes. So the
// ceiling is on live connections, not on the rate of new ones.
func limitConns(ln net.Listener, n, perSource int) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n), perSrc: srclimit.New(perSource)}
}

type limitListener struct {
	net.Listener
	sem    chan struct{}
	perSrc *srclimit.PerSource
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		// Over its per-source cap, the connection closes here, and the loop
		// accepts the next connection on the same global slot. So an address that
		// floods never reaches http.Server, and never holds a slot after this
		// close. An error return would make http.Server delay its full accept
		// loop. That lets the flooder slow all other clients by other means.
		release, ok := l.perSrc.Acquire(c.RemoteAddr())
		if !ok {
			_ = c.Close()
			continue
		}
		return &limitConn{Conn: c, release: func() { release(); <-l.sem }}, nil
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (s *Server) Serve(ctx context.Context) error {
	addr := s.Addr()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if err := base.CheckBindHost(host); err != nil {
		return fmt.Errorf("www bind %q: %w", host, err)
	}
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		return err
	}
	srv := s.httpServer()
	srv.Addr = addr
	base, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ln := limitConns(base, maxConns, maxConnsPerSource)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("pi-fortress www http://%s/setup.sh", addr)
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
