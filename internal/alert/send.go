package alert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

// Under pressure, the DNS daemon of the Pi can be slow or stopped, and a
// new process cannot get memory. So the pressure sender makes the costly
// parts ready before they are necessary: the addresses of the webhook host,
// the system roots, and one HTTP/1.1 connection that it keeps open between
// posts. It sends no request to keep the connection open. The server
// closes an idle connection when it wants. Then a cached address and a TLS
// session ticket make the next connection cheap.
const (
	sendTimeout   = 5 * time.Second
	sendRetry     = time.Second
	backlogRetry  = time.Minute
	backlogMax    = 8
	resolveEvery  = 10 * time.Minute
	dialTimeout   = 3 * time.Second
	idleConnLimit = 10 * time.Minute
)

// hostCache keeps the last good addresses of the webhook host. A failed
// lookup keeps the old addresses.
type hostCache struct {
	mu     sync.Mutex
	host   string
	addrs  []netip.Addr
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

func (c *hostCache) setHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.host != host {
		c.host, c.addrs = host, nil
	}
}

func (c *hostCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	host := c.host
	c.mu.Unlock()
	if host == "" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		c.store(host, []netip.Addr{ip})
		return nil
	}
	lookup := c.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	ips, err := lookup(ctx, host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("no address for %s", host)
	}
	c.store(host, ips)
	return nil
}

func (c *hostCache) store(host string, ips []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.host == host {
		c.addrs = ips
	}
}

// dial connects to the cached addresses of the host, in order. For a
// different host, or with no address yet, it dials the name.
func (c *hostCache) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	ips := c.addrs
	if host != c.host {
		ips = nil
	}
	c.mu.Unlock()
	if len(ips) == 0 {
		return d.DialContext(ctx, network, addr)
	}
	var first error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// warmClient is the HTTP client of the sender. The TLS server name is the
// host of the URL, as with each dial: only the address comes from the
// cache.
func warmClient(c *hostCache) *http.Client {
	tr := &http.Transport{
		DialContext:           c.dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(4)},
		TLSHandshakeTimeout:   sendTimeout,
		ResponseHeaderTimeout: sendTimeout,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       idleConnLimit,
	}
	return &http.Client{Transport: tr, Timeout: sendTimeout}
}

// sender posts the pressure messages. The loop gives a message with put,
// which never blocks. A message that fails two times waits in a short
// backlog, and the sender tries it again each minute.
type sender struct {
	ch      chan string
	out     io.Writer
	errw    io.Writer
	cache   *hostCache
	client  *http.Client
	url     string
	dropped int
	mu      sync.Mutex
	// load reads the webhook URL again (LoadURL).
	load func() string
	// retryEvery is backlogRetry. Tests make it short.
	retryEvery time.Duration
}

func newSender(out, errw io.Writer, load func() string) *sender {
	c := &hostCache{}
	return &sender{ch: make(chan string, sendQueue), out: out, errw: errw, cache: c, client: warmClient(c), load: load, retryEvery: backlogRetry}
}

func (s *sender) put(msg string) {
	select {
	case s.ch <- msg:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// prepare reads the URL, resolves its host and loads the system roots.
func (s *sender) prepare(ctx context.Context) {
	s.url = s.load()
	if u, err := url.Parse(s.url); err == nil && u.Hostname() != "" {
		s.cache.setHost(u.Hostname())
		if err := s.cache.refresh(ctx); err != nil {
			fmt.Fprintf(s.errw, "pressure: webhook host not resolved, the last addresses stay: %s\n", postFailure(s.url, err))
		}
	}
	_, _ = x509.SystemCertPool()
}

func (s *sender) post(msg string) bool {
	a := &Alerter{Client: s.client, Stderr: s.errw}
	if a.PostMessage(s.url, msg) == nil {
		return true
	}
	time.Sleep(sendRetry)
	return a.PostMessage(s.url, msg) == nil
}

func (s *sender) run(ctx context.Context) {
	s.prepare(ctx)
	every := s.retryEvery
	if every <= 0 {
		every = backlogRetry
	}
	retry := time.NewTicker(every)
	defer retry.Stop()
	resolve := time.NewTicker(resolveEvery)
	defer resolve.Stop()
	var backlog []string
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.ch:
			fmt.Fprintln(s.out, msg)
			s.mu.Lock()
			if s.dropped > 0 {
				msg += fmt.Sprintf(" (%d earlier pressure message%s dropped: the queue was full)", s.dropped, plural(s.dropped))
				s.dropped = 0
			}
			s.mu.Unlock()
			backlog = append(backlog, msg)
			if len(backlog) > backlogMax {
				backlog = backlog[len(backlog)-backlogMax:]
			}
		case <-retry.C:
		case <-resolve.C:
			s.prepare(ctx)
			continue
		}
		for len(backlog) > 0 && s.url != "" && ctx.Err() == nil {
			if !s.post(backlog[0]) {
				break
			}
			backlog = backlog[1:]
		}
	}
}
