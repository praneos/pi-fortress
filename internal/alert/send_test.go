package alert

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCachedDialerKeepsLastGoodAddress: the webhook host resolves one
// time. A later lookup that fails (the DNS of the Pi is down) keeps the
// address, and the post still goes out. The URL keeps its host name, so
// TLS and the Host header see the name, not the address.
func TestCachedDialerKeepsLastGoodAddress(t *testing.T) {
	var hosts []string
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer ts.Close()
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	hook := "http://hook.invalid:" + strconv.Itoa(port) + "/topic"

	var lookups atomic.Int32
	failing := atomic.Bool{}
	c := &hostCache{lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if host != "hook.invalid" {
			t.Errorf("lookup of %q", host)
		}
		if failing.Load() {
			return nil, errors.New("no DNS")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	c.setHost("hook.invalid")
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := &Alerter{Client: warmClient(c), Stderr: &bytes.Buffer{}}
	if err := a.PostMessage(hook, "one"); err != nil {
		t.Fatalf("post with a cached address: %v", err)
	}
	failing.Store(true)
	if err := c.refresh(context.Background()); err == nil {
		t.Fatal("a failed lookup reported no error")
	}
	// A new connection, not the idle one: the address must come from the
	// cache again.
	a.Client.CloseIdleConnections()
	if err := a.PostMessage(hook, "two"); err != nil {
		t.Fatalf("post after a failed lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != 2 || !strings.HasPrefix(hosts[0], "hook.invalid:") {
		t.Fatalf("Host headers = %v", hosts)
	}
	if lookups.Load() != 2 {
		t.Fatalf("lookups = %d; a dial must not resolve", lookups.Load())
	}
}

// TestCachedDialerReusesConnection: two posts share one connection.
func TestCachedDialerReusesConnection(t *testing.T) {
	var conns atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	ts.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	ts.Start()
	defer ts.Close()
	c := &hostCache{}
	c.setHost("127.0.0.1")
	_ = c.refresh(context.Background())
	a := &Alerter{Client: warmClient(c), Stderr: &bytes.Buffer{}}
	for _, m := range []string{"a", "b", "c"} {
		if err := a.PostMessage(ts.URL+"/t", m); err != nil {
			t.Fatal(err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("connections = %d; want one kept open", n)
	}
}

// TestSenderRetriesAndNeverBlocks: a refused post stays in the backlog
// and goes out on the next retry. put never waits on the network.
func TestSenderRetriesAndNeverBlocks(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusTooManyRequests)
	got := make(chan string, 16)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			got <- string(b)
		}
	}))
	defer ts.Close()
	var out, errw bytes.Buffer
	var outMu sync.Mutex
	s := newSender(lockedWriter{&outMu, &out}, lockedWriter{&outMu, &errw}, func() string { return ts.URL + "/t" })
	s.retryEvery = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	start := time.Now()
	for range sendQueue * 3 {
		s.put("PRESSURE HIGH test")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("put waited")
	}
	time.Sleep(2500 * time.Millisecond)
	status.Store(http.StatusOK)
	select {
	case m := <-got:
		if !strings.HasPrefix(m, "PRESSURE HIGH test") {
			t.Fatalf("posted %q", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the backlog was not retried")
	}
	cancel()
	<-done
	outMu.Lock()
	defer outMu.Unlock()
	if !strings.Contains(errw.String(), "status 429") {
		t.Fatalf("the refusal is not in stderr: %q", errw.String())
	}
	if !strings.Contains(out.String(), "PRESSURE HIGH test") {
		t.Fatal("the message is not on stdout (the journal)")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
