package cli

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The loop of the admin socket has a cap, the same as the broker loop.
// Past max, it closes a connection immediately, without the cost of a
// goroutine. A slot that becomes free takes the next caller.
func TestAcceptCappedDropsPastMax(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	release := make(chan struct{})
	var serving atomic.Int32
	go func() {
		defer close(done)
		acceptCapped(ctx, ln, 2, "test", func(c net.Conn) error {
			defer c.Close()
			serving.Add(1)
			<-release
			return nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})
	dial := func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	closedSoon := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF
	}
	a, b := dial(), dial()
	for serving.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	if !closedSoon(dial()) {
		t.Fatal("a third connection was held past the cap")
	}
	if closedSoon(a) || closedSoon(b) {
		t.Fatal("a connection inside the cap was closed")
	}
	close(release)
	if !closedSoon(a) || !closedSoon(b) {
		t.Fatal("released connections were not closed")
	}
	// A slot becomes free immediately after its connection closes. Thus
	// the next caller retries, as a real caller does.
	deadline := time.Now().Add(3 * time.Second)
	for serving.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("a freed slot did not take the next caller")
		}
		dial()
		time.Sleep(5 * time.Millisecond)
	}
}

// flakyListener fails Accept with EMFILE while fails is above zero, then
// accepts on the real listener.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
	calls atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	if l.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

// A lasting accept error (EMFILE) does not spin the loop at full CPU and
// flood the journal: it backs off. When the error passes, the loop serves
// again.
func TestAcceptCappedBacksOff(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	sock := filepath.Join(t.TempDir(), "a.sock")
	real, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: real}
	ln.fails.Store(1 << 30)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var served atomic.Int32
	go func() {
		defer close(done)
		acceptCapped(ctx, ln, 2, "test", func(c net.Conn) error {
			served.Add(1)
			return c.Close()
		})
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})
	time.Sleep(300 * time.Millisecond)
	// 5, 10, 20, 40, 80, 160 ms: about 7 calls in 300 ms.
	if n := ln.calls.Load(); n > 15 {
		t.Fatalf("%d accept calls in 300 ms; the loop does not back off", n)
	}
	ln.fails.Store(0)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for served.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the loop did not serve after the error passed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// pf engine has no wildcard default and refuses a given wildcard. www
// already had this rule. It refuses before it reads the CA.
func TestEngineRefusesWildcardListen(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "missing.pem")
	for _, l := range []string{"", "0.0.0.0:8080", "[::]:8080", ":8080", "pi.example:8080", "224.0.0.1:8080", "10.77.0.1"} {
		args := []string{"engine", "-ca", ca}
		if l != "" {
			args = append(args, "-listen", l)
		}
		var out, errb bytes.Buffer
		if code := Main(args, &out, &errb); code == 0 || !strings.Contains(errb.String(), "-listen") {
			t.Errorf("%q: code=%d stderr=%q", l, code, errb.String())
		}
	}
}

func brokerArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	repo := filepath.Join("..", "..")
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secrets, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return append([]string{"broker",
		"-policy", filepath.Join(repo, "vm", "policy", "core.hosts"),
		"-rules", filepath.Join(repo, "vm", "policy", "key_prefixes.rules"),
		"-secrets", secrets, "-agent-net", "10.77.0.0/24",
		"-sock", filepath.Join(dir, "b.sock")}, extra...)
}

// A negative or absurd -mem-budget-mb is a typo. pf refuses it. It does
// not read it as the default.
func TestBrokerRefusesBadMemBudget(t *testing.T) {
	for _, v := range []string{"-1", "2000000"} {
		var out, errb bytes.Buffer
		code := Main(brokerArgs(t, "-mem-budget-mb", v), &out, &errb)
		if code == 0 || !strings.Contains(errb.String(), "-mem-budget-mb") {
			t.Fatalf("%s: code=%d stderr=%q", v, code, errb.String())
		}
	}
}

// A public -fakeip-net typed by hand is refused at the flag, as render
// refuses FAKEIP_NET, before anything binds.
func TestBrokerRefusesPublicFakeIPNet(t *testing.T) {
	repo := filepath.Join("..", "..")
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secrets, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := Main([]string{"broker",
		"-policy", filepath.Join(repo, "vm", "policy", "core.hosts"),
		"-rules", filepath.Join(repo, "vm", "policy", "key_prefixes.rules"),
		"-secrets", secrets, "-agent-net", "10.77.0.0/24",
		"-sock", filepath.Join(dir, "b.sock"),
		"-fakeip-net", "8.8.0.0/16", "-fakeip-journal", filepath.Join(dir, "j")}, &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "-fakeip-net") || !strings.Contains(errb.String(), "must sit inside") {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "b.sock")); err == nil {
		t.Fatal("the broker bound its socket before refusing the flag")
	}
}
