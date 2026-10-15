package origdst

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestParseInet4(t *testing.T) {
	raw := []byte{
		0x02, 0x00,
		0x01, 0xbb,
		0x0a, 0x4d, 0x00, 0x01,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	got, err := parseInet4(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.77.0.1:443" {
		t.Fatalf("got %s", got)
	}
}

func TestParseInet6(t *testing.T) {
	raw := make([]byte, 16)
	raw[0] = afInet6
	_, err := parseInet4(raw)
	if err != ErrIPv6 {
		t.Fatalf("err=%v", err)
	}
}

func TestParseShort(t *testing.T) {
	_, err := parseInet4([]byte{1, 2, 3})
	if err != ErrShort {
		t.Fatalf("err=%v", err)
	}
}

func TestGetNoRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := ln.Addr().(*net.TCPAddr).AddrPort()
	type result struct {
		addr netip.AddrPort
		err  error
	}
	resc := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resc <- result{err: err}
			return
		}
		defer c.Close()
		addr, err := Get(c.(*net.TCPConn))
		resc <- result{addr, err}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var r result
	select {
	case r = <-resc:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	if runtime.GOOS != "linux" {
		if r.err == nil || r.addr.IsValid() {
			t.Fatalf("non-linux Get = %v, %v; want zero addr and error", r.addr, r.err)
		}
		return
	}
	switch {
	case r.err == nil:
		if r.addr != want {
			t.Fatalf("tracked, not redirected: got %v, want own listener %v", r.addr, want)
		}
	case errors.Is(r.err, syscall.ENOENT), errors.Is(r.err, syscall.ENOPROTOOPT):
		if r.addr.IsValid() {
			t.Fatalf("err=%v but addr=%v", r.err, r.addr)
		}
	default:
		t.Fatalf("err=%v (%T); want nil, ENOENT (untracked) or ENOPROTOOPT (no conntrack)", r.err, r.err)
	}
	t.Logf("addr=%v err=%v", r.addr, r.err)
}
