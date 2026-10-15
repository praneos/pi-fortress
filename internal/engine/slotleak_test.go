package engine

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"pi-fortress/internal/ca"
	"pi-fortress/internal/preamble"
)

// startStreamBroker answers the preamble, and then pushes flood bytes at
// the engine. It is a stand-in for an origin server that serves a large
// response: the bytes that the engine must write back to a client that no
// longer reads.
func startStreamBroker(t *testing.T, flood int) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "stream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := preamble.Decode(br); err != nil {
					return
				}
				buf := make([]byte, 64*1024)
				for sent := 0; sent < flood; sent += len(buf) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
				// Hold the conn, so the engine never sees EOF from this side.
				// Only the deadlines of the engine can end the splice.
				<-t.Context().Done()
			}(c)
		}
	}()
	return sock
}

// dialDeafClient completes the TLS handshake, and then never reads again.
// A hostile agent gets the tiny receive buffer for free when it advertises
// a zero window. It caps how much the engine can push before its write blocks.
func dialDeafClient(t *testing.T, addr, sni string, store *ca.Store) *tls.Conn {
	t.Helper()
	d := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(store.Root())
	tc := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { tc.Close() })
	return tc
}

// slotFree probes the single-slot engine. When the slot is free, the engine
// accepts and waits for a ClientHello until the handshake deadline, so the
// probe read times out. When the slot is held, the accept loop closes the
// conn immediately.
func slotFree(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// TestIdleReleasesSlotWithNothingToWrite is the control: the same harness
// and the same deaf client, but no bytes for the engine to write back. Both
// copy directions end on the read deadline, and the slot comes back.
func TestIdleReleasesSlotWithNothingToWrite(t *testing.T) {
	sock := startStreamBroker(t, 0)
	orig := netip.MustParseAddrPort("192.0.2.40:443")
	const idle = 200 * time.Millisecond
	addr, store, logs, _ := startEngineWith(t, sock, orig, nil, func(e *Engine) {
		e.Idle = idle
		e.MaxConns = 1
	})
	tc := dialDeafClient(t, addr, "example.com", store)
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * idle)
	if !slotFree(t, addr) {
		t.Fatalf("control: slot still held after 10 idle periods, logs=%q", logs.String())
	}
}

// TestBlockedWriteReleasesSlot is the deaf client with something to hear.
// It asks for 16 MiB and never reads a byte, so the engine write to it
// blocks when both socket buffers fill. While copyIdle bounded only the
// read side, that goroutine stayed in dst.Write permanently. splice waited
// on a second done that never came, and the slot was gone until the
// process died. 256 sockets were enough to deny the proxy to all clients.
// The write deadline ends it, so the slot must come back without help.
func TestBlockedWriteReleasesSlot(t *testing.T) {
	sock := startStreamBroker(t, 16<<20)
	orig := netip.MustParseAddrPort("192.0.2.41:443")
	const idle = 200 * time.Millisecond
	addr, store, logs, _ := startEngineWith(t, sock, orig, nil, func(e *Engine) {
		e.Idle = idle
		e.MaxConns = 1
	})
	tc := dialDeafClient(t, addr, "example.com", store)
	if _, err := tc.Write([]byte("GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// Ten idle periods: long enough that a slot still held here is held
	// by the wedge, and not by a copy that had not timed out yet.
	time.Sleep(10 * idle)
	if !slotFree(t, addr) {
		t.Fatalf("slot still held 10 idle periods after the last client byte, logs=%q", logs.String())
	}
}
