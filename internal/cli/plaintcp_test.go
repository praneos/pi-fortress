package cli

import (
	"net"
	"runtime/debug"
	"strings"
	"testing"
)

// pf listens and dials with plain TCP. Since Go 1.24 a listener uses MPTCP
// when the kernel has it. go.mod sets multipathtcp=0 for each binary of
// the module, so the box does not depend on the sysctl alone.
func TestListenersArePlainTCP(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info")
	}
	def := ""
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" {
			def = s.Value
		}
	}
	if !strings.Contains(","+def+",", ",multipathtcp=0,") {
		t.Fatalf("DefaultGODEBUG %q does not turn MPTCP off", def)
	}
	// On a kernel with MPTCP, the listener and the dialed connection are
	// plain TCP. On a kernel without it, this passes in any case.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener here:", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, conn := range map[string]net.Conn{"accepted": s, "dialed": c} {
		if mp, err := conn.(*net.TCPConn).MultipathTCP(); err != nil || mp {
			t.Errorf("%s connection: MPTCP %v, %v", name, mp, err)
		}
	}
}
