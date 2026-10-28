package netgate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/nfq"
)

// fakeConntrack writes a script that prints out and stderr and exits with
// code. With sleep, it only sleeps, as one process (exec), as conntrack is.
func fakeConntrack(t *testing.T, out []byte, stderr string, code int, sleep int) []string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "table")
	if err := os.WriteFile(data, out, 0644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "conntrack")
	body := fmt.Sprintf("#!/bin/sh\ncat %s\necho '%s' >&2\nexit %d\n", data, stderr, code)
	if sleep > 0 {
		body = fmt.Sprintf("#!/bin/sh\nexec sleep %d\n", sleep)
	}
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return []string{script, "-L", "-o", "extended"}
}

// table is a conntrack listing of n lines, larger than one data message.
func table(n int) []byte {
	var b bytes.Buffer
	for i := range n {
		fmt.Fprintf(&b, "ipv4     2 tcp      6 431999 ESTABLISHED src=10.78.0.%d dst=93.184.216.34 sport=%d dport=443 packets=12 bytes=3456 src=93.184.216.34 dst=192.168.1.50 sport=443 dport=%d packets=10 bytes=7890 [ASSURED] mark=0 use=1\n", i%250+1, 40000+i, 40000+i)
	}
	return b.Bytes()
}

func TestCTStreamsTheWholeTable(t *testing.T) {
	want := table(2000)
	if len(want) < 3*ctChunk {
		t.Fatalf("the test table has %d bytes, too small to cross messages", len(want))
	}
	h := newHarness(t, func(c *Config) {
		c.CTArgv = fakeConntrack(t, want, "conntrack v1.4.7 (conntrack-tools): 2000 flow entries have been shown.", 0, 0)
	})
	got, err := ReadCT(h.sock("ct.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
	// An empty table is an empty answer, not an error.
	h2 := newHarness(t, func(c *Config) { c.CTArgv = fakeConntrack(t, nil, "0 flow entries", 0, 0) })
	if got, err := ReadCT(h2.sock("ct.sock")); err != nil || len(got) != 0 {
		t.Fatalf("empty table: %d bytes, %v", len(got), err)
	}
}

// At most one run each 2 s. observe asks one time in each 10 s poll.
func TestCTRate(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.CTArgv = fakeConntrack(t, table(3), "", 0, 0) })
	if _, err := ReadCT(h.sock("ct.sock")); err != nil {
		t.Fatal(err)
	}
	h.advance(time.Second)
	if _, err := ReadCT(h.sock("ct.sock")); err == nil || !strings.Contains(err.Error(), "more than one CT request") {
		t.Fatalf("a second request after 1 s: %v", err)
	}
	h.advance(time.Second)
	if _, err := ReadCT(h.sock("ct.sock")); err != nil {
		t.Fatalf("a request after 2 s: %v", err)
	}
	if !h.logged("CT refused") {
		t.Fatal("no log line for the refused request")
	}
}

// A failed run gives an error with the reason, and no part of the table.
func TestCTFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		argv func(t *testing.T) []string
		mod  func(c *Config)
		why  string
	}{
		"exit 1": {
			argv: func(t *testing.T) []string {
				return fakeConntrack(t, table(5), "conntrack v1.4.7 (conntrack-tools): Operation failed: Operation not permitted", 1, 0)
			},
			why: "Operation not permitted",
		},
		"no conntrack": {
			argv: func(t *testing.T) []string { return []string{filepath.Join(t.TempDir(), "conntrack")} },
			why:  "no such file",
		},
		"too slow": {
			argv: func(t *testing.T) []string { return fakeConntrack(t, table(5), "", 0, 3) },
			mod:  func(c *Config) { c.ctTimeout, c.ctMax = 200*time.Millisecond, ctMax },
			why:  "ran longer than",
		},
		"too large": {
			argv: func(t *testing.T) []string { return fakeConntrack(t, table(2000), "", 0, 0) },
			mod:  func(c *Config) { c.ctTimeout, c.ctMax = ctTimeout, 2*ctChunk },
			why:  "more than 65536 bytes",
		},
	} {
		h := newHarness(t, func(c *Config) {
			c.CTArgv = tc.argv(t)
			if tc.mod != nil {
				tc.mod(c)
			}
		})
		got, err := ReadCT(h.sock("ct.sock"))
		if err == nil || !strings.Contains(err.Error(), tc.why) || got != nil {
			t.Errorf("%s: %d bytes, error %v; want no data and %q", name, len(got), err, tc.why)
		}
	}
}

// Only observe. A request from another uid, or on the socket of pf dns,
// gets nothing; a GATE on the socket of observe is closed.
func TestCTPeerCheck(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.CT = Peer{UID: me().UID + 1, GID: me().GID}
		c.CTArgv = fakeConntrack(t, table(3), "", 0, 0)
	})
	if _, err := ReadCT(h.sock("ct.sock")); err == nil {
		t.Fatal("a CT request from another uid passed")
	}
	if !h.logged(fmt.Sprintf("ct.sock: peer uid %d gid %d refused", me().UID, me().GID)) {
		t.Fatal("no log line for the refused peer")
	}
	h2 := newHarness(t, func(c *Config) { c.CTArgv = fakeConntrack(t, table(3), "", 0, 0) })
	if _, err := ReadCT(h2.sock("dns.sock")); err == nil {
		t.Fatal("a CT request on dns.sock passed")
	}
	if err := Ping(h2.sock("ct.sock"), "resolved_v4"); err == nil {
		t.Fatal("a GATE on ct.sock passed")
	}
	if got := h2.calls(); len(got) != 0 {
		t.Fatalf("nft ran: %q", got)
	}
}

func TestCTRequestWire(t *testing.T) {
	if err := decodeCTRequest(ctRequest); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{{}, {verbCT}, {verbCT, 0, 0, 1}, {verbCT, 0, 0, 0, 0}, {'X', 0, 0, 0}} {
		if err := decodeCTRequest(b); !errors.Is(err, errProto) {
			t.Errorf("CT request %v: %v", b, err)
		}
	}
}

// With NoCT, netgate opens no ct.sock. A CT request fails, and the GATE
// and SNI of pf dns work as before.
func TestNoCTKeepsGateAndSNI(t *testing.T) {
	h, fq, _ := sniHarness(t, func(c *Config) {
		c.NoCT = true
		c.CTArgv = fakeConntrack(t, table(3), "", 0, 0)
	})
	if _, err := os.Stat(h.sock("ct.sock")); err == nil {
		t.Fatal("ct.sock exists with NoCT")
	}
	if _, err := ReadCT(h.sock("ct.sock")); err == nil {
		t.Fatal("a CT request passed with NoCT")
	}
	if err := NewGateClient(h.sock("dns.sock")).Add("resolved_v4", v4s("1.1.1.1")); err != nil {
		t.Fatalf("GATE with NoCT: %v", err)
	}
	sc, err := DialSNI(h.sock("dns.sock"), 1)
	if err != nil {
		t.Fatalf("SNI with NoCT: %v", err)
	}
	defer sc.Close()
	fq.in <- nfq.Packet{ID: 4}
	if _, err := sc.Recv(); err != nil {
		t.Fatal(err)
	}
}
