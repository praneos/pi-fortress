package engine

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/preamble"
)

func blockedHello(t *testing.T, addr, sni string) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatalf("handshake with blocked sni %q succeeded", sni)
	}
}

// A blocked name goes to the broker as a preamble with a refusal cause
// and no TLS session, so that the broker writes the row to strip.jsonl.
// One name from one client gives one row in sniRowEvery. The journal line
// stays for each connection.
func TestBlockedSNISendsOneRefusalPerNameAndClient(t *testing.T) {
	sock, ch := startEchoBroker(t)
	orig := netip.MustParseAddrPort("192.0.2.24:443")
	addr, _, logs, _ := startEngineWith(t, sock, orig, nil, func(e *Engine) {
		e.Blocked = blocklist.New("phish.example")
	})
	blockedHello(t, addr, "phish.example")
	select {
	case p := <-ch:
		if p.Refused != preamble.RefusedSNIBlocked || p.SNI != "phish.example" || p.OrigDst != orig || !p.Src.IsValid() {
			t.Fatalf("preamble %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no refusal reached the broker")
	}
	blockedHello(t, addr, "phish.example")
	blockedHello(t, addr, "login.phish.example")
	select {
	case p := <-ch:
		if p.SNI != "login.phish.example" {
			t.Fatalf("second refusal for %q, want only login.phish.example", p.SNI)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no refusal for a second name")
	}
	select {
	case p := <-ch:
		t.Fatalf("extra preamble %+v", p)
	case <-time.After(200 * time.Millisecond):
	}
	waitLog(t, logs, "sni blocked refused sni=login.phish.example")
}

func TestRowDueBoundsTheTable(t *testing.T) {
	e := &Engine{}
	now := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("10.77.0.10")
	if !e.rowDue(src, "a.example", now) {
		t.Fatal("first row not due")
	}
	if e.rowDue(src, "a.example", now.Add(sniRowEvery-time.Second)) {
		t.Fatal("second row inside sniRowEvery is due")
	}
	if !e.rowDue(src, "a.example", now.Add(sniRowEvery)) {
		t.Fatal("row after sniRowEvery not due")
	}
	for i := range 3 * sniRowKeys {
		e.rowDue(src, strconv.Itoa(i)+".example", now)
	}
	if n := len(e.rowLast); n > sniRowKeys {
		t.Fatalf("table has %d keys, cap %d", n, sniRowKeys)
	}
}
