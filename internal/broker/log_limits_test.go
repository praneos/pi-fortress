package broker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/alert"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

// TestStripRowsCappedPerRequest is the 900-row request: each header holds
// a token. strip.jsonl gets the first maxStripRows rows, which pf alert
// fires on. It also gets one summary row that counts the remaining rows,
// and pf alert still reads that row as a strip row.
func TestStripRowsCappedPerRequest(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	rawUpstream(t, b, func(i int, req *httpwire.Request, c net.Conn) bool {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		return false
	})
	var raw strings.Builder
	raw.WriteString("GET / HTTP/1.1\r\nHost: example.com\r\n")
	const tokens = 30
	for i := range tokens {
		fmt.Fprintf(&raw, "X-T%d: ghp_%036d\r\n", i, i)
	}
	raw.WriteString("\r\n")
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("8.8.8.8:443"), Src: netip.MustParseAddrPort("10.77.0.10:51000")}
	roundtrip(t, b, p, raw.String())
	data, err := os.ReadFile(b.Logs.StripPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows, summaries int
	var summary map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if ev["rule"] == stripSummaryRule {
			summaries++
			summary = ev
			continue
		}
		rows++
	}
	if rows != maxStripRows || summaries != 1 {
		t.Fatalf("rows=%d summaries=%d, want %d and 1:\n%s", rows, summaries, maxStripRows, data)
	}
	if n, _ := summary["count"].(float64); int(n) != tokens-maxStripRows {
		t.Fatalf("summary counts %v, want %d: %v", summary["count"], tokens-maxStripRows, summary)
	}
	if got, want := alert.Summarize(summary), "STRIP suppressed in request -> example.com"; got != want {
		t.Fatalf("pf alert reads the summary as %q, want %q", got, want)
	}
}

// TestStripCapLetsCanaryThrough: a request that spent its rows on junk
// tokens still logs the canary one time, and only one time.
func TestStripCapLetsCanaryThrough(t *testing.T) {
	var cp stripCap
	for i := range maxStripRows {
		if !cp.take(false) {
			t.Fatalf("row %d refused under the cap", i)
		}
	}
	if cp.take(false) {
		t.Fatal("a row past the cap was let through")
	}
	if !cp.take(true) {
		t.Fatal("the first canary past the cap was dropped")
	}
	if cp.take(true) {
		t.Fatal("a second canary past the cap was let through")
	}
	if n := cp.drain(); n != 2 {
		t.Fatalf("suppressed %d, want 2", n)
	}
	var none *stripCap
	if !none.take(false) {
		t.Fatal("a nil cap must count nothing")
	}
}
