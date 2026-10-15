package broker

import (
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// A strip that reached the wire is a fact about the wire, whatever
// occurred to the request after. The broker scrubs a streamed body during
// the copy to the origin. Here the copy fails at a placeholder that the
// stream may not substitute. At that time, the broker has already
// replaced the earlier credential in bytes that the origin received.
// serve returned on the roundTrip error and never read stream.Events(),
// so that strip left no row. That row is the one record for the operator
// that the agent put a live credential on the wire. It was lost because
// the request that carried it ended badly.
func TestStreamStripLoggedWhenRequestEndsInRefusal(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	ph := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	pat := "ghp_" + strings.Repeat("A", 36)
	var leaked atomic.Bool
	done := make(chan struct{}, 1)
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), pat) {
			leaked.Store(true)
		}
		done <- struct{}{}
	})
	// The token sits far enough ahead of the placeholder that the stream
	// has committed and written it before the guard ends the copy.
	body := strings.Repeat("z", 600<<10) + " " + pat + " " + strings.Repeat("z", 600<<10) + " " + ph + " tail"
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	raw := "POST /v1/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	resp, rb := roundtripStream(t, b, p, raw)
	if resp.Code != 503 || string(rb) != RefusedBody {
		t.Fatalf("%d %q", resp.Code, rb)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	if leaked.Load() {
		t.Fatal("the origin saw the token the stream was meant to strip")
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(rows), `"rule":"github_classic"`) {
		t.Fatalf("a strip that happened on the wire left no row: %q", rows)
	}
	// The refusal is still logged, and the strip is logged once.
	if !strings.Contains(string(rows), `"cause":"placeholder_in_streamed_body"`) {
		t.Fatalf("the refusal lost its cause: %q", rows)
	}
	if n := strings.Count(string(rows), `"rule":"github_classic"`); n != 1 {
		t.Fatalf("the strip was logged %d times: %q", n, rows)
	}
}

// The ordinary success path logs each streamed strip exactly once. It is
// the same call site as the refusal above. So a fix that logs on the
// error path must not make the success path log twice.
func TestStreamStripLoggedOnceOnSuccess(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	pat := "ghp_" + strings.Repeat("A", 36)
	var leaked atomic.Bool
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), pat) {
			leaked.Store(true)
		}
		w.WriteHeader(200)
	})
	body := strings.Repeat("z", 600<<10) + " " + pat + " " + strings.Repeat("z", 600<<10)
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	raw := "POST /v1/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	resp, _ := roundtripStream(t, b, p, raw)
	if resp.Code != 200 {
		t.Fatalf("%d", resp.Code)
	}
	if leaked.Load() {
		t.Fatal("the origin saw the token the stream was meant to strip")
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if n := strings.Count(string(rows), `"rule":"github_classic"`); n != 1 {
		t.Fatalf("the strip was logged %d times, want 1: %q", n, rows)
	}
}
