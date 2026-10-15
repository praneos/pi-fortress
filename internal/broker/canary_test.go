package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

const (
	canarySlot = "d0d1d2d3d4d5d6d7"
	canaryLive = "canary-live-7f3a9c2e51"
)

// addCanary puts a CANARY slot in the test store and returns its
// placeholder.
func addCanary(t *testing.T, path string) string {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(secrets.EnvKey(canarySlot, corepolicy.KindCanary) + "=" + canaryLive + "\n"); err != nil {
		t.Fatal(err)
	}
	return secrets.Placeholder(canarySlot, corepolicy.KindCanary)
}

// canaryCall writes raw from a goroutine, so a refusal that closes the
// connection mid-body does not block the writer. It returns the body of
// the one response.
func canaryCall(t *testing.T, b *Broker, p preamble.Preamble, raw string) string {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	go func() {
		_ = preamble.Encode(c1, &p)
		_, _ = io.WriteString(c1, raw)
	}()
	_ = c1.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := httpwire.ReadResponse(bufio.NewReader(c1), 1<<20, false)
	c1.Close()
	<-errc
	if err != nil {
		t.Fatal(err)
	}
	return string(resp.Body)
}

// The agent holds the CANARY placeholder. It aims the placeholder, and
// also the live value, at a core host that does not bind CANARY and at a
// foreign host. It puts them in a header, past the buffer in a streamed
// body, and in the URL. The origin sees neither the value nor the
// placeholder. Each attempt writes a canary row, with "threat":"canary" as
// the last field of the row. Each refusal row has the alert flag.
func TestCanaryNeverOnTheWire(t *testing.T) {
	b, path := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	b.AllowHosts = map[string]struct{}{"example.com": {}}
	ph := addCanary(t, path)
	var mu sync.Mutex
	var seen bytes.Buffer
	countingUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		fmt.Fprintf(&seen, "%s %s %v %s\n", r.Method, r.URL, r.Header, body)
		mu.Unlock()
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	})
	big := strings.Repeat("z", 1<<20+16) + " " + ph + " tail"
	small := `{"k":"` + canaryLive + `"}`
	for _, sni := range []string{"api.anthropic.com", "example.com"} {
		p := preamble.Preamble{SNI: sni, OrigDst: netip.MustParseAddrPort("8.8.8.8:443"), Src: netip.MustParseAddrPort("10.77.0.10:51000")}
		if got := canaryCall(t, b, p, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nAuthorization: Bearer "+ph+"\r\n\r\n"); strings.Contains(got, canaryLive) {
			t.Fatal(got)
		}
		canaryCall(t, b, p, "POST / HTTP/1.1\r\nHost: "+sni+"\r\nContent-Length: "+strconv.Itoa(len(big))+"\r\n\r\n"+big)
		canaryCall(t, b, p, "POST /x?k="+canaryLive+" HTTP/1.1\r\nHost: "+sni+"\r\nX-K: "+canaryLive+"\r\nContent-Length: "+strconv.Itoa(len(small))+"\r\n\r\n"+small)
	}
	mu.Lock()
	wire := seen.String()
	mu.Unlock()
	if strings.Contains(wire, canaryLive) || strings.Contains(wire, ph) {
		t.Fatalf("canary reached the origin:\n%.2000s", wire)
	}
	raw, _ := os.ReadFile(b.Logs.StripPath)
	header, stream, strips := 0, 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.Contains(line, "CANARY") {
			if strings.Contains(line, "threat") {
				t.Fatalf("threat on a non-canary row: %s", line)
			}
			continue
		}
		if !strings.HasSuffix(line, `,"threat":"canary"}`) {
			t.Fatalf("threat not last: %s", line)
		}
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		switch {
		case r.Ev == "" && strings.HasPrefix(r.Rule, "secret:"+canarySlot+"_CANARY"):
			strips++
		case !r.Alert || r.Slot != canarySlot || r.Kind != corepolicy.KindCanary:
			t.Fatalf("refusal row: %s", line)
		case r.Cause == "kind_not_allowed_for_sni":
			header++
		case r.Cause == "placeholder_in_streamed_body":
			stream++
		}
	}
	if header != 2 || stream != 2 || strips < 2 {
		t.Fatalf("header=%d stream=%d strips=%d\n%s", header, stream, strips, raw)
	}
}

// With CANARY bound, a placeholder for a slot that is not there alerts
// each time. The once-per-cause alert of other kinds does not change.
func TestCanaryDoesNotSpendTheOnceAlert(t *testing.T) {
	b, path := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	addCanary(t, path)
	pol := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(pol, []byte("pf-core-echo.test CANARY GITHUB_TOKEN\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	if b.Policy, err = corepolicy.Load(pol); err != nil {
		t.Fatal(err)
	}
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	send := func(ph string) {
		rawRoundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer "+ph+"\r\n\r\n")
	}
	for range 3 {
		send(secrets.Placeholder("ffffffffffffffff", corepolicy.KindCanary))
	}
	for range 2 {
		send(secrets.Placeholder("ffffffffffffffff", "GITHUB_TOKEN"))
	}
	raw, _ := os.ReadFile(b.Logs.StripPath)
	var alerts []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Cause != "slot_unknown" {
			t.Fatalf("cause: %s", line)
		}
		alerts = append(alerts, fmt.Sprintf("%s:%v:%s", r.Kind, r.Alert, r.Threat))
	}
	want := "CANARY:true:canary CANARY:true:canary CANARY:true:canary GITHUB_TOKEN:true: GITHUB_TOKEN:false:"
	if got := strings.Join(alerts, " "); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
