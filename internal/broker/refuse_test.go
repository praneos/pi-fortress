package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

// rawRoundtrip returns all bytes of the response, with the headers. The
// byte-identical claim is about these bytes. It stops at the end of the
// first response, not at EOF. A refusal announces Connection: close and
// then continues to read. Thus a wait for the close would also collect the
// 400 of the idle timeout.
func rawRoundtrip(t *testing.T, b *Broker, p preamble.Preamble, raw string) string {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c1, raw); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	var seen bytes.Buffer
	if _, err := httpwire.ReadResponse(bufio.NewReader(io.TeeReader(c1, &seen)), 1<<20, false); err != nil {
		t.Fatal(err)
	}
	// The refusal said Connection: close. The broker closes, and nothing (no
	// deadline 400) follows the one response.
	rest, err := io.ReadAll(c1)
	if err != nil || len(rest) != 0 {
		t.Fatalf("after the refusal: %q, %v", rest, err)
	}
	<-errc
	return seen.String()
}

// Each refusal, not only the substitution refusal, closes the connection
// that it announced it would close. Before, the non-Expect paths went back
// to the loop of Handle, and an idle client got a deadline 400 after it.
func TestRefusalClosesTheConnection(t *testing.T) {
	b, _ := testBroker(t)
	p := preamble.Preamble{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.3:443")}
	got := rawRoundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
	if !strings.HasPrefix(got, "HTTP/1.1 501 ") || !strings.Contains(got, "Connection: close") {
		t.Fatalf("response %q", got)
	}
}

func refuseCase(t *testing.T, sni, ph string, prep func(t *testing.T, b *Broker, path string)) (string, []jsonl.Refused) {
	t.Helper()
	b, path := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
	if prep != nil {
		prep(t, b, path)
	}
	p := preamble.Preamble{SNI: sni, OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	if sni == "pf-open-echo.test" {
		p.OrigDst = netip.MustParseAddrPort("192.0.2.3:443")
	}
	got := rawRoundtrip(t, b, p, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nAuthorization: Bearer "+ph+"\r\n\r\n")
	raw, _ := os.ReadFile(b.Logs.StripPath)
	var rows []jsonl.Refused
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return got, rows
}

// The full design depends on this one property: an agent cannot tell the
// four causes apart. The test asserts it on the raw bytes, not on the
// status code. Reason: a header or a body that changed with the cause
// would leak as much as a code that changed. This property is also the
// most likely to erode when new causes are added. That is why it is a test
// and not a comment.
func TestRefusalIsByteIdenticalAcrossCauses(t *testing.T) {
	cases := []struct {
		name  string
		sni   string
		ph    string
		cause string
		prep  func(t *testing.T, b *Broker, path string)
	}{
		{
			name: "kind not allowed for this sni", sni: "pf-open-echo.test",
			ph:    secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN"),
			cause: "kind_not_allowed_for_sni",
		},
		{
			name: "slot unknown", sni: "pf-core-echo.test",
			ph:    secrets.Placeholder("0000000000000000", "GITHUB_TOKEN"),
			cause: "slot_unknown",
		},
		{
			name: "slot disabled", sni: "pf-core-echo.test",
			ph:    secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN"),
			cause: "slot_disabled",
			prep: func(t *testing.T, b *Broker, path string) {
				if err := secrets.Open(path).Disable("a1b2c3d4e5f67890"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "slot holds no value", sni: "pf-core-echo.test",
			ph:    secrets.Placeholder("1111111111111111", "GITHUB_TOKEN"),
			cause: "slot_empty",
			prep: func(t *testing.T, b *Broker, path string) {
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.WriteString(secrets.EnvKey("1111111111111111", "GITHUB_TOKEN") + "=\n"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	var first string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rows := refuseCase(t, tc.sni, tc.ph, tc.prep)
			if first == "" {
				first = got
			} else if got != first {
				t.Fatalf("the agent can tell this cause apart:\n%q\nwant\n%q", got, first)
			}
			if !strings.Contains(got, "503 Service Unavailable") || !strings.Contains(got, "Retry-After: 60") || !strings.HasSuffix(got, RefusedBody) {
				t.Fatalf("response %q", got)
			}
			for _, leak := range []string{tc.cause, "slot", "kind", "sealed", "disabled", "unknown"} {
				if strings.Contains(strings.ToLower(got), leak) {
					t.Fatalf("the response names %q: %q", leak, got)
				}
			}
			// The broker does not delete the detail. It only routes it.
			if len(rows) != 1 {
				t.Fatalf("operator log rows %+v", rows)
			}
			r := rows[0]
			// Each case gets a new broker. Thus this is the first refusal of its
			// cause, and each of them is marked. The second refusal is different: see
			// TestOperationalCauseAlertsOnce.
			if r.Ev != "substitution_refused" || r.Cause != tc.cause || !r.Alert || r.Where != "header" || r.SNI != tc.sni {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// If a 03:00 power cut seals the store, the store refuses all that an
// agent retries. The operator must get this information one time. A
// webhook every few seconds makes people mute the alert channel. The
// destination deny is the opposite case: a flood of those is the signal.
func TestOperationalCauseAlertsOnce(t *testing.T) {
	b, path := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	if err := secrets.Open(path).Disable("a1b2c3d4e5f67890"); err != nil {
		t.Fatal(err)
	}
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	raw := "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer " + secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN") + "\r\n\r\n"
	open := preamble.Preamble{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.3:443"), Src: netip.MustParseAddrPort("10.77.0.10:51000")}
	openRaw := "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer " + secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN") + "\r\n\r\n"
	for range 3 {
		rawRoundtrip(t, b, p, raw)
		rawRoundtrip(t, b, open, openRaw)
	}
	body, _ := os.ReadFile(b.Logs.StripPath)
	var disabled, denied int
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		// The refusal names the client when the preamble carried one. When the
		// preamble carried none, the row is byte-for-byte the old row.
		if has := strings.Contains(line, `"client_ip":"10.77.0.10"`); has != (r.Cause == "kind_not_allowed_for_sni") || (!has && strings.Contains(line, "client_ip")) {
			t.Fatalf("client_ip on %s", line)
		}
		if !r.Alert {
			continue
		}
		switch r.Cause {
		case "slot_disabled":
			disabled++
		case "kind_not_allowed_for_sni":
			denied++
		}
	}
	if disabled != 1 {
		t.Fatalf("a disabled slot alerted %d times, want 1", disabled)
	}
	if denied != 3 {
		t.Fatalf("the destination deny alerted %d times, want every one", denied)
	}
}

// A key in a field name is attempted egress, like a placeholder aimed at a
// wrong host. Each one alerts, and the agent gets the one refusal.
func TestKeyInHeaderNameAlertsEachTime(t *testing.T) {
	b, _ := testBroker(t)
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
	p := preamble.Preamble{SNI: "pf-open-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.3:443")}
	raw := "GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nX-" + secrets.Placeholder("a1b2c3d4e5f67890", "GITHUB_TOKEN") + ": 1\r\n\r\n"
	for range 3 {
		got := rawRoundtrip(t, b, p, raw)
		if !strings.Contains(got, "503 Service Unavailable") || !strings.HasSuffix(got, RefusedBody) {
			t.Fatalf("not the one refusal: %q", got)
		}
	}
	body, _ := os.ReadFile(b.Logs.StripPath)
	alerts := 0
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Cause == "key_in_header_name" && r.Alert {
			alerts++
		}
	}
	if alerts != 3 {
		t.Fatalf("%d alerts, want 3:\n%s", alerts, body)
	}
}
