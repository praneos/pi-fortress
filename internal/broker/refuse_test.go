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
	"sync/atomic"
	"testing"
	"time"

	"pi-fortress/internal/alert"
	"pi-fortress/internal/blocklist"
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

// A live value in Host is attempted egress: the origin routes by that
// name. Each one alerts, and the agent gets the one refusal. The row names
// the SNI, not the Host, so the value does not go to the log or to the
// webhook.
func TestLiveValueInHostAlertsEachTime(t *testing.T) {
	b, _ := testBroker(t)
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
	for _, sni := range []string{"pf-open-echo.test", "pf-core-echo.test"} {
		p := preamble.Preamble{SNI: sni, OrigDst: netip.MustParseAddrPort("192.0.2.3:443")}
		raw := "GET / HTTP/1.1\r\nHost: lab_fence_github." + sni + "\r\n\r\n"
		for range 2 {
			got := rawRoundtrip(t, b, p, raw)
			if !strings.Contains(got, "503 Service Unavailable") || !strings.HasSuffix(got, RefusedBody) {
				t.Fatalf("%s: not the one refusal: %q", sni, got)
			}
		}
	}
	body, _ := os.ReadFile(b.Logs.StripPath)
	if strings.Contains(string(body), "lab_fence_github") {
		t.Fatalf("the live value is in the log:\n%s", body)
	}
	alerts := 0
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var r jsonl.Refused
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Cause == "live_in_host" && r.Alert && r.Slot == "a1b2c3d4e5f67890" && r.Host == r.SNI {
			alerts++
		}
	}
	if alerts != 4 {
		t.Fatalf("%d alerts, want 4:\n%s", alerts, body)
	}
}

// The broker decides on a WebSocket from Connection and Upgrade before the
// fence runs. A live value there refuses the request, also a kind that the
// host injects, and each one alerts. Nothing goes to the origin, and no
// row or alert text carries the live value.
func TestLiveValueInConnectionAlertsEachTime(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	// The broker may dial ahead (predial). The origin must get no request.
	var got atomic.Bool
	wsUpstream(t, b, func(*httpwire.Request, net.Conn, *bufio.Reader) { got.Store(true) })
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64)
	ghp := "ghp_" + strings.Repeat("A", 36)
	ws := "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	for _, tc := range []struct{ fields, want string }{
		{"Connection: lab_fence_github\r\n", RefusedBody},
		{ws + "Connection: Upgrade, " + oat + "\r\n", RefusedBody},
		{"Connection: keep-alive, " + ghp + "\r\n", RefusedBody},
		// The broker answers each Upgrade other than websocket with 501
		// before the fence runs.
		{"Upgrade: lab_fence_github\r\nConnection: Upgrade\r\n", "upgrade\n"},
	} {
		got := rawRoundtrip(t, b, anthropic, "GET /socket HTTP/1.1\r\nHost: api.anthropic.com\r\n"+tc.fields+"\r\n")
		if !strings.HasSuffix(got, tc.want) {
			t.Fatalf("%q: not the refusal: %q", tc.fields, got)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if got.Load() {
		t.Fatal("a refused request reached the origin")
	}
	strip, _ := os.ReadFile(b.Logs.StripPath)
	unknown, _ := os.ReadFile(b.Logs.UnknownPath)
	all := string(strip) + string(unknown)
	for _, live := range []string{"lab_fence_github", oat, ghp} {
		if strings.Contains(all, live) {
			t.Fatalf("the live value is in a row:\n%s", all)
		}
	}
	slots := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(all), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		if msg := alert.Summarize(m); strings.Contains(msg, "lab_fence_github") || strings.Contains(msg, "sk-ant-") || strings.Contains(msg, "ghp_") {
			t.Fatalf("the live value is in the alert %q", msg)
		}
		if m["cause"] != "live_in_connection" {
			continue
		}
		if m["alert"] != true || m["where"] != "header:Connection" {
			t.Fatalf("row %s", line)
		}
		slot, _ := m["slot"].(string)
		slots[slot] = true
	}
	for _, slot := range []string{"a1b2c3d4e5f67890", "b0b1b2b3b4b5b6b7", ""} {
		if !slots[slot] {
			t.Fatalf("no live_in_connection alert for slot %q:\n%s", slot, all)
		}
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

// The broker writes some rows before the fence runs: the target rules,
// the blocklist, the paranoid deny and a refused git push. A Host that
// holds a live value or a token-prefix match must not go into these rows
// either, because the alerter posts the host of a strip row to the
// webhook. The row names the SNI instead.
func TestLiveValueInHostStaysOutOfEarlyRows(t *testing.T) {
	akia := "AKIA" + strings.Repeat("Q", 16)
	for _, tc := range []struct {
		name, sni, host, dst, target, live, want, where string
		setup                                           func(*Broker)
	}{
		{name: "bad host", sni: "evil.example", host: "lab_fence_github@evil.example", live: "lab_fence_github", want: "evil.example", where: "target"},
		{name: "port mismatch", sni: "evil.example", host: akia + ".evil.example:8443", live: akia, want: "evil.example", where: "target"},
		{name: "blocklist", sni: "ok.example", host: akia + ".blocked.example", live: akia, want: "ok.example", where: "host",
			setup: func(b *Broker) { b.Blocked = blocklist.New("blocked.example") }},
		{name: "git push", sni: "github.com", host: akia + ".github.com", target: "/o/x.git/info/refs?service=git-receive-pack", live: akia, want: "github.com", where: "target",
			setup: func(b *Broker) { b.GitPush = gitPushList(t, "github.com o/r\n") }},
		{name: "paranoid", sni: "github.com", host: akia + ".evil.example", live: akia, want: "github.com", where: whereParanoid,
			setup: func(b *Broker) {
				pb := paranoidBroker(t)
				b.Paranoid, b.Forward = pb.Paranoid, pb.Forward
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := testBroker(t)
			dir := t.TempDir()
			b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
			var dialed atomic.Bool
			b.DialTLS = noDial(&dialed)
			if tc.setup != nil {
				tc.setup(b)
			}
			target := tc.target
			if target == "" {
				target = "/"
			}
			p := preamble.Preamble{SNI: tc.sni, OrigDst: netip.MustParseAddrPort("8.8.8.8:443")}
			_ = rawRoundtrip(t, b, p, "GET "+target+" HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
			strip, _ := os.ReadFile(b.Logs.StripPath)
			unknown, _ := os.ReadFile(b.Logs.UnknownPath)
			all := string(strip) + string(unknown)
			if strings.Contains(strings.ToLower(all), strings.ToLower(tc.live)) {
				t.Fatalf("the live value is in a row:\n%s", all)
			}
			found := false
			for _, line := range strings.Split(strings.TrimSpace(all), "\n") {
				var m map[string]any
				if err := json.Unmarshal([]byte(line), &m); err != nil {
					t.Fatalf("row %q: %v", line, err)
				}
				if msg := alert.Summarize(m); strings.Contains(strings.ToLower(msg), strings.ToLower(tc.live)) {
					t.Fatalf("the live value is in the alert %q", msg)
				}
				if m["where"] == tc.where && m["host"] == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s row with host %q:\n%s", tc.where, tc.want, all)
			}
		})
	}
}
