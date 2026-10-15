package broker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
	"pi-fortress/internal/secrets"
)

func TestStripJSONL(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		return nil, errors.New("no dial")
	}
	p := preamble.Preamble{
		SNI:     "example.com",
		OrigDst: netip.MustParseAddrPort("93.184.216.34:443"),
	}
	drive(t, b, p, "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer ghp_"+strings.Repeat("A", 36)+"\r\n\r\n")
	raw, err := os.ReadFile(b.Logs.StripPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rule":"github_classic"`) || !strings.Contains(string(raw), `"where":"header"`) {
		t.Fatal(string(raw))
	}
}

// The row keeps shape (names, sizes, methods). It carries no hash of a
// header or a body and no TLS client fingerprint, not even as an empty
// string: the keys are absent.
func TestUnknownJSONLShapeOnly(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		return nil, errors.New("no dial")
	}
	p := preamble.Preamble{
		SNI:     "example.com",
		OrigDst: netip.MustParseAddrPort("93.184.216.34:443"),
	}
	drive(t, b, p, "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	raw, err := os.ReadFile(b.Logs.UnknownPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"ja3"`, `"ja3n"`, `"ja4"`, `"tlsh"`, `"hash_ver"`, `"hdr_sha256"`, `"body_sha256"`} {
		if strings.Contains(s, want) {
			t.Fatalf("row carries %s:\n%s", want, s)
		}
	}
	if !strings.Contains(s, `"body_len":2`) || !strings.Contains(s, `"method":"POST"`) || !strings.Contains(s, `"src":"split"`) {
		t.Fatalf("shape lost:\n%s", s)
	}
}

func TestAllowedNoUnknown(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	b.AllowHosts = map[string]struct{}{"github.com": {}}
	b.DialTLS = func(ctx context.Context, dst netip.AddrPort, sni string) (net.Conn, error) {
		return nil, errors.New("no dial")
	}
	p := preamble.Preamble{
		SNI:     "github.com",
		OrigDst: netip.MustParseAddrPort("140.82.112.3:443"),
	}
	drive(t, b, p, "GET / HTTP/1.1\r\nHost: github.com\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n")
	if _, err := os.Stat(b.Logs.UnknownPath); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(b.Logs.UnknownPath)
		t.Fatalf("unexpected unknown %s", raw)
	}
}

func TestDisabledSlotNotInjectedAndUseLogged(t *testing.T) {
	b, path := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	raw := "GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"
	if got := roundtrip(t, b, p, raw); !strings.Contains(got, "lab_fence_github") {
		t.Fatal(got)
	}
	roundtrip(t, b, p, raw)
	use, _ := os.ReadFile(b.Logs.UsePath)
	if strings.Count(string(use), "\n") != 1 || !strings.Contains(string(use), `"slot":"a1b2c3d4e5f67890"`) || !strings.Contains(string(use), `"host":"pf-core-echo.test"`) {
		t.Fatalf("use log:\n%s", use)
	}
	if err := secrets.Open(path).Disable("a1b2c3d4e5f67890"); err != nil {
		t.Fatal(err)
	}
	got := roundtrip(t, b, p, raw)
	if strings.Contains(got, "lab_fence_github") || strings.Contains(got, "pf_a1b2c3d4e5f67890_GITHUB_TOKEN") {
		t.Fatal(got)
	}
	if !strings.Contains(got, RefusedBody) {
		t.Fatalf("a disabled slot must refuse, not forward:\n%s", got)
	}
	strip, _ := os.ReadFile(b.Logs.StripPath)
	for _, want := range []string{`"ev":"substitution_refused"`, `"cause":"slot_disabled"`, `"slot":"a1b2c3d4e5f67890"`, `"kind":"GITHUB_TOKEN"`, `"where":"header"`} {
		if !strings.Contains(string(strip), want) {
			t.Fatalf("strip log missing %s:\n%s", want, strip)
		}
	}
	if n := strings.Count(string(strip), `"alert":true`); n != 1 {
		t.Fatalf("a disabled slot must alert once and then stay quiet, got %d:\n%s", n, strip)
	}
	if use2, _ := os.ReadFile(b.Logs.UsePath); string(use2) != string(use) {
		t.Fatal("disabled slot logged as used")
	}
}

// The fence refuses a placeholder in a body, even of the host's own kind.
// This alerts and leaves no use row. The fence substitutes the same
// placeholder in a header and leaves exactly one use row.
func TestSubstitutionLogsUse(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl"), UsePath: filepath.Join(dir, "use.jsonl")}
	p := preamble.Preamble{SNI: "pf-core-echo.test", OrigDst: netip.MustParseAddrPort("192.0.2.2:443")}
	post := func(hdr, body string) string {
		return "POST / HTTP/1.1\r\nHost: pf-core-echo.test\r\n" + hdr + "Content-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	ph := "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"
	got := roundtrip(t, b, p, post("", `{"token":"`+ph+`"}`))
	if !strings.Contains(got, RefusedBody) {
		t.Fatalf("a placeholder in the body must refuse:\n%s", got)
	}
	if strip, _ := os.ReadFile(b.Logs.StripPath); !strings.Contains(string(strip), `"cause":"placeholder_outside_header"`) || !strings.Contains(string(strip), `"alert":true`) {
		t.Fatalf("the body refusal was not logged as an alert:\n%s", strip)
	}
	if use, _ := os.ReadFile(b.Logs.UsePath); len(use) != 0 {
		t.Fatalf("a refused request left a use row:\n%s", use)
	}
	roundtrip(t, b, p, post("Authorization: Bearer "+ph+"\r\n", `{}`))
	use, _ := os.ReadFile(b.Logs.UsePath)
	if strings.Count(string(use), "\n") != 1 || !strings.Contains(string(use), `"slot":"a1b2c3d4e5f67890"`) || !strings.Contains(string(use), `"host":"pf-core-echo.test"`) {
		t.Fatalf("a placeholder substituted in a header left no use row:\n%s", use)
	}
}
