package broker

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

// sendRefused gives Handle one preamble with a refusal cause, as the engine
// sends it, and nothing after it.
func sendRefused(t *testing.T, b *Broker, p preamble.Preamble) error {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	errc := make(chan error, 1)
	go func() { errc <- b.Handle(context.Background(), c2) }()
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	if err := preamble.Encode(c1, &p); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Handle did not return after a refused preamble")
	}
	return nil
}

// A name that the engine refused because the blocklist has it gets one
// strip.jsonl row. The row does not alert: the fence stopped the
// connection. The broker writes nothing for a name that its own list does
// not have, for a cause that it does not know, or for a source that it
// does not serve.
func TestEngineSNIBlockedWritesARowThatDoesNotAlert(t *testing.T) {
	b, _ := testBroker(t)
	b.Blocked = blocklist.New("phish.example")
	b.AgentNet = netip.MustParsePrefix("10.77.0.0/24")
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl")}
	base := preamble.Preamble{
		ConnID:  "c1",
		Src:     netip.MustParseAddrPort("10.77.0.10:40000"),
		OrigDst: netip.MustParseAddrPort("192.0.2.1:443"),
		SNI:     "login.phish.example",
		Refused: preamble.RefusedSNIBlocked,
	}
	if err := sendRefused(t, b, base); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	raw := strings.TrimSpace(stripRows(t, b.Logs.StripPath))
	if strings.Count(raw, "\n") != 0 || raw == "" {
		t.Fatalf("want one row, got %q", raw)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(raw), &row); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ev": "substitution_refused", "cause": "sni_blocked", "rule": "refused:sni_blocked",
		"host": "login.phish.example", "sni": "login.phish.example", "where": "sni",
		"client_ip": "10.77.0.10", "threat": "sni_blocked",
	}
	for k, v := range want {
		if row[k] != v {
			t.Errorf("%s = %v, want %v", k, row[k], v)
		}
	}
	if _, ok := row["alert"]; ok {
		t.Errorf("row has alert: %s", raw)
	}

	for name, p := range map[string]preamble.Preamble{
		"name not on the list": func() preamble.Preamble { p := base; p.SNI = "example.com"; return p }(),
		"unknown cause":        func() preamble.Preamble { p := base; p.Refused = "made_up"; return p }(),
		"source not served":    func() preamble.Preamble { p := base; p.Src = netip.MustParseAddrPort("192.168.1.5:40000"); return p }(),
	} {
		if err := sendRefused(t, b, p); err == nil {
			t.Errorf("%s: Handle gave no error", name)
		}
		if got := strings.TrimSpace(stripRows(t, b.Logs.StripPath)); got != raw {
			t.Fatalf("%s: a row was written: %q", name, got)
		}
	}
}
