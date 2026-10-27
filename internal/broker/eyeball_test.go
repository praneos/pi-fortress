package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/eyeball"
	"pi-fortress/internal/preamble"
)

// The table maps two public ranges to documentation ASNs (RFC 5398). They
// are public because dest.Allowed refuses TEST-NET before the eyeball
// check. The test dialer never leaves the process.
func eyeTable(t *testing.T) *eyeball.Table {
	t.Helper()
	var b bytes.Buffer
	r1, _ := eyeball.ParseRange("1.1.1.0", "1.1.1.255", "64496")
	r2, _ := eyeball.ParseRange("8.8.8.0", "8.8.8.255", "64497")
	if err := eyeball.Write(&b, time.Now(), []eyeball.Range{r1, r2}); err != nil {
		t.Fatal(err)
	}
	tab, err := eyeball.Parse(&b)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func eyeAllow(t *testing.T, text string) *eyeball.Allow {
	t.Helper()
	a, _, err := eyeball.ParseAllow(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// eyeRows gives the eyeball rows of the strip log.
func eyeRows(t *testing.T, path string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, line := range strings.Split(stripRows(t, path), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if m["cause"] == string(CauseEyeball) {
			rows = append(rows, m)
		}
	}
	return rows
}

func wantEyeRow(t *testing.T, row map[string]any, where, host, dest, asn string, alert bool) {
	t.Helper()
	got, _ := row["alert"].(bool)
	if row["where"] != where || row["host"] != host || row["dest_ip"] != dest || row["kind"] != asn || got != alert ||
		row["ev"] != "substitution_refused" || row["rule"] != "refused:"+string(CauseEyeball) {
		t.Fatalf("row %v, want where=%s host=%s dest_ip=%s kind=%s alert=%v", row, where, host, dest, asn, alert)
	}
}

const eyeReq = "GET / HTTP/1.1\r\nHost: home.example\r\n\r\n"

// Audit mode: the broker dials the eyeball address and writes one row
// that alerts. The next connection to the same name and ASN writes a row
// that does not alert. A new name alerts again.
func TestEyeballAuditDialsAndAlertsOncePerName(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	r.b.Eyeball = eyeball.Static(eyeball.Audit, eyeTable(t), nil)
	for i := 0; i < 2; i++ {
		p := preamble.Preamble{SNI: "home.example", OrigDst: r.assign(t, "home.example"), Src: netip.MustParseAddrPort("10.20.0.5:5000")}
		if body := roundtrip(t, r.b, p, eyeReq); body != upstreamOK {
			t.Fatalf("body=%q", body)
		}
	}
	if d := r.dials(); len(d) != 2 || d[0].Addr() != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("dialed %v", d)
	}
	p := preamble.Preamble{SNI: "other.example", OrigDst: r.assign(t, "other.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	rows := eyeRows(t, r.strip)
	if len(rows) != 3 {
		t.Fatalf("rows %v", rows)
	}
	wantEyeRow(t, rows[0], "audit", "home.example", "1.1.1.1", "AS64496", true)
	wantEyeRow(t, rows[1], "audit", "home.example", "1.1.1.1", "AS64496", false)
	wantEyeRow(t, rows[2], "audit", "other.example", "1.1.1.1", "AS64496", true)
	if rows[0]["client_ip"] != "10.20.0.5" {
		t.Errorf("client_ip %v", rows[0]["client_ip"])
	}
}

// Refuse mode: no dial, the 502 of a resolve that found nothing
// dialable, and a row with where "resolve" that alerts.
func TestEyeballRefuseFakeIP(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1", "8.8.8.8")
	r.b.Eyeball = eyeball.Static(eyeball.Refuse, eyeTable(t), nil)
	p := preamble.Preamble{SNI: "home.example", OrigDst: r.assign(t, "home.example")}
	if body := roundtrip(t, r.b, p, eyeReq); body != "origin\n" {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != 0 {
		t.Fatalf("dialed %v", d)
	}
	rows := eyeRows(t, r.strip)
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	wantEyeRow(t, rows[0], "resolve", "home.example", "1.1.1.1", "AS64496", true)
	if strings.Contains(stripRows(t, r.strip), string(CauseFakeIPDestDenied)) {
		t.Error("the refusal also wrote a dest-denied row")
	}
}

// Refuse mode with a name that also has an address outside the table:
// the broker dials that address and writes no row.
func TestEyeballRefuseDialsTheOtherAddress(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1", "9.9.9.9")
	r.b.Eyeball = eyeball.Static(eyeball.Refuse, eyeTable(t), nil)
	p := preamble.Preamble{SNI: "mixed.example", OrigDst: r.assign(t, "mixed.example")}
	if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: mixed.example\r\n\r\n"); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	if d := r.dials(); len(d) != 1 || d[0].Addr() != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("dialed %v", d)
	}
	if rows := eyeRows(t, r.strip); len(rows) != 0 {
		t.Fatalf("rows %v", rows)
	}
}

// The allow list exempts a name (and the names below it) or an ASN.
func TestEyeballAllowListExempts(t *testing.T) {
	for _, tc := range []struct{ allow, name, answer string }{
		{"home.example\n", "nas.home.example", "1.1.1.1"},
		{"AS64497\n", "dns.example", "8.8.8.8"},
	} {
		r := newFakeRig(t, tc.answer)
		r.b.Eyeball = eyeball.Static(eyeball.Refuse, eyeTable(t), eyeAllow(t, tc.allow))
		p := preamble.Preamble{SNI: tc.name, OrigDst: r.assign(t, tc.name)}
		if body := roundtrip(t, r.b, p, "GET / HTTP/1.1\r\nHost: "+tc.name+"\r\n\r\n"); body != upstreamOK {
			t.Fatalf("%s: body=%q", tc.name, body)
		}
		if rows := eyeRows(t, r.strip); len(rows) != 0 {
			t.Fatalf("%s: rows %v", tc.name, rows)
		}
	}
}

// No table: the check fails open, also in refuse mode. The broker dials
// and writes no row.
func TestEyeballNoTableFailsOpen(t *testing.T) {
	r := newFakeRig(t, "1.1.1.1")
	var said []string
	c := &eyeball.Checker{
		Mode:      eyeball.Refuse,
		TablePath: filepath.Join(t.TempDir(), eyeball.TableFile),
		Logf:      func(f string, a ...any) { said = append(said, f) },
	}
	c.Reload()
	r.b.Eyeball = c
	p := preamble.Preamble{SNI: "home.example", OrigDst: r.assign(t, "home.example")}
	if body := roundtrip(t, r.b, p, eyeReq); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	if rows := eyeRows(t, r.strip); len(rows) != 0 || len(said) != 1 {
		t.Fatalf("rows %v, log %q", rows, said)
	}
}

// A connection to a real address (forward DNS) gets the same check on the
// address that the agent dialed. Refuse gives the body of the dest.Allowed
// refusal, so the agent cannot tell the two apart.
func TestEyeballForwardMode(t *testing.T) {
	real := netip.MustParseAddrPort("1.1.1.1:443")
	r := newFakeRig(t)
	r.b.FakeIP = nil
	r.b.Eyeball = eyeball.Static(eyeball.Audit, eyeTable(t), nil)
	p := preamble.Preamble{SNI: "Home.Example.", OrigDst: real}
	if body := roundtrip(t, r.b, p, eyeReq); body != upstreamOK {
		t.Fatalf("audit body=%q", body)
	}
	rows := eyeRows(t, r.strip)
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	wantEyeRow(t, rows[0], "audit", "home.example", "1.1.1.1", "AS64496", true)

	r = newFakeRig(t)
	r.b.FakeIP = nil
	r.b.Eyeball = eyeball.Static(eyeball.Refuse, eyeTable(t), nil)
	body, err := refusedAtPreamble(t, r.b, p)
	if body != "ssrf\n" || !errors.Is(err, ErrSSRF) || !strings.Contains(err.Error(), string(CauseEyeball)) {
		t.Fatalf("refuse: body=%q err=%v", body, err)
	}
	if d := r.dials(); len(d) != 0 {
		t.Fatalf("dialed %v", d)
	}
	rows = eyeRows(t, r.strip)
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	wantEyeRow(t, rows[0], "preamble", "home.example", "1.1.1.1", "AS64496", true)
}

// A segment with INSPECT=on is not the agent network. Its devices talk to
// home lines for good reasons, so the check does not run for it.
func TestEyeballSkipsFenceSegment(t *testing.T) {
	r := newFakeRig(t)
	r.b.FakeIP = nil
	r.b.AgentNet = netip.MustParsePrefix("10.20.0.0/24")
	r.b.FenceNets = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	r.b.Eyeball = eyeball.Static(eyeball.Refuse, eyeTable(t), nil)
	p := preamble.Preamble{SNI: "home.example", OrigDst: netip.MustParseAddrPort("1.1.1.1:443"), Src: netip.MustParseAddrPort("10.30.0.5:5000")}
	if body := roundtrip(t, r.b, p, eyeReq); body != upstreamOK {
		t.Fatalf("body=%q", body)
	}
	if rows := eyeRows(t, r.strip); len(rows) != 0 {
		t.Fatalf("rows %v", rows)
	}
	p.Src = netip.MustParseAddrPort("10.20.0.5:5000")
	if body, err := refusedAtPreamble(t, r.b, p); body != "ssrf\n" || !errors.Is(err, ErrSSRF) {
		t.Fatalf("agent network: body=%q err=%v", body, err)
	}
}

// The debounce set of the alerts never grows past its bound.
func TestEyeballAlertMemoryBounded(t *testing.T) {
	b := &Broker{}
	for i := 0; i < 3*eyeballAlertKeys; i++ {
		if !b.eyeballAlert(fmt.Sprintf("n%d.example", i), 64496) {
			t.Fatalf("name %d did not alert", i)
		}
		if len(b.eyeSaid) > eyeballAlertKeys {
			t.Fatalf("set has %d keys", len(b.eyeSaid))
		}
	}
}
