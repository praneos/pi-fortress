package jsonl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func lines(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		out = append(out, ev)
	}
	return out
}

// clock is a Writer clock that a test moves manually.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// TestUnknownRowClipped is the 64 KiB unknown row: forty header names of
// a kilobyte each, and a Host of a kilobyte. Each free-text field has a
// limit. Thus the row is a few KiB, for all request shapes.
func TestUnknownRowClipped(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl")}
	long := strings.Repeat("h", 1000)
	names := make([]string, 50)
	for i := range names {
		names[i] = long
	}
	ev := Unknown{Host: long, SNI: long, Method: long, Path: long, HTTPVersion: long, HeaderNames: names, UA: long, ContentType: long, AuthScheme: long, CookieNames: names}
	if err := w.Unknown(ev); err != nil {
		t.Fatal(err)
	}
	if names[0] != long {
		t.Fatal("clipping wrote through to the caller's slice")
	}
	raw, _ := os.ReadFile(w.UnknownPath)
	if len(raw) > 8<<10 {
		t.Fatalf("row is %d bytes", len(raw))
	}
	var got Unknown
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.HeaderNames) != maxNames || len(got.HeaderNames[0]) != maxNameBytes {
		t.Fatalf("header names: %d of %d bytes", len(got.HeaderNames), len(got.HeaderNames[0]))
	}
	if len(got.Host) != maxHost || len(got.SNI) != maxHost || len(got.Method) != 32 || len(got.CookieNames) != maxCookies {
		t.Fatalf("host=%d sni=%d method=%d cookies=%d", len(got.Host), len(got.SNI), len(got.Method), len(got.CookieNames))
	}
}

// TestStripRowClipped: a rule can have the Content-Encoding of the origin.
func TestStripRowClipped(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	if err := w.Strip(Strip{Host: strings.Repeat("h", 9000), Where: "response", Rule: "encoded:" + strings.Repeat("x", 9000)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Refused(Refused{Host: strings.Repeat("h", 9000), Repo: strings.Repeat("r", 9000), Cause: "c"}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range lines(t, w.StripPath) {
		if len(ev["host"].(string)) != maxHost || len(ev["rule"].(string)) > maxRule+len("refused:") {
			t.Fatalf("unclipped: host %d rule %d", len(ev["host"].(string)), len(ev["rule"].(string)))
		}
	}
}

// TestUnknownRateLimitedPerClientAndHost: a burst to one host writes the
// burst and no more. A different host of the same client has no change.
// The next row after the window has one suppressed summary.
func TestUnknownRateLimitedPerClientAndHost(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	w := &Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl"), Now: c.now}
	for range unknownPairBurst + 80 {
		_ = w.Unknown(Unknown{ClientIP: "10.77.0.10", Host: "loop.example"})
	}
	_ = w.Unknown(Unknown{ClientIP: "10.77.0.10", Host: "other.example"})
	if n := len(lines(t, w.UnknownPath)); n != unknownPairBurst+1 {
		t.Fatalf("%d rows, want %d", n, unknownPairBurst+1)
	}
	c.t = c.t.Add(unknownWindow + time.Second)
	_ = w.Unknown(Unknown{ClientIP: "10.77.0.10", Host: "loop.example"})
	rows := lines(t, w.UnknownPath)
	var sum map[string]any
	for _, ev := range rows[unknownPairBurst+1:] {
		if ev["where"] == suppressedWhere {
			sum = ev
		}
	}
	if sum == nil || sum["host"] != "loop.example" || sum["client_ip"] != "10.77.0.10" || sum["suppressed"] != float64(80) {
		t.Fatalf("summary %v in %v", sum, rows[unknownPairBurst+1:])
	}
	if last := rows[len(rows)-1]; last["where"] != "http" {
		t.Fatalf("the row after the window was not written: %v", last)
	}
}

// TestUnknownRateLimitedPerClient is the loop over made-up hostnames.
// Each hostname gets a new bucket for that host. The bucket of the
// client limits the loop.
func TestUnknownRateLimitedPerClient(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	w := &Writer{UnknownPath: filepath.Join(dir, "unknown.jsonl"), Now: c.now}
	for i := range unknownSrcBurst + 100 {
		_ = w.Unknown(Unknown{ClientIP: "10.77.0.10", Host: strings.Repeat("a", i%50) + ".example" + string(rune('a'+i%26)) + strings.Repeat("b", i/50)})
	}
	if n := len(lines(t, w.UnknownPath)); n != unknownSrcBurst {
		t.Fatalf("%d rows, want %d", n, unknownSrcBurst)
	}
	c.t = c.t.Add(unknownWindow + time.Second)
	_ = w.Unknown(Unknown{ClientIP: "10.77.0.10", Host: "x.example"})
	var found bool
	for _, ev := range lines(t, w.UnknownPath) {
		if ev["where"] == suppressedWhere && ev["host"] == "*" && ev["suppressed"] == float64(100) {
			found = true
		}
	}
	if !found {
		t.Fatal("no per-client summary row")
	}
}

// TestCeilingAcrossRotation: past the ceiling, the writer drops and tells
// this one time. After logrotate makes space, the writer starts again
// automatically. This applies to the method of vm/pi/logrotate.conf
// (rename, then a new file) and to the copytruncate method.
func TestCeilingAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "strip.jsonl")
	w := &Writer{StripPath: path, MaxBytes: 2000}
	row := Strip{Host: "example.com", Where: "header", Rule: "github_classic"}
	fill := func() int {
		t.Helper()
		dropped := 0
		for range 100 {
			if err := w.Strip(row); errors.Is(err, ErrFull) {
				dropped++
			} else if err != nil {
				t.Fatal(err)
			}
		}
		return dropped
	}
	dropped := fill()
	if dropped == 0 {
		t.Fatal("nothing was dropped at the ceiling")
	}
	st, _ := os.Stat(path)
	if st.Size() > 2000+512 {
		t.Fatalf("file grew to %d past a 2000-byte ceiling", st.Size())
	}
	full := 0
	for _, ev := range lines(t, path) {
		if ev["rule"] == "log_full" {
			full++
		}
	}
	if full != 1 {
		t.Fatalf("%d log_full rows, want exactly 1", full)
	}
	for _, rotate := range []struct {
		name string
		do   func() error
	}{
		{"rename+create", func() error { return os.Rename(path, path+".1") }},
		{"copytruncate", func() error { return os.Truncate(path, 0) }},
	} {
		if err := rotate.do(); err != nil {
			t.Fatal(err)
		}
		if err := w.Strip(row); err != nil {
			t.Fatalf("%s: %v", rotate.name, err)
		}
		got := lines(t, path)
		if len(got) != 2 || got[0]["rule"] != "log_resumed" || got[0]["count"] != float64(dropped) || got[1]["rule"] != "github_classic" {
			t.Fatalf("%s: after rotation %v, want log_resumed counting %d then the row", rotate.name, got, dropped)
		}
		dropped = fill()
	}
}

// fillStrip writes ordinary strips until the ceiling refuses one.
func fillStrip(t *testing.T, w *Writer) {
	t.Helper()
	for i := 0; ; i++ {
		err := w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic", ClientIP: "10.77.0." + strconv.Itoa(i%200)})
		if errors.Is(err, ErrFull) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// An agent could fill strip.jsonl to its ceiling in one rotation window.
// Then the code dropped all rows after that, also the canary and the
// refusals that the broker marked for the webhook. The code writes
// those past the ceiling into their own reserve. The reserve has a
// limit, so it is also not a path around the ceiling.
func TestCanaryAndAlertRowsPassTheCeiling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip.jsonl")
	w := &Writer{StripPath: path, MaxBytes: 2000}
	fillStrip(t, w)
	if err := w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic"}); !errors.Is(err, ErrFull) {
		t.Fatalf("an ordinary strip past the ceiling: %v", err)
	}
	if err := w.Strip(Strip{Host: "canary.example", Where: "header", Rule: "challenge", Threat: "canary"}); err != nil {
		t.Fatalf("canary strip: %v", err)
	}
	if err := w.Refused(Refused{Host: "api.example", Cause: "sealed", Alert: true}); err != nil {
		t.Fatalf("alert refusal: %v", err)
	}
	if err := w.Refused(Refused{Host: "api.example", Cause: "sealed"}); !errors.Is(err, ErrFull) {
		t.Fatalf("an unmarked refusal past the ceiling: %v", err)
	}
	var canary, alert bool
	for _, ev := range lines(t, path) {
		canary = canary || ev["threat"] == "canary"
		alert = alert || ev["alert"] == true
	}
	if !canary || !alert {
		t.Fatalf("canary %v alert %v in the file", canary, alert)
	}
	var err error
	for range 10000 {
		if err = w.Strip(Strip{Host: "canary.example", Where: "header", Rule: "challenge", Threat: "canary"}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrFull) {
		t.Fatalf("the reserve never filled: %v", err)
	}
	if st, _ := os.Stat(path); st.Size() > 2000+reserveBytes(2000)+512 {
		t.Fatalf("file grew to %d past a 2000-byte ceiling and its reserve", st.Size())
	}
}

// The budget of the client limits the strips of one agent, as it limits
// its unknown rows. A summary tells what the code dropped. A different
// client has no change. The code still writes a canary from the
// throttled client.
func TestStripRowsRateLimitedPerClient(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	w := &Writer{StripPath: filepath.Join(t.TempDir(), "strip.jsonl"), Now: c.now}
	for range stripSrcBurst + 100 {
		_ = w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic", ClientIP: "10.77.0.10"})
	}
	_ = w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic", ClientIP: "10.77.0.11"})
	_ = w.Strip(Strip{Host: "canary.example", Where: "header", Rule: "challenge", ClientIP: "10.77.0.10", Threat: "canary"})
	_ = w.Refused(Refused{Host: "api.example", Cause: "sealed", ClientIP: "10.77.0.10", Alert: true})
	_ = w.Refused(Refused{Host: "api.example", Cause: "sealed", ClientIP: "10.77.0.10"})
	if n := len(lines(t, w.StripPath)); n != stripSrcBurst+3 {
		t.Fatalf("%d rows, want %d", n, stripSrcBurst+3)
	}
	c.t = c.t.Add(unknownWindow + time.Second)
	_ = w.Strip(Strip{Host: "example.com", Where: "header", Rule: "github_classic", ClientIP: "10.77.0.10"})
	var sum map[string]any
	for _, ev := range lines(t, w.StripPath) {
		if ev["ev"] == stripSuppressedEv {
			sum = ev
		}
	}
	if sum == nil || sum["client_ip"] != "10.77.0.10" || sum["count"] != float64(101) {
		t.Fatalf("summary %v", sum)
	}
}
