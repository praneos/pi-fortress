package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadURL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte("# comment\n\nhttps://ntfy.sh/topic-x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := LoadURL([]string{dir}); got != "https://ntfy.sh/topic-x" {
		t.Fatal(got)
	}
}

// A webhook URL is the credential: whoever holds the ntfy topic or the
// Slack path can post to the channel of the operator. http.Client.Do
// reports each transport failure as a *url.Error that carries the full
// request URL. Before this test, an ordinary timeout on a flaky link wrote
// that credential to stderr. vm/pi/alert.service leaves stderr pointed at
// journald, and from there the credential went into each diagnostic export.
func TestWebhookErrorNeverNamesTheURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := ts.Client()
	dead := ts.URL
	ts.Close()
	var errbuf strings.Builder
	a := &Alerter{Client: client, Stderr: &errbuf}
	a.PostMessage(dead+"/tk_TOPICSECRET?auth=tk_QUERYSECRET", "STRIP github_classic in header -> example.com")
	got := errbuf.String()
	if got == "" {
		t.Fatal("a failed webhook post said nothing at all")
	}
	for _, secret := range []string{"tk_TOPICSECRET", "tk_QUERYSECRET"} {
		if strings.Contains(got, secret) {
			t.Fatalf("webhook credential copied to the journal: %q", got)
		}
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("no endpoint to diagnose from: %q", got)
	}
}

// A 429 or a 500 means that the alert never reached the operator. To treat
// it as success is worse than a transport error, because a transport error
// is at least reported.
func TestWebhookNon2xxIsReported(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)
	var errbuf strings.Builder
	a := &Alerter{Client: ts.Client(), Stderr: &errbuf}
	a.PostMessage(ts.URL+"/tk_TOPICSECRET?auth=tk_QUERYSECRET", "STRIP github_classic in header -> example.com")
	got := errbuf.String()
	if !strings.Contains(got, "429") {
		t.Fatalf("an undelivered alert was recorded as sent: %q", got)
	}
	for _, secret := range []string{"tk_TOPICSECRET", "tk_QUERYSECRET"} {
		if strings.Contains(got, secret) {
			t.Fatalf("webhook credential copied to the journal: %q", got)
		}
	}
}

// docs/fence.md:40-41: each canary refusal alerts "without spending the
// once-per-cause alert of other kinds". The broker writes both rows with
// no rule, and with the same host and where. Before the threat was in the
// debounce key, the ordinary refusal claimed the slot, and the canary went
// quiet. The canary is the one alert that the fence exists to raise.
func TestCanarySurvivesAnOrdinaryRefusalOnTheSameHost(t *testing.T) {
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	var mu sync.Mutex
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(ts.Close)
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(ts.URL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ordinary := `{"ev":"substitution_refused","host":"evil.example","where":"header","cause":"slot_unknown","slot":"d0","kind":"OPENAI","alert":true}`
	canary := `{"ev":"substitution_refused","host":"evil.example","where":"header","cause":"kind_not_allowed_for_sni","slot":"d0","kind":"CANARY","alert":true,"threat":"canary"}`
	if err := os.WriteFile(strip, []byte(ordinary+"\n"+canary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := &Alerter{
		StripLog:    strip,
		OffsetPath:  filepath.Join(dir, "alert.offset"),
		LastPath:    filepath.Join(dir, "alert.last"),
		PolicyDirs:  []string{dir},
		Client:      ts.Client(),
		DebounceFor: 10 * time.Second,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("posted %d of 2 alerts: %q", len(bodies), bodies)
	}
	if !strings.HasPrefix(bodies[1], "CANARY ") {
		t.Fatalf("second post was not the canary: %q", bodies[1])
	}
}

func TestWebhookNtfyAndSlack(t *testing.T) {
	var mu sync.Mutex
	var got []struct {
		ct, body, ua, title string
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, struct{ ct, body, ua, title string }{
			ct: r.Header.Get("Content-Type"), body: string(b), ua: r.Header.Get("User-Agent"), title: r.Header.Get("Title"),
		})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(ts.Close)
	a := &Alerter{Client: ts.Client(), Stderr: io.Discard}
	ev := map[string]any{"rule": "github_classic", "where": "header", "host": "example.com", "token": "sk-ant-oat01-LEAK"}
	a.PostWebhook(ts.URL+"/topic", ev)
	a.PostWebhook(ts.URL+"/hooks.slack.com/services/x", ev)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("%d", len(got))
	}
	for i, want := range []struct{ ct, body string }{
		{"text/plain", "STRIP github_classic"},
		{"application/json", `"text"`},
	} {
		if got[i].ct != want.ct || !strings.Contains(got[i].body, want.body) || strings.Contains(got[i].body, "sk-ant-") {
			t.Fatalf("%+v", got[i])
		}
	}
	if got[0].ua != "pi-fortress-alert" || got[0].title != "pi-fortress" {
		t.Fatalf("%+v", got[0])
	}
}

func TestDrainShowAndDebounceWebhook(t *testing.T) {
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	var n int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(204)
	}))
	t.Cleanup(ts.Close)
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(ts.URL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	line := `{"host":"example.com","rule":"github_classic","t":"2026-01-01T00:00:00Z","where":"header"}` + "\n"
	if err := os.WriteFile(strip, []byte(line+line), 0644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	a := &Alerter{
		StripLog:    strip,
		OffsetPath:  filepath.Join(dir, "alert.offset"),
		LastPath:    filepath.Join(dir, "alert.last"),
		PolicyDirs:  []string{dir},
		Client:      ts.Client(),
		DebounceFor: 10 * time.Second,
		Stdout:      &out,
		Stderr:      io.Discard,
	}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("webhook count %d want 1", n)
	}
	if !strings.Contains(out.String(), "STRIP github_classic in header -> example.com") {
		t.Fatal(out.String())
	}
	last, err := os.ReadFile(a.LastPath)
	if err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	if err := json.Unmarshal(last, &ev); err != nil {
		t.Fatal(err)
	}
	if ev["rule"] != "github_classic" {
		t.Fatal(string(last))
	}
	var shown strings.Builder
	a.Stdout = &shown
	if a.Show() != 0 || !strings.Contains(shown.String(), "github_classic") {
		t.Fatal(shown.String())
	}
}

// syncBuf exists because Watch runs on its own goroutine, and the test
// polls what Watch has written so far. A bare strings.Builder shared that
// way is a data race. -race reports it as a failure of the test that runs
// at that time.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestWatchSummarize(t *testing.T) {
	dir := t.TempDir()
	strip := filepath.Join(dir, "strip.jsonl")
	if err := os.WriteFile(strip, nil, 0644); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	a := &Alerter{
		StripLog: strip,
		Stdout:   &out,
		Stderr:   io.Discard,
		Poll:     20 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- a.Watch(ctx) }()
	time.Sleep(40 * time.Millisecond)
	f, err := os.OpenFile(strip, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"rule":"github_classic","where":"header","host":"example.com"}` + "\n")
	_ = f.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "STRIP github_classic in header -> example.com") {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal(out.String())
}

func TestSummarizeCanary(t *testing.T) {
	got := Summarize(map[string]any{"ev": "substitution_refused", "cause": "kind_not_allowed_for_sni", "slot": "d0", "kind": "CANARY", "host": "evil.example", "alert": true, "threat": "canary"})
	if got != "CANARY REFUSED kind_not_allowed_for_sni slot d0 (CANARY) -> evil.example" {
		t.Fatal(got)
	}
	got = Summarize(map[string]any{"rule": "secret:d0d1d2d3d4d5d6d7_CANARY", "where": "body", "host": "evil.example", "threat": "canary"})
	if got != "CANARY STRIP secret:d0d1d2d3d4d5d6d7_CANARY in body -> evil.example" {
		t.Fatal(got)
	}
}

// The notice file of observe is a second log with its own checkpoint. A row
// there posts, reads as what it is, and does not change the strip offset.
func TestNoticeLogPostsBesideTheStripLog(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(ts.Close)
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(ts.URL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	notice := filepath.Join(dir, "notice.jsonl")
	var out syncBuf
	a := &Alerter{
		StripLog: filepath.Join(dir, "strip.jsonl"), OffsetPath: filepath.Join(dir, "alert.offset"),
		NoticeLog: notice, NoticeOffsetPath: filepath.Join(dir, "notice.offset"),
		LastPath: filepath.Join(dir, "alert.last"), PolicyDirs: []string{dir}, Client: ts.Client(),
		DebounceFor: 10 * time.Second, Poll: 10 * time.Millisecond, Stdout: &out, Stderr: io.Discard,
	}
	// Run starts each tail from the end of its log, unless a checkpoint tells
	// it otherwise. So the test writes the row before Run, with a checkpoint at
	// its start. Then no sleep has to guess when the first pass attached.
	row := `{"t":"2026-09-21T00:00:00Z","threat":"volume","rule":"observe","where":"agent","client_ip":"10.77.0.10","host":"gist.github.com (140.82.113.4)","detail":"612 MB in 1h"}` + "\n"
	if err := os.WriteFile(notice, []byte(row), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.NoticeOffsetPath, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(bodies)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), bodies...)
	mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "612 MB in 1h") {
		t.Fatalf("webhook got %q", got)
	}
	want := "BULK UPLOAD 10.77.0.10 (agent) -> gist.github.com (140.82.113.4): 612 MB in 1h"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("stdout %q, want %q", out.String(), want)
	}
}

// A query name refused because it carries a key tells what was refused and
// where it went. It never gives the name: observe never has more than the zone.
func TestSummarizeKeyInDNSName(t *testing.T) {
	got := Summarize(map[string]any{
		"threat": "dns_key", "where": "agent", "client_ip": "10.77.0.10",
		"host": "evil.example", "detail": "refused, rule anthropic_oat",
	})
	if want := "KEY IN A DNS NAME 10.77.0.10 (agent) -> evil.example: refused, rule anthropic_oat"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}
