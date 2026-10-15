package alert

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// hookServer answers every POST with status and counts the bodies it saw.
func hookServer(t *testing.T, status *atomic.Int32) (*httptest.Server, *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func policyDir(t *testing.T, url string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(url+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A 500 from the webhook means that the operator never got the alert. So
// the post stays, and is retried, paced by the retry floor. The row itself
// is recorded locally (alert.last, the console line) and checkpointed
// immediately. A webhook that the agent can make refuse must not delay the record.
func TestDrainRetriesUndeliveredLine(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	srv, got := hookServer(t, &status)
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	line := "{\"ev\":\"strip\",\"rule\":\"anthropic\",\"where\":\"header\",\"host\":\"api.example\"}\n"
	if err := os.WriteFile(log, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	var out strings.Builder
	a := &Alerter{
		StripLog:   log,
		OffsetPath: filepath.Join(dir, "off"),
		LastPath:   filepath.Join(dir, "last"),
		PolicyDirs: []string{policyDir(t, srv.URL)},
		Stdout:     &out,
		Stderr:     io.Discard,
		Now:        func() time.Time { return now },
	}
	if err := a.Drain(false); err == nil {
		t.Fatal("Drain reported success after a 500")
	}
	if len(*got) != 1 {
		t.Fatalf("posted %d times, want 1", len(*got))
	}
	if !strings.Contains(out.String(), "STRIP anthropic in header -> api.example") {
		t.Fatalf("no console line while the webhook refused: %q", out.String())
	}
	if last, _ := os.ReadFile(a.LastPath); !strings.Contains(string(last), "api.example") {
		t.Fatalf("alert.last not written while the webhook refused: %q", last)
	}
	if off, _ := os.ReadFile(a.OffsetPath); !strings.HasPrefix(string(off), fmt.Sprint(len(line))+" ") {
		t.Fatalf("checkpoint held back by the webhook: %q", off)
	}
	status.Store(204)
	now = now.Add(time.Second)
	_ = a.Drain(false)
	if len(*got) != 1 {
		t.Fatalf("retried inside the retry floor: %d posts", len(*got))
	}
	now = now.Add(retryAfter)
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 || !strings.Contains((*got)[1], "api.example") {
		t.Fatalf("posts %q, want the line retried", *got)
	}
	if n := strings.Count(out.String(), "api.example"); n != 1 {
		t.Fatalf("the retry repeated the console line: %q", out.String())
	}
}

// The WG state file is the only record that the transition was announced.
// If the alerter writes it before the post, a failed post is never retried,
// and the operator never learns that the tunnel went down.
func TestWGOnceKeepsStateWhenPostFails(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	srv, got := hookServer(t, &status)
	dir := t.TempDir()
	last := filepath.Join(dir, "wg.last")
	a := &Alerter{
		LastPath:   last,
		PolicyDirs: []string{policyDir(t, srv.URL)},
		Stdout:     io.Discard,
		Stderr:     io.Discard,
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
	}
	if code := a.WGOnce("wg-does-not-exist", time.Minute); code == 0 {
		t.Fatal("WGOnce reported success after a failed post")
	}
	if len(*got) != 1 {
		t.Fatalf("posted %d times, want 1", len(*got))
	}
	if raw, err := os.ReadFile(last); err == nil && strings.TrimSpace(string(raw)) != "" {
		t.Fatalf("recorded %q as announced though the post failed", raw)
	}
}
