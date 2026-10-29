package alert

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The row of the uplink watchdog reads as what it is: the device, the
// connection, the down time, and who brought it back.
func TestSummarizeUplinkBack(t *testing.T) {
	for _, c := range []struct {
		row  map[string]any
		want string
	}{
		{map[string]any{"threat": "uplink", "rule": "uplink_back", "where": "wlan0", "host": "home", "down_s": float64(754), "tries": float64(3)},
			"UPLINK BACK wlan0 (home) after 12m34s down; the uplink watchdog ran nmcli connection up 3 times"},
		{map[string]any{"threat": "uplink", "where": "wlan0", "host": "home", "down_s": float64(60), "tries": float64(1)},
			"UPLINK BACK wlan0 (home) after 1m0s down; the uplink watchdog ran nmcli connection up 1 time"},
		{map[string]any{"threat": "uplink", "where": "eth1", "host": "wired", "down_s": float64(90), "tries": float64(0)},
			"UPLINK BACK eth1 (wired) after 1m30s down; NetworkManager brought it back"},
		// A name with a control rune does not forge a second line.
		{map[string]any{"threat": "uplink", "where": "wlan0", "host": "a\nb"},
			"UPLINK BACK wlan0 (a?b) after ? down; NetworkManager brought it back"},
	} {
		if got := Summarize(c.row); got != c.want {
			t.Errorf("Summarize(%v) = %q, want %q", c.row, got, c.want)
		}
	}
}

// The event file of the uplink watchdog is a third log with its own
// checkpoint. Its row goes through the queue and posts one time.
func TestUplinkLogPostsBesideTheOtherLogs(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(ts.URL+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "uplink", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(events), 0o755); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	a := &Alerter{
		StripLog: filepath.Join(dir, "strip.jsonl"), OffsetPath: filepath.Join(dir, "alert.offset"),
		NoticeLog: filepath.Join(dir, "notice.jsonl"), NoticeOffsetPath: filepath.Join(dir, "notice.offset"),
		UplinkLog: events, UplinkOffsetPath: filepath.Join(dir, "alert", "uplink.offset"),
		LastPath: filepath.Join(dir, "alert.last"), PolicyDirs: []string{dir}, Client: ts.Client(),
		DebounceFor: 10 * time.Second, Poll: 10 * time.Millisecond, Stdout: &out, Stderr: io.Discard,
	}
	row := `{"ts":"2026-10-01T12:01:00Z","threat":"uplink","rule":"uplink_back","where":"wlan0","host":"home","uuid":"0b5e6b84-3c1d-4f7e-9a51-2a3f1c9d7e11","down_s":60,"tries":1}` + "\n"
	if err := os.WriteFile(events, []byte(row), 0o644); err != nil {
		t.Fatal(err)
	}
	// The checkpoint is at the start of the row, so that Run reads it.
	if err := os.MkdirAll(filepath.Dir(a.UplinkOffsetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.UplinkOffsetPath, []byte("0\n"), 0o644); err != nil {
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
	// More passes: the row must not post a second time.
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), bodies...)
	mu.Unlock()
	want := "UPLINK BACK wlan0 (home) after 1m0s down; the uplink watchdog ran nmcli connection up 1 time"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("webhook got %q, want one post %q", got, want)
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("stdout %q, want %q", out.String(), want)
	}
	if raw, err := os.ReadFile(a.UplinkOffsetPath); err != nil || !strings.HasPrefix(strings.TrimSpace(string(raw)), strconv.Itoa(len(row))+" ") {
		t.Fatalf("uplink checkpoint %q (%v), want past the row", raw, err)
	}
}
