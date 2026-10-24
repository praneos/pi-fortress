package alert

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCapAfterKeepsWhatArrivedDuringTheSummary(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cur := webhookCap{start: now.Add(-time.Hour), posted: 9, keyPosted: 4, suppressed: 5, by: map[string]int{"a": 3, "b": 1}}
	snap := webhookCap{suppressed: 2, by: map[string]int{"a": 1, "b": 1}}
	want := webhookCap{start: now, posted: 1, suppressed: 3, by: map[string]int{"a": 2}}
	if got := cur.after(snap, now); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got := cur.after(cur, now); got.by != nil || got.suppressed != 0 || got.posted != 1 {
		t.Fatalf("got %+v", got)
	}
}

// A row that the cap holds back while the summary post is out belongs to
// the next summary, with its kind. The snapshot of the window must not
// share the count map with the live window, or the kind is lost.
func TestSummaryKeepsKindsHeldBackDuringThePost(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, string(b))
		mu.Unlock()
		if strings.Contains(string(b), "suppressed in the last hour") {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)

	now := time.Unix(1700000000, 0)
	a := &Alerter{
		CapPosts: 1,
		LastPath: filepath.Join(t.TempDir(), "last"),
		Client:   srv.Client(),
		Stdout:   io.Discard,
		Stderr:   io.Discard,
		Now:      func() time.Time { return now },
	}
	url := srv.URL + "/topic"
	row := func(host string) {
		t.Helper()
		if err := a.handle(`{"ev":"strip","rule":"anthropic","where":"header","host":"`+host+`"}`, url); err != nil {
			t.Fatal(err)
		}
	}
	row("h0.example")
	row("h1.example")
	if err := a.flush(url); err != nil {
		t.Fatal(err)
	}

	now = now.Add(capWindow + time.Second)
	done := make(chan error, 1)
	go func() { done <- a.flush(url) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the summary never went out")
	}
	row("h2.example")
	free()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	got := a.cap.by["strip"]
	a.mu.Unlock()
	if got != 1 {
		t.Fatalf("the next window holds strip %d, want 1", got)
	}

	now = now.Add(capWindow + time.Second)
	if err := a.flush(url); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := posts[len(posts)-1]
	mu.Unlock()
	if !strings.Contains(last, "1 alert suppressed in the last hour (strip 1)") {
		t.Fatalf("next summary %q", last)
	}
}
