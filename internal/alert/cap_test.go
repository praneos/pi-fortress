package alert

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capRig is an Alerter on a strip log, a webhook that records each body
// under a mutex, and a clock that the test moves.
type capRig struct {
	a      *Alerter
	log    string
	now    time.Time
	status atomic.Int32
	mu     sync.Mutex
	posts  []string
	out    bytes.Buffer
}

func newCapRig(t *testing.T) *capRig {
	t.Helper()
	r := &capRig{now: time.Unix(1700000000, 0)}
	r.status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.posts = append(r.posts, string(b))
		r.mu.Unlock()
		w.WriteHeader(int(r.status.Load()))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	r.log = filepath.Join(dir, "strip.jsonl")
	r.a = &Alerter{
		StripLog:   r.log,
		OffsetPath: filepath.Join(dir, "off"),
		LastPath:   filepath.Join(dir, "last"),
		PolicyDirs: []string{policyDir(t, srv.URL)},
		Stdout:     &r.out,
		Stderr:     io.Discard,
		Now:        func() time.Time { return r.now },
	}
	return r
}

// strips appends n strip rows, each on its own host, so the debounce
// suppresses none of them. This is the case that the cap exists for.
func (r *capRig) strips(t *testing.T, from, n int, threat string) {
	t.Helper()
	f, err := os.OpenFile(r.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := from; i < from+n; i++ {
		fmt.Fprintf(f, "{\"ev\":\"strip\",\"threat\":%q,\"rule\":\"anthropic\",\"where\":\"header\",\"host\":\"h%d.example\"}\n", threat, i)
	}
}

func (r *capRig) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.posts...)
}

// Forty incidents on forty hosts in one hour: thirty posts. The other ten
// go to the console and alert.last as always. When the hour is up, one post
// tells that ten were suppressed. It comes on the first poll after the
// hour, and it needs no new row to trigger it.
func TestWebhookCapSuppressesAndSummarises(t *testing.T) {
	r := newCapRig(t)
	r.strips(t, 0, 40, "")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if n := len(r.got()); n != defaultCapPosts {
		t.Fatalf("%d posts in the first hour, want %d", n, defaultCapPosts)
	}
	if n := strings.Count(r.out.String(), "STRIP anthropic"); n != 40 {
		t.Fatalf("%d console lines, want every one of the 40:\n%s", n, r.out.String())
	}
	if last, _ := os.ReadFile(r.a.LastPath); !strings.Contains(string(last), "h39.example") {
		t.Fatalf("alert.last is not the last row: %s", last)
	}

	r.now = r.now.Add(59 * time.Minute)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if n := len(r.got()); n != defaultCapPosts {
		t.Fatalf("a summary went out before the hour was up: %q", r.got()[n-1])
	}

	r.now = r.now.Add(2 * time.Minute)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != defaultCapPosts+1 || !strings.Contains(posts[len(posts)-1], "10 alerts suppressed") {
		t.Fatalf("no summary when the window rolled: %d posts, last %q", len(posts), posts[len(posts)-1])
	}

	// The new window has the summary in it and room for the rest.
	r.strips(t, 40, 1, "")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if posts = r.got(); len(posts) != defaultCapPosts+2 || !strings.Contains(posts[len(posts)-1], "h40.example") {
		t.Fatalf("the next window did not post: %q", posts[len(posts)-1])
	}
	// A quiet hour rolls with nothing to say.
	r.now = r.now.Add(2 * time.Hour)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if n := len(r.got()); n != defaultCapPosts+2 {
		t.Fatalf("an hour with nothing suppressed posted a summary: %q", r.got()[n-1])
	}
}

// A canary row is the alert that docs/fence.md promises always arrives.
// So a full window does not suppress it.
func TestWebhookCapNeverHoldsACanary(t *testing.T) {
	r := newCapRig(t)
	r.a.CapPosts = 3
	r.strips(t, 0, 5, "")
	r.strips(t, 5, 1, "canary")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 4 || !strings.HasPrefix(posts[3], "CANARY ") {
		t.Fatalf("posts %q; want three and the canary", posts)
	}
}

// A summary that the webhook refused is the one message that says that
// alerts were missed. So the window and its count stay until delivery,
// paced by the retry floor. Rows that arrive in the meantime add to it.
func TestWebhookCapSummaryRetriedUntilDelivered(t *testing.T) {
	r := newCapRig(t)
	r.a.CapPosts = 2
	r.strips(t, 0, 4, "")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	r.status.Store(500)
	r.now = r.now.Add(capWindow + time.Second)
	_ = r.a.Drain(false)
	if n := len(r.got()); n != 3 {
		t.Fatalf("%d posts, want the two and one failed summary", n)
	}
	r.strips(t, 4, 1, "")
	r.now = r.now.Add(time.Second)
	_ = r.a.Drain(false)
	if n := len(r.got()); n != 3 {
		t.Fatalf("retried inside the retry floor: %d posts", n)
	}
	r.status.Store(200)
	r.now = r.now.Add(retryAfter)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 4 || !strings.Contains(posts[3], "3 alerts suppressed") {
		t.Fatalf("posts %q; want the summary to carry all three", posts)
	}
}

// A negative cap is no cap.
func TestWebhookCapOff(t *testing.T) {
	r := newCapRig(t)
	r.a.CapPosts = -1
	r.strips(t, 0, defaultCapPosts+5, "")
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if n := len(r.got()); n != defaultCapPosts+5 {
		t.Fatalf("%d posts with the cap off", n)
	}
}
