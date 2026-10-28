package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Each sink has a body limit, and refuses a post over it. So PostMessage
// cuts a long message to the limit of the sink, as measured after the
// escape of that sink. The cut is at a rune boundary, never inside an
// escape sequence, and the post ends with a mark that tells it was cut.
func TestPostFitsSinkLimit(t *testing.T) {
	srv, got := recordHooks(t)
	a := &Alerter{Client: srv.Client(), Stderr: io.Discard}
	discordHook := srv.URL + "/discord.com/api/webhooks/1/x"
	slackHook := srv.URL + "/hooks.slack.com/services/T/B/x"
	ntfyHook := srv.URL + "/ntfy-topic"

	// The leading "a" puts each escape across the limit, so a cut that
	// counts escaped characters alone would end inside one.
	for _, msg := range []string{
		"a" + strings.Repeat("_", 1500),
		"a" + strings.Repeat("@", 1500),
		"a" + strings.Repeat("\u00e9", 1500) + strings.Repeat("\U0001F600", 600),
	} {
		if err := a.PostMessage(discordHook, msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.PostMessage(slackHook, "a"+strings.Repeat("&", 1500)); err != nil {
		t.Fatal(err)
	}
	if err := a.PostMessage(ntfyHook, "a"+strings.Repeat("\u00e9", 3000)); err != nil {
		t.Fatal(err)
	}
	if err := a.PostMessage(ntfyHook, "short"); err != nil {
		t.Fatal(err)
	}
	posts := got()
	if len(posts) != 6 {
		t.Fatalf("%d posts", len(posts))
	}

	mark := discordEscape(" (cut)")
	for _, p := range posts[:3] {
		var dc struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal([]byte(p.body), &dc); err != nil {
			t.Fatal(err)
		}
		if n := len(utf16.Encode([]rune(dc.Content))); n > 2000 {
			t.Fatalf("discord content is %d characters, over 2000", n)
		}
		body, ok := strings.CutSuffix(dc.Content, mark)
		if !ok {
			t.Fatalf("discord content has no cut mark: ...%q", tail(dc.Content))
		}
		if n := len(body) - len(strings.TrimRight(body, `\`)); n%2 != 0 || strings.HasSuffix(body, "@") {
			t.Fatalf("discord content cut inside an escape: ...%q", tail(body))
		}
	}

	var sl struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(posts[3].body), &sl); err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutSuffix(sl.Text, " (cut)")
	if n := utf8.RuneCountInString(sl.Text); n > 3000 || !ok || !strings.HasSuffix(body, "&amp;") {
		t.Fatalf("slack text: %d characters, ...%q", n, tail(sl.Text))
	}

	if b := posts[4].body; len(b) > 4096 || !utf8.ValidString(b) || !strings.HasSuffix(b, " (cut)") {
		t.Fatalf("ntfy body: %d bytes, valid %v, ...%q", len(b), utf8.ValidString(b), tail(b))
	}
	if b := posts[5].body; b != "short" {
		t.Fatalf("a short message changed: %q", b)
	}
}

func tail(s string) string {
	if len(s) > 24 {
		return s[len(s)-24:]
	}
	return s
}

// statusHook answers a post that contains a key of codes with that
// status, and any other post with 204. It records each body.
func statusHook(t *testing.T, codes map[string]int) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		code := http.StatusNoContent
		for k, c := range codes {
			if strings.Contains(string(b), k) {
				code = c
			}
		}
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// A sink that refuses the body of a post (400, 413, 422) refuses the same
// body each time. So flush drops that post, counts it as suppressed for
// its kind, and continues with the next post. A refusal that is about the
// webhook (for example 429) keeps the post at the head for a retry.
func TestRefusedPostDoesNotHoldQueue(t *testing.T) {
	srv, got := statusHook(t, map[string]int{
		"r400.example": http.StatusBadRequest,
		"r413.example": http.StatusRequestEntityTooLarge,
		"r422.example": http.StatusUnprocessableEntity,
		"wait.example": http.StatusTooManyRequests,
	})
	now := t0
	a := &Alerter{Client: srv.Client(), Now: func() time.Time { return now }, Stdout: io.Discard, Stderr: io.Discard}
	url := srv.URL + "/topic"
	row := func(host string) string {
		return `{"ev":"strip","rule":"anthropic","where":"header","host":"` + host + `"}`
	}
	for _, h := range []string{"r400.example", "r413.example", "r422.example", "ok1.example"} {
		if err := a.handleFrom(row(h), url, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.flush(url); err != nil {
		t.Fatalf("flush: %v", err)
	}
	posts := got()
	if len(posts) != 4 || !strings.Contains(posts[3], "ok1.example") || len(a.queue) != 0 {
		t.Fatalf("posts %q, queue %d", posts, len(a.queue))
	}
	if a.cap.suppressed != 3 || a.cap.by["strip"] != 3 || !a.retryAt.IsZero() {
		t.Fatalf("cap %+v, retryAt %v", a.cap, a.retryAt)
	}
	now = now.Add(capWindow + time.Second)
	if err := a.flush(url); err != nil {
		t.Fatalf("flush: %v", err)
	}
	posts = got()
	if sum := posts[len(posts)-1]; len(posts) != 5 || !strings.Contains(sum, "3 alerts suppressed") || !strings.Contains(sum, "strip 3") {
		t.Fatalf("summary: %q", posts)
	}

	for _, h := range []string{"wait.example", "ok2.example"} {
		if err := a.handleFrom(row(h), url, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.flush(url); err == nil {
		t.Fatal("flush reported success after a 429")
	}
	if posts = got(); len(posts) != 6 || len(a.queue) != 2 || !strings.Contains(a.queue[0].msg, "wait.example") {
		t.Fatalf("posts %d, queue %+v", len(posts), a.queue)
	}
}

// A canary post goes before the posts that wait in the queue.
func TestCanaryGoesBeforeQueuedPosts(t *testing.T) {
	srv, got := recordHooks(t)
	a := &Alerter{Client: srv.Client(), Now: func() time.Time { return t0 }, Stdout: io.Discard, Stderr: io.Discard}
	url := srv.URL + "/topic"
	for _, line := range []string{
		`{"ev":"strip","rule":"anthropic","where":"header","host":"one.example"}`,
		`{"ev":"strip","rule":"anthropic","where":"header","host":"two.example"}`,
		`{"ev":"strip","threat":"canary","rule":"canary","where":"header","host":"three.example"}`,
	} {
		if err := a.handleFrom(line, url, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.flush(url); err != nil {
		t.Fatal(err)
	}
	posts := got()
	if len(posts) != 3 || !strings.HasPrefix(posts[0].body, "CANARY ") || !strings.Contains(posts[1].body, "one.example") {
		t.Fatalf("posts %q", posts)
	}
}
