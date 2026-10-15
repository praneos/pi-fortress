package alert

import (
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

// The host, zone and detail of a row are text that an agent chose. A
// newline in one forged a second line in the journal. ESC or C1 drove the
// terminal of the operator, and a bidi override changed the order of the text.
func TestConsoleLineCarriesNoControls(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "strip.jsonl")
	ev, _ := json.Marshal(map[string]any{"ev": "strip", "rule": "anthropic", "where": "header",
		"host": "evil.example\r\nSTRIP secret:x in body -> fake\x1b[2J\u009b31m‮"})
	if err := os.WriteFile(log, append(ev, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	a := &Alerter{StripLog: log, OffsetPath: filepath.Join(dir, "off"), LastPath: filepath.Join(dir, "last"),
		PolicyDirs: []string{dir}, Stdout: &out, Stderr: io.Discard}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if want := "STRIP anthropic in header -> evil.example??STRIP secret:x in body -> fake?[2J?31m?\n"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	n := Summarize(map[string]any{"threat": "dns_key", "where": "agent", "client_ip": "10.77.0.10\n",
		"host": "z\x1b]0;pwn\x07.example", "detail": "refused\r\nKEY IN A DNS NAME forged"})
	if strings.ContainsAny(n, "\r\n\x1b\x07") {
		t.Fatalf("notice line carries controls: %q", n)
	}
}

type hookRec struct {
	ct, body string
}

func recordHooks(t *testing.T) (*httptest.Server, func() []hookRec) {
	t.Helper()
	var mu sync.Mutex
	var got []hookRec
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, hookRec{r.Header.Get("Content-Type"), string(b)})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []hookRec {
		mu.Lock()
		defer mu.Unlock()
		return append([]hookRec(nil), got...)
	}
}

// Slack and Discord read markup in what they get. So a host that an agent
// chose was a clickable "rotate-key-now" link to its own page, or a ping
// of the full channel. Each gets its own escape. ntfy shows text/plain as
// text, so ntfy gets only the removal of the control runes.
func TestWebhookBodiesNeutraliseMarkup(t *testing.T) {
	srv, got := recordHooks(t)
	a := &Alerter{Client: srv.Client(), Stderr: io.Discard}
	ev := map[string]any{"ev": "strip", "rule": "anthropic", "where": "header",
		"host": "<https://evil.example|rotate-key-now> <!channel> [x](https://evil) @everyone *b* _i_ ~s~ `c` a&b\x1b[2J\r\n"}
	for _, hook := range []string{
		srv.URL + "/hooks.slack.com/services/T/B/x",
		srv.URL + "/discord.com/api/webhooks/1/x",
		srv.URL + "/ntfy-topic",
	} {
		if err := a.PostWebhook(hook, ev); err != nil {
			t.Fatal(err)
		}
	}
	posts := got()
	if len(posts) != 3 {
		t.Fatalf("%d posts", len(posts))
	}

	var sl map[string]any
	if err := json.Unmarshal([]byte(posts[0].body), &sl); err != nil {
		t.Fatal(err)
	}
	text, _ := sl["text"].(string)
	if sl["mrkdwn"] != false || strings.ContainsAny(text, "<>\x1b\r\n") || strings.Contains(text, "&b") {
		t.Fatalf("slack body not neutralised: %q", posts[0].body)
	}
	if !strings.Contains(text, "&lt;https://evil.example|rotate-key-now&gt;") || !strings.Contains(text, "&lt;!channel&gt;") || !strings.Contains(text, "a&amp;b") {
		t.Fatalf("slack text %q", text)
	}

	var dc map[string]any
	if err := json.Unmarshal([]byte(posts[1].body), &dc); err != nil {
		t.Fatal(err)
	}
	content, _ := dc["content"].(string)
	am, _ := dc["allowed_mentions"].(map[string]any)
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
		t.Fatalf("discord mentions not disabled: %q", posts[1].body)
	}
	for _, bad := range []string{"[x](https://evil)", "@everyone", "*b*", "_i_", "~s~", "`c`", "\x1b", "\r", "\n"} {
		if strings.Contains(content, bad) {
			t.Fatalf("discord content keeps %q: %q", bad, content)
		}
	}
	if !strings.Contains(content, `\[x\]\(https://evil\)`) || !strings.Contains(content, "@​everyone") || !strings.Contains(content, `\<https://evil.example\|rotate-key-now\>`) {
		t.Fatalf("discord content %q", content)
	}

	if posts[2].ct != "text/plain" || strings.ContainsAny(posts[2].body, "\x1b\r\n") || !strings.Contains(posts[2].body, "STRIP anthropic in header -> <https://evil.example|rotate-key-now>") {
		t.Fatalf("ntfy body %q", posts[2].body)
	}
}

// A webhook that never answers must not delay the record. While the post
// of one tail is out, the row of the other tail still goes to the console
// and alert.last immediately.
func TestHungPostNeverStallsLocalRecording(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	dir := t.TempDir()
	var out syncBuf
	a := &Alerter{LastPath: filepath.Join(dir, "last"), Client: srv.Client(), Stdout: &out, Stderr: io.Discard}
	url := srv.URL + "/topic"
	if err := a.handle(`{"ev":"strip","rule":"anthropic","where":"header","host":"a.example"}`, url); err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.flush(url) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the post never went out")
	}
	done := make(chan error, 1)
	go func() {
		done <- a.handle(`{"threat":"dns_key","where":"agent","client_ip":"10.77.0.10","host":"z.example","detail":"refused"}`, url)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a row waited on a hung webhook post")
	}
	if !strings.Contains(out.String(), "KEY IN A DNS NAME 10.77.0.10 (agent) -> z.example") {
		t.Fatalf("console %q", out.String())
	}
	if last, _ := os.ReadFile(a.LastPath); !strings.Contains(string(last), "z.example") {
		t.Fatalf("alert.last %q", last)
	}
	if err := a.flush(url); err != nil {
		t.Fatalf("a second flush waited instead of skipping: %v", err)
	}
}

// A webhook that refuses leaves each row recorded. The queued posts are sent
// in order when the webhook answers again.
func TestRefusingWebhookQueuesInOrder(t *testing.T) {
	r := newCapRig(t)
	r.status.Store(500)
	r.strips(t, 0, 3, "")
	if err := r.a.Drain(false); err == nil {
		t.Fatal("Drain reported success after a 500")
	}
	if n := strings.Count(r.out.String(), "STRIP anthropic"); n != 3 {
		t.Fatalf("%d console lines, want 3", n)
	}
	if last, _ := os.ReadFile(r.a.LastPath); !strings.Contains(string(last), "h2.example") {
		t.Fatalf("alert.last %s", last)
	}
	if n := len(r.got()); n != 1 {
		t.Fatalf("%d posts, want only the head tried", n)
	}
	r.status.Store(200)
	r.now = r.now.Add(retryAfter)
	if err := r.a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := r.got()
	if len(posts) != 4 {
		t.Fatalf("posts %q", posts)
	}
	for i, want := range []string{"h0.example", "h0.example", "h1.example", "h2.example"} {
		if !strings.Contains(posts[i], want) {
			t.Fatalf("post %d %q, want %s", i, posts[i], want)
		}
	}
}

// Overflow drops the oldest ordinary post. While an ordinary post is there,
// it never drops a canary or a key post. It counts what it dropped.
func TestQueueOverflowDropsOrdinaryFirst(t *testing.T) {
	a := &Alerter{Now: func() time.Time { return time.Unix(1700000000, 0) }}
	a.enqueue(pending{msg: "canary", kind: "canary", keep: true})
	for range queueMax - 1 {
		a.enqueue(pending{msg: "tunnel", kind: "dns_tunnel"})
	}
	a.enqueue(pending{msg: "key", kind: "dns_key", keep: true})
	if len(a.queue) != queueMax || a.queue[0].msg != "canary" || a.queue[len(a.queue)-1].msg != "key" {
		t.Fatalf("queue %d head %q tail %q", len(a.queue), a.queue[0].msg, a.queue[len(a.queue)-1].msg)
	}
	if a.cap.suppressed != 1 || a.cap.by["dns_tunnel"] != 1 {
		t.Fatalf("drop not counted: %+v", a.cap)
	}
}
