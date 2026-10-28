package alert

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/jsonl"
)

var t0 = time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)

func blocksRow(at time.Time, where string, counts map[string]int, top ...jsonl.BlockHit) jsonl.Blocks {
	return jsonl.Blocks{T: at.Format(time.RFC3339Nano), Threat: jsonl.BlocksThreat, Rule: "observe", Where: where, Counts: counts, Top: top}
}

// One window gives a maximum of one post, at its end, and not before.
func TestDigestPostsOnceAWindow(t *testing.T) {
	d := &Digest{Every: time.Hour, Stderr: io.Discard}
	d.load(t0)
	d.add(blocksRow(t0.Add(time.Minute), "agent", map[string]int{jsonl.BlockSecurity: 2},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "urlhaus-domains-online", Src: "10.77.0.10", Dst: "evil.example", N: 2}), t0.Add(time.Minute))
	if msg := d.due(t0.Add(59 * time.Minute)); msg != "" {
		t.Fatalf("post before the end of the window: %q", msg)
	}
	msg := d.due(t0.Add(time.Hour))
	if !strings.Contains(msg, "agent: security feeds 2") || !strings.Contains(msg, "10.77.0.10 -> evil.example (urlhaus-domains-online) x2") {
		t.Fatalf("post: %q", msg)
	}
	// The window closed with the post. A block just after it waits for the
	// end of the next window.
	d.add(blocksRow(t0.Add(61*time.Minute), "agent", map[string]int{jsonl.BlockOperator: 1}), t0.Add(61*time.Minute))
	for _, at := range []time.Duration{time.Hour, 61 * time.Minute, 119 * time.Minute} {
		if msg := d.due(t0.Add(at)); msg != "" {
			t.Fatalf("second post in one window at +%v: %q", at, msg)
		}
	}
	if msg := d.due(t0.Add(2 * time.Hour)); !strings.Contains(msg, "agent: operator blacklist 1") || strings.Contains(msg, "security") {
		t.Fatalf("next window: %q", msg)
	}
}

// A window with only blocks that do not count gives no post, and its
// counts do not go into the next window.
func TestDigestQuietWindowDoesNotPost(t *testing.T) {
	d := &Digest{Every: time.Hour, Stderr: io.Discard}
	if msg := d.due(t0); msg != "" {
		t.Fatalf("empty: %q", msg)
	}
	d.add(blocksRow(t0.Add(time.Minute), "house", map[string]int{jsonl.BlockHouse: 5000, jsonl.BlockOther: 40}), t0)
	d.add(blocksRow(t0.Add(2*time.Minute), "desk", map[string]int{jsonl.BlockOther: 3}), t0)
	if msg := d.due(t0.Add(time.Hour)); msg != "" {
		t.Fatalf("quiet window posted: %q", msg)
	}
	d.add(blocksRow(t0.Add(70*time.Minute), "house", map[string]int{jsonl.BlockSecurity: 1}), t0.Add(70*time.Minute))
	msg := d.due(t0.Add(2 * time.Hour))
	if !strings.Contains(msg, "house: security feeds 1") || strings.Contains(msg, "5000") {
		t.Fatalf("the quiet window leaked into the next: %q", msg)
	}
}

// The class decides the post. The agent segment counts for each class. On
// another segment, only a security feed or the operator blacklist counts.
// When a post goes out, the house lists are one count, with no names, and
// a device of another segment is not named.
func TestDigestClassSplit(t *testing.T) {
	cases := []struct {
		name   string
		row    jsonl.Blocks
		posted bool
	}{
		{"agent other", blocksRow(t0, "agent", map[string]int{jsonl.BlockOther: 1}), true},
		{"house security", blocksRow(t0, "house", map[string]int{jsonl.BlockSecurity: 1}), true},
		{"desk operator", blocksRow(t0, "desk", map[string]int{jsonl.BlockOperator: 1}), true},
		{"house lists", blocksRow(t0, "house", map[string]int{jsonl.BlockHouse: 900}), false},
		{"house other", blocksRow(t0, "house", map[string]int{jsonl.BlockOther: 9}), false},
	}
	for _, c := range cases {
		d := &Digest{Every: time.Hour, Stderr: io.Discard}
		d.load(t0)
		d.add(c.row, t0)
		if got := d.due(t0.Add(time.Hour)) != ""; got != c.posted {
			t.Errorf("%s: posted %v, want %v", c.name, got, c.posted)
		}
	}

	d := &Digest{Every: time.Hour, Stderr: io.Discard}
	d.add(blocksRow(t0, "house", map[string]int{jsonl.BlockSecurity: 1, jsonl.BlockHouse: 900},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "spamhaus-drop", Src: "10.78.0.20", Dst: "203.0.113.9", N: 1},
		jsonl.BlockHit{Class: jsonl.BlockHouse, Feed: "hagezi-pro", Src: "10.78.0.20", Dst: "ads.example", N: 900}), t0)
	d.add(blocksRow(t0, "agent", map[string]int{jsonl.BlockOperator: 1},
		jsonl.BlockHit{Class: jsonl.BlockOperator, Feed: "local", Src: "10.77.0.10", Dst: "192.0.2.1", N: 1}), t0)
	msg := d.due(t0.Add(time.Hour))
	want := "BLOCKED 2026-10-27 10:00 to 11:00 UTC" +
		" | agent: operator blacklist 1; top: 10.77.0.10 -> 192.0.2.1 (operator) x1" +
		" | house: security feeds 1, house ad and tracker lists 900; top: 203.0.113.9 (spamhaus-drop) x1"
	if msg != want {
		t.Fatalf("post:\n%s\nwant:\n%s", msg, want)
	}
}

// A name can carry a key or a placeholder. The post has its zone only.
func TestDigestRedactsCredentialShapedNames(t *testing.T) {
	// Built at run time, so the leak check of the tree does not see a key.
	gh := "ghp" + "_" + "R4nd0mLook1ngT0kenB0dyQx7Zp2Lk9Wm3Vt8Yh"
	cases := map[string]string{
		"evil.example": "evil.example",
		"pf_0123456789abcdef_GITHUB_TOKEN.evil.example": "(redacted).evil.example",
		gh + ".evil.example":                            "(redacted).evil.example",
		strings.Repeat("a1b2", 9) + ".tunnel.example":   "(redacted).tunnel.example",
		"x." + gh: "(redacted)",
	}
	for in, want := range cases {
		if got := redactName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	d := &Digest{Every: time.Hour, Stderr: io.Discard}
	d.add(blocksRow(t0, "agent", map[string]int{jsonl.BlockSecurity: 1},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: gh + ".evil.example", N: 2},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: gh + ".evil.example\r\nforged", N: 1}), t0)
	msg := d.due(t0.Add(time.Hour))
	if strings.Contains(msg, gh) || strings.ContainsAny(msg, "\r") || strings.Contains(msg, "forged") ||
		!strings.Contains(msg, "(redacted).evil.example (f) x2") || !strings.Contains(msg, "(not shown) (f) x1") {
		t.Fatalf("post: %q", msg)
	}
}

// The digest shows a name only when it has the shape of a host name. Any
// other name is a fixed word, so no scheme, port, path or markup gets into
// a post. A long name keeps its right end, cut to 64 characters.
func TestDigestShowsHostShapedNamesOnly(t *testing.T) {
	long := strings.Repeat("abcdefghij.", 12) + "blocked.example"
	d := &Digest{Every: time.Hour, Stderr: io.Discard}
	d.add(blocksRow(t0, "agent", map[string]int{jsonl.BlockSecurity: 7, jsonl.BlockOther: 1},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: "https://login.example/reset", N: 7},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: "host.example:8443", N: 6},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: "caf\u00e9.example", N: 5},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "f", Src: "10.77.0.10", Dst: long, N: 4},
		jsonl.BlockHit{Class: jsonl.BlockOther, Src: "(untracked)", Dst: "(not logged)", N: 1}), t0)
	msg := d.due(t0.Add(time.Hour))
	_, top, _ := strings.Cut(msg, "top: ")
	if strings.ContainsAny(top, ":/\u00e9") || strings.Count(top, "(not shown)") != 3 {
		t.Fatalf("post: %q", msg)
	}
	if !strings.Contains(msg, "(untracked) -> (not logged) (other) x1") {
		t.Fatalf("the fixed words of pf observe changed: %q", msg)
	}
	i := strings.Index(msg, "...")
	j := strings.Index(msg, "blocked.example (f) x4")
	if i < 0 || j < 0 || j+len("blocked.example")-i != 64 || strings.Contains(msg, long) {
		t.Fatalf("long name not cut to 64 characters: %q", msg)
	}
}

// The state file keeps the open window. A restart does not lose it, does
// not count a replayed row two times, and does not post a closed window
// again.
func TestDigestSurvivesARestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "digest.json")
	row := blocksRow(t0.Add(time.Minute), "agent", map[string]int{jsonl.BlockSecurity: 1})
	d := &Digest{Every: time.Hour, StatePath: state, Stderr: io.Discard}
	d.load(t0)
	d.add(row, t0.Add(time.Minute))

	d2 := &Digest{Every: time.Hour, StatePath: state, Stderr: io.Discard}
	d2.add(row, t0.Add(2*time.Minute)) // the notice tail reads the row again
	if msg := d2.due(t0.Add(30 * time.Minute)); msg != "" {
		t.Fatalf("restart closed the window early: %q", msg)
	}
	msg := d2.due(t0.Add(time.Hour))
	if !strings.HasSuffix(msg, " | agent: security feeds 1") {
		t.Fatalf("after restart: %q", msg)
	}
	d3 := &Digest{Every: time.Hour, StatePath: state, Stderr: io.Discard}
	if msg := d3.due(t0.Add(61 * time.Minute)); msg != "" {
		t.Fatalf("restart posted the window again: %q", msg)
	}
	var st digestState
	raw, err := os.ReadFile(state)
	if err != nil || json.Unmarshal(raw, &st) != nil || !st.Start.Equal(t0.Add(time.Hour)) || len(st.Counts) != 0 {
		t.Fatalf("state: %s %v", raw, err)
	}
}

// The state file has the names of the open window, so only its owner
// reads it. A file or a temp file from an older version with a wider mode
// does not keep that mode.
func TestDigestStateIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "digest.json")
	for _, p := range []string{state, state + ".tmp"} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Digest{Every: time.Hour, StatePath: state, Stderr: io.Discard}
	d.load(t0)
	d.add(blocksRow(t0.Add(time.Minute), "agent", map[string]int{jsonl.BlockSecurity: 1},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Dst: "evil.example", N: 1}), t0.Add(time.Minute))
	st, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m != 0o600 {
		t.Fatalf("mode %v, want 0600", m)
	}
	if raw, _ := os.ReadFile(state); !strings.Contains(string(raw), "evil.example") {
		t.Fatalf("state: %s", raw)
	}
}

// Through the Alerter: a Blocks row from the notice log goes into the
// digest, does not post alone and does not replace alert.last. The same
// row in the strip log is only a console line. At the end of the window,
// one post goes to the webhook.
func TestAlerterPostsTheDigestFromTheNoticeLog(t *testing.T) {
	dir := t.TempDir()
	srv, got := recordHooks(t)
	if err := os.WriteFile(filepath.Join(dir, "alert.url"), []byte(srv.URL+"/ntfy-topic\n"), 0644); err != nil {
		t.Fatal(err)
	}
	now := t0
	a := &Alerter{
		StripLog: filepath.Join(dir, "strip.jsonl"), OffsetPath: filepath.Join(dir, "alert.offset"),
		NoticeLog: filepath.Join(dir, "notice.jsonl"), NoticeOffsetPath: filepath.Join(dir, "notice.offset"),
		LastPath: filepath.Join(dir, "alert.last"), PolicyDirs: []string{dir}, Client: srv.Client(),
		Stdout: io.Discard, Stderr: io.Discard, Now: func() time.Time { return now },
		Digest: &Digest{Every: time.Hour, StatePath: filepath.Join(dir, "digest.json"), Stderr: io.Discard},
	}
	raw, _ := json.Marshal(blocksRow(t0.Add(time.Minute), "agent", map[string]int{jsonl.BlockSecurity: 3},
		jsonl.BlockHit{Class: jsonl.BlockSecurity, Feed: "phishing-army", Src: "10.77.0.10", Dst: "evil.example", N: 3}))
	for _, p := range []string{a.NoticeLog, a.StripLog} {
		if err := os.WriteFile(p, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	if err := a.noticeTail().Drain(false); err != nil {
		t.Fatal(err)
	}
	if n := len(got()); n != 0 {
		t.Fatalf("%d posts before the end of the window", n)
	}
	if _, err := os.Stat(a.LastPath); err == nil {
		t.Fatal("a Blocks row replaced alert.last")
	}
	now = t0.Add(time.Hour)
	if err := a.noticeTail().Drain(false); err != nil {
		t.Fatal(err)
	}
	if err := a.Drain(false); err != nil {
		t.Fatal(err)
	}
	posts := got()
	if len(posts) != 1 || !strings.Contains(posts[0].body, "agent: security feeds 3; top: 10.77.0.10 -> evil.example (phishing-army) x3") {
		t.Fatalf("posts: %+v", posts)
	}
	if strings.Contains(posts[0].body, "ntfy-topic") {
		t.Fatalf("the post carries the webhook: %q", posts[0].body)
	}
}
