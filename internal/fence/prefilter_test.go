package fence

import (
	"io"
	"strings"
	"testing"

	"pi-fortress/internal/tokenrules"
)

func benchTokenSet(t *testing.T) *tokenSet {
	t.Helper()
	re, err := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	return tokensFor(re)
}

// The shipped rules are all written from the token class, and all have a
// literal prefix. Thus both halves of the prefilter are armed. If a new
// rule disables either half, the fence still matches, but slower. This
// test says which half went.
func TestShippedRulesArmTheFilter(t *testing.T) {
	ts := benchTokenSet(t)
	if !ts.complete {
		t.Error("a rule has no literal prefix; the regexp now runs on every byte")
	}
	if !ts.bounded {
		t.Error("a rule uses a character outside the token class; the length check is off")
	}
	if ts.minLen != 20 {
		t.Errorf("shortest possible match is %d, expected AKIA + 16", ts.minLen)
	}
	if ts.maxPrefix != len("sk-ant-admin01-") {
		t.Errorf("maxPrefix = %d, expected the longest rule prefix", ts.maxPrefix)
	}
}

// A prefix that cannot complete costs a few byte comparisons, not an NFA
// pass over the kilobytes after it.
func TestPrefilterRejectsShortRuns(t *testing.T) {
	ts := benchTokenSet(t)
	noise := []byte(` "a":"ghp_short", "b":"sk-nope", "c":"AKIA!", "d":"npm_x", `)
	wins, ok := ts.candidates(noise)
	if !ok {
		t.Fatal("prefilter disabled")
	}
	if len(wins) != 0 {
		t.Fatalf("near-misses opened %d windows: %v", len(wins), wins)
	}
	if ts.match(noise) {
		t.Fatal("a near-miss matched")
	}
}

// The window of a real hit ends immediately after the token, not a fixed
// 4 KiB later. Thus one token in a large body does not pull the NFA over
// the body.
func TestPrefilterWindowStopsAtTheToken(t *testing.T) {
	ts := benchTokenSet(t)
	body := []byte(strings.Repeat("z", 100) + " " + ghp + " " + strings.Repeat("z", 8192))
	wins, ok := ts.candidates(body)
	if !ok || len(wins) != 1 {
		t.Fatalf("windows %v ok=%v", wins, ok)
	}
	if w := wins[0][1] - wins[0][0]; w > len(ghp)+4 {
		t.Fatalf("window is %d bytes for a %d byte token", w, len(ghp))
	}
	if !ts.match(body) {
		t.Fatal("the token stopped matching")
	}
}

// The scan keeps a run that reaches the end of the buffer, for any length:
// on a stream, the remainder of the token did not arrive yet.
func TestPrefilterKeepsARunThatReachesTheEnd(t *testing.T) {
	ts := benchTokenSet(t)
	if _, ok := ts.span([]byte("xx ghp_abc"), 3, new(tokenRun)); !ok {
		t.Fatal("a truncated hit at the buffer end was dropped")
	}
	if _, ok := ts.span([]byte("xx ghp_abc "), 3, new(tokenRun)); ok {
		t.Fatal("a hit whose run ends short was kept")
	}
}

// Clean traffic must not stay in the buffer. With no prefix in sight, the
// stream holds only enough that a prefix cannot be split. Thus a window
// that a chunked upload never needs does not delay it.
func TestStreamHoldsBackOnlyAPrefixOnCleanTraffic(t *testing.T) {
	ts := benchTokenSet(t)
	pr, pw := io.Pipe()
	ts_ := newTokenStream(pr, ts, false)
	const chunk = "the quick brown fox jumps over the lazy dog, and nothing here is a token at all."
	go func() {
		_, _ = io.WriteString(pw, chunk)
	}()
	buf := make([]byte, 4096)
	n, err := ts_.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(chunk) - (ts.maxPrefix - 1); n != want {
		t.Fatalf("emitted %d of %d bytes, want %d held back only for a split prefix", n, len(chunk), want)
	}
	_ = pw.Close()
}
