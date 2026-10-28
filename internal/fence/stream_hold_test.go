package fence

import (
	"bytes"
	"io"
	"maps"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// holdRun is a run of token bytes. It starts with head, and has next at
// the start of each 4000 bytes, twelve times. Then 5000 token bytes with
// no prefix come. Each prefix is inside the window of the one before it.
// Thus the windows merge into one match longer than maxHold. The match ends
// one window after the last prefix, and the run goes on past it.
func holdRun(head, next string) string {
	unit := next + strings.Repeat("B", 4000-len(next))
	return head + strings.Repeat(unit, 12) + strings.Repeat("B", 5000)
}

// holdRuns are such runs for rules with each body class. A rule whose
// class has no '-' or '_' continues over a prefix of letters only.
func holdRuns() map[string]string {
	return map[string]string{
		"gitlab_pat":     holdRun("glpat-", "glpat-"),
		"anthropic_oat":  holdRun("sk-ant-oat01-", "sk-ant-oat01-"),
		"github_oauth":   holdRun("gho_", "AKIA"),
		"github_classic": holdRun("gh"+"p_", "ASIA"),
	}
}

// stepReader gives src in reads of n bytes. Before each read it calls
// peek, if there is one.
type stepReader struct {
	src  []byte
	n    int
	peek func()
}

func (r *stepReader) Read(p []byte) (int, error) {
	if r.peek != nil {
		r.peek()
	}
	if len(r.src) == 0 {
		return 0, io.EOF
	}
	k := copy(p, r.src[:min(r.n, len(r.src))])
	r.src = r.src[k:]
	return k, nil
}

// holdStream is a token stream over body in reads of n bytes. At each read
// of the source, the scan of the read before is complete. Then holdStream
// counts the bytes that the stream holds. It fails when they are more than
// maxHold and one window, or when the reads take longer than limit. peak
// is the most bytes that the stream held.
func holdStream(t *testing.T, ts *tokenSet, body []byte, n int, pad bool, limit time.Duration) (s *tokenStream, peak *int) {
	t.Helper()
	src := &stepReader{src: body, n: n}
	s, peak = newTokenStream(src, ts, pad), new(int)
	start := time.Now()
	src.peek = func() {
		if *peak = max(*peak, len(s.Buf)-s.pre); *peak > maxHold+window {
			t.Fatalf("reads of %d: the stream holds %d bytes, limit %d", n, *peak, maxHold+window)
		}
		if d := time.Since(start); d > limit {
			t.Fatalf("reads of %d: %v and not done, limit %v", n, d, limit)
		}
	}
	return s, peak
}

// stripRef is the strip of b as the fence defines it, from the matches ms
// of b. Each strip is the group of its rule. A token longer than maxHold
// goes on to the end of its run of token bytes, and a match that starts
// inside that run is a part of it. With pad, each strip has the length of
// the bytes that it replaces.
func stripRef(ts *tokenSet, ms [][]int, b []byte, pad bool) []byte {
	var out []byte
	pos := 0
	for _, m := range ms {
		lo, hi := ts.token(m)
		if lo < pos {
			continue
		}
		if hi-lo > maxHold {
			for hi < len(b) && inTokenClass(b[hi]) {
				hi++
			}
		}
		repl := stripRepl
		if pad {
			repl = padRepl(hi - lo)
		}
		out = append(append(out, b[pos:lo]...), repl...)
		pos = hi
	}
	return append(out, b[pos:]...)
}

// A run of token bytes that is one match longer than maxHold leaves the
// stream as one strip, from its prefix to the end of the run. This is so
// at the start of the body and after other bytes, for each read size.
// The stream holds no more than maxHold and one window of it. The bytes
// after the run go out unchanged. The buffered path strips the same bytes.
func TestStreamHoldLimitStripsRun(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	ts := tokensFor(ctx.TokenRE)
	rng := rand.New(rand.NewPCG(17, 18))
	for rule, run := range holdRuns() {
		for _, before := range []string{"", "x", "text before: "} {
			for _, after := range []string{"", " and the text after it.\n"} {
				body := []byte(before + run + after)
				want := before + StripRepl + after
				if got := string(ts.replace(body, stripRepl)); got != want {
					t.Fatalf("%s, before %q: buffered %.60q, want %.60q", rule, before, got, want)
				}
				if got := ts.rules(body); len(got) != 1 || got[0] != rule {
					t.Fatalf("%s, before %q: buffered rules %v", rule, before, got)
				}
				for _, size := range []int{1, 7, 32 << 10} {
					for _, pad := range []bool{false, true} {
						w := want
						if pad {
							w = before + string(padRepl(len(run))) + after
						}
						s, _ := holdStream(t, ts, body, size, pad, time.Minute)
						got, err := io.ReadAll(s)
						if err != nil || string(got) != w {
							t.Fatalf("%s, before %q, reads of %d, pad %v: stream %.60q, want %.60q", rule, before, size, pad, got, w)
						}
						if !maps.Equal(s.hits, map[string]int{rule: 1}) {
							t.Fatalf("%s, before %q, reads of %d: strips %v", rule, before, size, s.hits)
						}
					}
				}
				fwant, fgot, werr, gerr := bothPaths(t, ctx, pol, string(body), rng)
				if werr != nil || gerr != nil {
					t.Fatalf("%s: %v / %v", rule, werr, gerr)
				}
				if string(fwant) != want || !bytes.Equal(fgot, fwant) {
					t.Fatalf("%s, before %q: fence buffered %.60q, stream %.60q", rule, before, fwant, fgot)
				}
			}
		}
	}
}

// At the edge of the hold limit: a token of maxHold bytes strips as the
// match, and the run after it goes out. A token one byte longer strips on
// to the end of its run. The first window of the run sets the length of
// the token, which ends one window after its last prefix. The stream gives
// the bytes of the buffered path at each length, for each read size.
func TestStreamHoldLimitEdge(t *testing.T) {
	ts := benchTokenSet(t)
	unit := "glpat-" + strings.Repeat("B", 4090)
	for first := window - 3; first <= window+2; first++ {
		run := "glpat-" + strings.Repeat("B", first-6) + unit + unit + "glpat-" + strings.Repeat("B", 5000)
		long := first+2*len(unit)+window+1 > maxHold
		for _, before := range []string{"", "x "} {
			body := []byte(before + run + " y")
			ms := ts.matches(body)
			if len(ms) != 1 {
				t.Fatalf("first %d: %d matches", first, len(ms))
			}
			want := stripRef(ts, ms, body, false)
			if got := ts.replace(body, stripRepl); !bytes.Equal(got, want) {
				t.Fatalf("first %d: buffered %.60q, want %.60q", first, got, want)
			}
			if bytes.Contains(want, []byte("B")) == long {
				t.Fatalf("first %d: token longer than maxHold %v, but the run after it is out %v", first, long, !long)
			}
			for _, size := range []int{1, 7, 1000, 32 << 10} {
				for _, pad := range []bool{false, true} {
					s, _ := holdStream(t, ts, body, size, pad, time.Minute)
					got, err := io.ReadAll(s)
					if w := stripRef(ts, ms, body, pad); err != nil || !bytes.Equal(got, w) {
						t.Fatalf("first %d, before %q, reads of %d, pad %v: stream %.60q, want %.60q", first, before, size, pad, got, w)
					}
				}
			}
		}
	}
}

// The stream gives the same bytes at each read as the full scan for long
// runs too. Thus the pin of a long token changes only the cost of a read.
func TestStreamHoldLimitSameAsFullScan(t *testing.T) {
	ts := skipSets(t)[0]
	run := holdRun("glpat-", "glpat-")
	short := strings.Repeat("glpat-"+strings.Repeat("C", 3994), 3) + strings.Repeat("C", 6000)
	for i, body := range []string{
		run + " y",
		"x " + run + " y",
		"x " + short + " y " + run,
		"x " + run[:maxHold-30] + " " + run[:maxHold+30] + " y",
	} {
		sameAsFullScan(t, ts, []byte(body), uint64(i), 600, 0, i%2 == 1)
		sameAsFullScan(t, ts, []byte(body), uint64(i), 9000, 0, i%2 == 0)
	}
	// A rule that is not bounded: its windows do not follow the run.
	loose := skipSets(t)[2]
	tok := strings.Repeat("tok-"+strings.Repeat("x!", 1998), 6)
	sameAsFullScan(t, loose, []byte("x "+tok+" y"), 9, 600, 0, false)
	sameAsFullScan(t, loose, []byte(tok+" y"), 10, 9000, 0, true)
}

// The cost of a body of long runs is near linear in its size, for large and
// for small reads. Each run reaches the hold limit, and then its bytes go
// out as they come. The stream does not scan a growing buffer again at each
// read. The limits are loose, because machines differ.
func TestStreamHoldLimitCost(t *testing.T) {
	ts := benchTokenSet(t)
	oat := "sk-ant-oat01-"
	unit := oat + strings.Repeat("B", 4000)
	many := strings.Repeat("x "+holdRun(oat, oat)+" ", 80)[:4<<20]
	one := ("x " + strings.Repeat(unit, (4<<20)/len(unit)+1))[:4<<20]
	for _, c := range []struct {
		name string
		body string
		size int
	}{
		{"many runs", many, 32 << 10},
		{"many runs", many, 1 << 10},
		{"one run", one, 32 << 10},
		{"one run", one, 1 << 10},
		{"many runs", many[:256<<10], 1},
		{"one run", one[:256<<10], 1},
	} {
		start := time.Now()
		s, peak := holdStream(t, ts, []byte(c.body), c.size, false, time.Second)
		out, err := io.ReadAll(s)
		t.Logf("%s, %d KiB in reads of %d: %v, most held %d", c.name, len(c.body)>>10, c.size, time.Since(start), *peak)
		if err != nil || bytes.Contains(out, []byte(oat)) {
			t.Fatalf("%s, reads of %d: a run went out", c.name, c.size)
		}
	}
}
