package fence

import (
	"bytes"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/tokenrules"
)

// candidatesEachWalk is candidates as it was before tokenRun and
// foldIndex. span walked the run of each hit again, up to the window, and
// each hit had a search of its own (indexBefore). The tests below compare
// candidates with it.
func candidatesEachWalk(t *tokenSet, b []byte) ([][2]int, bool) {
	if !t.complete {
		return nil, false
	}
	var wins [][2]int
	for i, p := range t.prefixes {
		back := 1
		if t.lead[i] {
			back = tokenrules.LeadMax
		}
		for k := 0; k < len(b); {
			j := indexBefore(t, b[k:], p)
			if j < 0 {
				break
			}
			s := k + j
			if hi, ok := spanEachWalk(t, b, s); ok {
				wins = append(wins, [2]int{max(s-back, 0), hi})
			}
			k = s + 1
		}
	}
	if len(wins) == 0 {
		return nil, true
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i][0] < wins[j][0] })
	var out [][2]int
	for _, w := range wins {
		if n := len(out); n > 0 && w[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], w[1])
			continue
		}
		out = append(out, w)
	}
	return out, true
}

// spanEachWalk is span as it was before tokenRun.
func spanEachWalk(t *tokenSet, b []byte, s int) (int, bool) {
	lim := min(s+window, len(b))
	if !t.bounded {
		return lim, true
	}
	i := s
	for i < lim && inTokenClass(b[i]) {
		i++
	}
	if i-s < t.minLen && i < len(b) {
		return 0, false
	}
	return min(i+1, len(b)), true
}

// A run of token bytes with a prefix every few bytes has a hit every few
// bytes. All the hits of the run share the end of the run. span walks the
// run one time for each searched prefix, not one time for each hit. Thus
// the walk is linear in the body. Before, each hit walked up to one
// window: for a run of "ghp_", about window/4 times the body.
func TestSpanWalksARunOnce(t *testing.T) {
	ts := benchTokenSet(t)
	// all has each searched prefix. rev has them in the opposite order.
	// Thus in rev, the hits of each prefix after the first start before
	// the run that the prefix before it found, and span walks the run again.
	var all, rev []byte
	for i, p := range ts.prefixes {
		all = append(all, p...)
		rev = append(rev, ts.prefixes[len(ts.prefixes)-1-i]...)
	}
	for _, c := range []struct {
		name   string
		body   string
		passes int
	}{
		{"prefixes", benchPrefixRunBody(), 1},
		{"runs shorter than the hold", benchPrefixRunsBody(), 1},
		{"prefix and token bytes", strings.Repeat("ghp_A1b2", (1<<20)/8), 1},
		{"all prefixes", string(bytes.Repeat(all, (1<<20)/len(all))), len(ts.prefixes)},
		{"all prefixes, last first", string(bytes.Repeat(rev, (1<<20)/len(rev))), len(ts.prefixes)},
	} {
		b := []byte(c.body)
		wins, ok, work := ts.candidatesWalk(b)
		if !ok || len(wins) == 0 {
			t.Fatalf("%s: no windows, ok=%v", c.name, ok)
		}
		walked := work.walked
		t.Logf("%s: span walked %d bytes of a %d byte body", c.name, walked, len(b))
		if lim := c.passes * len(b); walked > lim {
			t.Errorf("%s: span walked %d bytes of a %d byte body, limit %d", c.name, walked, len(b), lim)
		}
	}
}

// sameWindows fails when candidates and candidatesEachWalk disagree on b.
func sameWindows(t *testing.T, ts *tokenSet, b []byte) {
	t.Helper()
	got, gok := ts.candidates(b)
	want, wok := candidatesEachWalk(ts, b)
	if gok == wok && slices.Equal(got, want) {
		return
	}
	i := 0
	for i < min(len(got), len(want)) && got[i] == want[i] {
		i++
	}
	t.Fatalf("%.80q (%d bytes): ok %v, %d windows; before ok %v, %d windows; first change at window %d",
		b, len(b), gok, len(got), wok, len(want), i)
}

// corpusValues gives the string and []byte values of a fuzz corpus file.
func corpusValues(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(raw), "\n") {
		for _, pre := range []string{"string(", "[]byte("} {
			if v, ok := strings.CutPrefix(line, pre); ok && strings.HasSuffix(v, ")") {
				if s, err := strconv.Unquote(v[:len(v)-1]); err == nil {
					out = append(out, []byte(s))
				}
			}
		}
	}
	return out
}

// spanEdgeBodies are runs that end at, before and after one window from a
// hit, runs that reach the end of the buffer, and hits that follow the end
// of a run.
func spanEdgeBodies() [][]byte {
	var out [][]byte
	for _, n := range []int{1, 19, 20, 21, window - 9, window - 4, window - 1, window, window + 1, window + 4, 2*window + 3} {
		dense := strings.Repeat("ghp_", n/4+1)[:n]
		one := "ghp_" + strings.Repeat("A", n)
		for _, run := range []string{dense, one, strings.ToUpper(dense)} {
			for _, pre := range []string{"", "x ", "ghp_ab ", "AKIA", "sk-ant-oat01-"} {
				for _, post := range []string{"", " ", "ghp_", " ghp_" + strings.Repeat("Q", 40), "%20ghp_", "!" + dense} {
					out = append(out, []byte(pre+run+post))
				}
			}
		}
	}
	return out
}

// candidates gives the same windows as candidatesEachWalk. The bodies are
// the values of the fuzz corpora, the bench bodies, edge cases at the
// window and at the end of the buffer, and random bodies of prefixes,
// separators and runs. The rule sets are those of skipSets: the shipped
// rules, a rule with \b after the token, rules that are not bounded, and a
// rule with no prefix.
func TestCandidatesSameAsEachWalk(t *testing.T) {
	sets := skipSets(t)
	files, err := filepath.Glob(filepath.Join("testdata", "fuzz", "*", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fuzz corpus: %v", err)
	}
	var bodies [][]byte
	for _, f := range files {
		for _, v := range corpusValues(t, f) {
			bodies = append(bodies, v, skipBody(v))
		}
	}
	if len(bodies) == 0 {
		t.Fatal("the fuzz corpus gave no values")
	}
	cut := func(s string) []byte { return []byte(s[:min(len(s), 64<<10)]) }
	bodies = append(bodies,
		cut(benchTokenBody()), cut(benchPrefixNoiseBody()),
		cut(benchPrefixRunBody()), cut(benchPrefixRunsBody()))
	bodies = append(bodies, spanEdgeBodies()...)
	rng := rand.New(rand.NewPCG(11, 12))
	for range 3000 {
		data := make([]byte, 2*(1+rng.IntN(40)))
		for j := range data {
			data[j] = byte(rng.IntN(256))
		}
		bodies = append(bodies, skipBody(data))
	}
	for _, b := range bodies {
		for _, ts := range sets {
			sameWindows(t, ts, b)
		}
	}
}

func FuzzCandidatesSameAsEachWalk(f *testing.F) {
	sets := skipSets(f)
	f.Add(uint8(0), []byte{0, 0, 0, 0, 0, 0, 140, 40, 0, 0, 141, 40})
	f.Add(uint8(0), []byte{0, 0, 255, 255, 0, 0, 255, 255, 9, 0, 0, 0})
	f.Add(uint8(1), []byte{3, 0, 135, 60, 9, 0, 3, 0})
	f.Add(uint8(2), []byte{7, 0, 129, 10, 9, 0, 7, 0, 129, 10})
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		b := skipBody(data)
		if len(b) > 64<<10 {
			return
		}
		sameWindows(t, sets[int(which)%len(sets)], b)
	})
}
