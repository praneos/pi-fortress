package fence

import (
	"bytes"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
)

// indexFoldBefore is indexFold as it was before foldIndex. Each call
// scanned again for both cases of the anchor byte. The tests below compare
// foldIndex with it.
func indexFoldBefore(src, needle []byte) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	if len(src) < n {
		return -1
	}
	k := foldAnchor(needle)
	lo := needle[k]
	up := lo
	if 'a' <= lo && lo <= 'z' {
		up = lo - 'a' + 'A'
	}
	// Byte k of a match sits in [k, end).
	end := len(src) - n + k + 1
	nl, nu := -1, -1
	for i := k; i < end; {
		if nl < i {
			nl = nextByteBefore(src, i, end, lo)
		}
		if up == lo {
			nu = nl
		} else if nu < i {
			nu = nextByteBefore(src, i, end, up)
		}
		p := min(nl, nu)
		if p >= end {
			return -1
		}
		if equalFoldASCII(src[p-k:p-k+n], needle) {
			return p - k
		}
		i = p + 1
	}
	return -1
}

func nextByteBefore(src []byte, i, end int, c byte) int {
	if j := bytes.IndexByte(src[i:end], c); j >= 0 {
		return i + j
	}
	return end
}

// indexBefore is the prefix search of t as it was before prefixIndex: one
// search for each hit.
func indexBefore(t *tokenSet, b, p []byte) int {
	if t.fold {
		return indexFoldBefore(b, p)
	}
	return httpwire.Index(b, p)
}

// foldHitsBefore is each hit of needle in b at or after lo, as a pass found
// them before foldIndex: one indexFoldBefore for each hit.
func foldHitsBefore(b, needle []byte, lo int) []int {
	var out []int
	for k := lo; k < len(b); {
		j := indexFoldBefore(b[k:], needle)
		if j < 0 {
			break
		}
		out = append(out, k+j)
		k += j + 1
	}
	return out
}

// foldHits is the same pass with one foldIndex. It also gives the number of
// bytes that the scans read.
func foldHits(b, needle []byte, lo int) ([]int, int) {
	f := newFoldIndex(b, needle)
	var out []int
	for k := lo; k < len(b); {
		s := f.next(k)
		if s < 0 {
			break
		}
		out = append(out, s)
		k = s + 1
	}
	return out, f.searched
}

// firstPrefixBefore is firstPrefixFrom as it was before prefixIndex.
func firstPrefixBefore(t *tokenSet, b []byte, lo int) int {
	best := -1
	for _, p := range t.prefixes {
		for k := lo; k < len(b); {
			j := indexBefore(t, b[k:], p)
			if j < 0 {
				break
			}
			s := k + j
			if t.hit(b, s) {
				if best < 0 || s < best {
					best = s
				}
				break
			}
			k = s + 1
		}
	}
	return best
}

// anchorCases is the number of bytes that foldIndex scans for in a search
// for p: two for a letter, one for a byte with no case.
func anchorCases(p []byte) int {
	if c := p[foldAnchor(p)]; 'a' <= c && c <= 'z' {
		return 2
	}
	return 1
}

// A body with a hit every few bytes, and the anchor byte of that prefix in
// one case only. A pass reads each byte of the body at most one time for
// each case of each anchor byte. Before foldIndex, each hit scanned for the
// other case to the end of the body: for a megabyte, about 10^5 times the
// body for one prefix.
func TestFoldSearchIsLinear(t *testing.T) {
	ts := benchTokenSet(t)
	for _, unit := range []string{"AKIA ", "akia ", "AkIa ", "AIZA ", "aiza\n", "ASIA ", "asIa!"} {
		b := bytes.Repeat([]byte(unit), (1<<20)/len(unit))
		lim := 0
		for _, p := range ts.prefixes {
			lim += anchorCases(p) * len(b)
			if _, n := foldHits(b, p, 0); n > anchorCases(p)*len(b) {
				t.Errorf("%q: the search for %q read %d bytes of a %d byte body", unit, p, n, len(b))
			}
		}
		_, ok, work := ts.candidatesWalk(b)
		if !ok {
			t.Fatalf("%q: no prefilter", unit)
		}
		_, first := ts.firstPrefixWork(b, 0)
		t.Logf("%q: candidates read %d, firstPrefixFrom read %d bytes of a %d byte body, limit %d",
			unit, work.searched, first, len(b), lim)
		if work.searched > lim {
			t.Errorf("%q: candidates read %d bytes of a %d byte body, limit %d", unit, work.searched, len(b), lim)
		}
		if first > lim {
			t.Errorf("%q: firstPrefixFrom read %d bytes of a %d byte body, limit %d", unit, first, len(b), lim)
		}
	}
}

// oneCaseBodies are runs of each folded prefix with one case of the
// anchor byte, near misses, and runs that end in a part of a prefix or in
// the other case.
func oneCaseBodies() [][]byte {
	var out [][]byte
	units := []string{"AKIA ", "akia ", "AkIa", "aKiA!", "AIZA ", "aiza-", "ASIA\n", "asIa ", "GHP_ ", "Sk-", "kK", "K", "k", "AKI ", "kia "}
	tails := []string{"", "k", "K", "AKI", "akia", "AKIA", "AKIA" + strings.Repeat("Q", 16), "aiz", "AIZ", "z", "Z", "s", "S"}
	for _, u := range units {
		run := strings.Repeat(u, (4<<10)/len(u))
		for _, tail := range tails {
			out = append(out, []byte(run+tail), []byte(tail+run))
		}
	}
	return out
}

// foldBody is a random body of the folded prefixes, each byte in a random
// case, parts of them, separators and letters of both cases.
func foldBody(rng *rand.Rand, prefixes [][]byte) []byte {
	const letters = "aAkKiIsSzZgGhHpP0189_-xX"
	seps := []string{" ", "_", "-", "\n", "!", "%20", `A`}
	var b []byte
	for range rng.IntN(40) {
		switch rng.IntN(4) {
		case 0, 1:
			p := prefixes[rng.IntN(len(prefixes))]
			if rng.IntN(4) == 0 {
				p = p[:rng.IntN(len(p)+1)]
			}
			for _, c := range p {
				if 'a' <= c && c <= 'z' && rng.IntN(2) == 0 {
					c -= 'a' - 'A'
				}
				b = append(b, c)
			}
		case 2:
			b = append(b, seps[rng.IntN(len(seps))]...)
		default:
			for range 1 + rng.IntN(24) {
				b = append(b, letters[rng.IntN(len(letters))])
			}
		}
	}
	return b
}

// foldNeedles are the folded prefixes of the shipped rules and other
// needles: a single letter, a single byte with no case, a long prefix, and
// one that is not lower case.
func foldNeedles(ts *tokenSet) [][]byte {
	out := slices.Clone(ts.prefixes)
	for _, n := range []string{"akia", "aiza", "asia", "ghp_", "sk-ant-api03-", "_", "k", "z", "kk", "x-0", "AKIA"} {
		out = append(out, []byte(n))
	}
	return out
}

// sameFoldHits fails when foldIndex and indexFoldBefore disagree on the
// hits of needle in b: in a pass from each of a few starts, and at the
// starts of a random walk that goes forward and back.
func sameFoldHits(t *testing.T, rng *rand.Rand, b, needle []byte) {
	t.Helper()
	n := len(needle)
	for _, lo := range []int{0, 1, len(b) / 3, len(b) - n - 1, len(b) - n, len(b) - n + 1, len(b) - 1, len(b)} {
		if lo < 0 || lo > len(b) {
			continue
		}
		got, _ := foldHits(b, needle, lo)
		if want := foldHitsBefore(b, needle, lo); !slices.Equal(got, want) {
			t.Fatalf("%.80q (%d bytes), %q from %d: hits %v, before %v", b, len(b), needle, lo, got, want)
		}
	}
	if len(b) > 4<<10 {
		return
	}
	f := newFoldIndex(b, needle)
	i := 0
	for range 64 {
		switch r := rng.IntN(10); {
		case r < 6:
			i += rng.IntN(6)
		case r < 8:
			i += rng.IntN(64)
		default:
			i -= rng.IntN(i + 1)
		}
		i = min(i, len(b))
		want := indexFoldBefore(b[i:], needle)
		if one := indexFold(b[i:], needle); one != want {
			t.Fatalf("%.80q (%d bytes): indexFold(b[%d:], %q) = %d, before %d", b, len(b), i, needle, one, want)
		}
		if want >= 0 {
			want += i
		}
		if got := f.next(i); got != want {
			t.Fatalf("%.80q (%d bytes), %q: next(%d) = %d, before %d", b, len(b), needle, i, got, want)
		}
	}
}

// foldIndex finds the same hits as the search before it, and
// firstPrefixFrom and candidates give the same results. The bodies are the
// values of the fuzz corpora, the bench bodies, the edge cases at the
// window, runs of one case of each anchor byte that end in a part of a
// prefix, and random bodies of the prefixes in both cases. The rule sets
// are those of skipSets: the shipped rules, which fold, and rules that do
// not fold.
func TestFoldIndexSameAsBefore(t *testing.T) {
	sets := skipSets(t)
	needles := foldNeedles(sets[0])
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
	cut := func(s string) []byte { return []byte(s[:min(len(s), 64<<10)]) }
	bodies = append(bodies,
		cut(benchCleanBody()), cut(benchTokenBody()), cut(benchPrefixNoiseBody()),
		cut(benchPrefixRunBody()), cut(benchPrefixRunsBody()), cut(benchOneCaseBody()))
	bodies = append(bodies, spanEdgeBodies()...)
	extra := oneCaseBodies()
	rng := rand.New(rand.NewPCG(21, 22))
	for range 3000 {
		extra = append(extra, foldBody(rng, needles))
	}
	bodies = append(bodies, extra...)
	for _, b := range bodies {
		for _, n := range needles {
			sameFoldHits(t, rng, b, n)
		}
		for _, ts := range sets {
			for _, lo := range []int{0, len(b) / 2, max(len(b)-window, 0), max(len(b)-1, 0)} {
				if got, want := ts.firstPrefixFrom(b, lo), firstPrefixBefore(ts, b, lo); got != want {
					t.Fatalf("%.80q (%d bytes): firstPrefixFrom(%d) = %d, before %d", b, len(b), lo, got, want)
				}
			}
		}
	}
	// TestCandidatesSameAsEachWalk covers the other bodies.
	for _, b := range extra {
		for _, ts := range sets {
			sameWindows(t, ts, b)
		}
	}
}
