package fence

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/tokenrules"
)

// fullScan is the token stream without idle and without the record of
// firstHit: it runs the full scan on each read. tokenStream must give the
// same bytes as fullScan at each read. Thus the skip changes the cost of
// a read, and not the output or the time at which a byte leaves.
type fullScan struct {
	httpwire.ScanPump
	ts     *tokenSet
	pad    bool
	outBuf []byte
	pre    int
	cut    bool
	from   int
	hits   map[string]int
	// run and done are as in tokenStream: inside a token longer than
	// maxHold, and the bytes of it that went out.
	run  bool
	done int
}

// part is the replacement of the next k bytes of a token, after done bytes
// of it: one marker at the start, or padRepl of the full token in parts.
func (t *fullScan) part(k int) []byte {
	off := t.done
	t.done += k
	if !t.pad {
		if off == 0 {
			return stripRepl
		}
		return nil
	}
	return padRepl(off + k)[off:]
}

func (t *fullScan) scan() {
	if len(t.Buf) == 0 {
		return
	}
	var out []byte
	if t.run {
		e := t.pre
		for e < len(t.Buf) && inTokenClass(t.Buf[e]) {
			e++
		}
		out = append(t.outBuf[:0], t.part(e-t.pre)...)
		if e == len(t.Buf) && !t.EOF {
			t.commit(out, e, e)
			return
		}
		t.run, t.pre, t.from = false, e, e
	}
	ms := t.ts.matchesFrom(t.Buf, t.from, !t.cut)
	n := len(t.Buf)
	long := -1
	if !t.EOF {
		if !t.ts.complete {
			n = max(n-window, 0)
		} else {
			n -= t.ts.maxPrefix - 1
			if i := t.ts.firstPrefixFrom(t.Buf, max(len(t.Buf)-window, 0)); i >= 0 && i < n {
				n = i
			}
			n = max(n, 0)
		}
		k, end := -1, 0
		for i, m := range ms {
			if lo, hi := t.ts.token(m); lo < n && hi > n {
				n, k, end = lo, i, hi
			}
		}
		// The hold limit: the part of the token before the last tail bytes
		// stays in it, and is longer than maxHold.
		tail := t.ts.minLen + t.ts.maxPrefix + tokenrules.LeadMax + 1
		if k >= 0 && min(end, len(t.Buf)-tail)-n > maxHold {
			long = k
		} else if n <= t.pre {
			t.commit(out, t.pre, t.from)
			return
		}
	}
	pos, end := t.pre, t.from
	for i, m := range ms {
		lo, hi := t.ts.token(m)
		if lo < pos {
			if i != long || hi <= pos {
				continue
			}
			for hi-lo > maxHold && hi < len(t.Buf) && inTokenClass(t.Buf[hi]) {
				hi++
			}
			lo = pos
		}
		if hi > n && i != long {
			break
		}
		if hi-lo > maxHold {
			for hi < len(t.Buf) && inTokenClass(t.Buf[hi]) {
				hi++
			}
		}
		t.done = 0
		out = append(append(out, t.Buf[pos:lo]...), t.part(hi-lo)...)
		pos, end, n = hi, hi, max(n, hi)
		t.hits[t.ts.ruleName(m)]++
		if hi == len(t.Buf) && !t.EOF {
			t.run = true
			break
		}
	}
	n = max(n, pos)
	t.commit(append(out, t.Buf[pos:n]...), n, end)
}

func (t *fullScan) commit(out []byte, n, end int) {
	t.outBuf = out
	t.Out = t.outBuf
	keep := max(n-tokenrules.LeadMax, 0)
	t.Buf = t.Buf[:copy(t.Buf, t.Buf[keep:])]
	t.pre = n - keep
	t.from = max(end-keep, 0)
	t.cut = t.cut || keep > 0
}

// pieces gives b in reads of one byte, and sometimes in a larger read of
// up to big bytes. The first ones bytes come in one read, so that a test
// pays for reads of one byte only where they matter.
type pieces struct {
	b         []byte
	rng       *rand.Rand
	big, ones int
}

func (s *pieces) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	k := 1
	if s.ones > 0 {
		k, s.ones = s.ones, 0
	} else if s.big > 1 && s.rng.IntN(4) == 0 {
		k = 1 + s.rng.IntN(s.big)
	}
	n := copy(p, s.b[:min(k, len(s.b))])
	s.b = s.b[n:]
	return n, nil
}

// sameAsFullScan streams body through tokenStream and fullScan in the same
// reads, and compares the bytes of each read and the strip counts. The
// full scan has no work budget. A stop of the stream at its budget ends
// the comparison: each read before it gave the same bytes.
func sameAsFullScan(t *testing.T, ts *tokenSet, body []byte, seed uint64, big, ones int, pad bool) {
	t.Helper()
	got := newTokenStream(&pieces{b: body, rng: rand.New(rand.NewPCG(seed, 1)), big: big, ones: ones}, ts, pad)
	ref := &fullScan{ts: ts, pad: pad, hits: map[string]int{}}
	ref.Src, ref.Scan = &pieces{b: body, rng: rand.New(rand.NewPCG(seed, 1)), big: big, ones: ones}, ref.scan
	pg, pr := make([]byte, 64<<10), make([]byte, 64<<10)
	for step := 0; ; step++ {
		ng, eg := got.Read(pg)
		if errors.Is(eg, ErrScanBudget) {
			if got.credit >= 0 {
				t.Fatalf("read %d: stop with %d of credit left", step, got.credit)
			}
			return
		}
		nr, er := ref.Read(pr)
		if ng != nr || eg != er || !bytes.Equal(pg[:ng], pr[:nr]) {
			t.Fatalf("read %d: %d bytes, %v; the full scan gave %d bytes, %v", step, ng, eg, nr, er)
		}
		if eg != nil {
			break
		}
	}
	if !maps.Equal(got.hits, ref.hits) {
		t.Fatalf("strips %v; the full scan gave %v", got.hits, ref.hits)
	}
}

// Rule sets for the comparison: the shipped rules, rules with a \b after
// the token, rules that are not bounded, and a rule with no prefix.
func skipSets(t testing.TB) []*tokenSet {
	re, _ := testPolicy(t)
	out := []*tokenSet{tokensFor(re)}
	for _, expr := range []string{
		`(?:\A|[^0-9A-Za-z_])(?P<a>AKIA[A-Z0-9]{16})\b|(?P<b>ab_[a-z]{3})|(?P<c>ghp_[A-Za-z0-9]{8}\b)`,
		`(?P<u>tok-[^ ]{10,})|(?P<v>ghp_[a-z]{4,})`,
		`(?P<x>[a-z]{12}Q)|(?P<y>ghp_[a-z]{6})`,
	} {
		out = append(out, tokensFor(regexp.MustCompile(expr)))
	}
	return out
}

var skipParts = []string{
	"ghp_", "sk-ant-oat01-", "glpat-", "AKIA", "sk-", "xai-", "hf_", "tok-", "ab_",
	" ", "_", "-", ".", "\n", "%20", `\n`, `"`, "AA", "Q", "z9",
}

// skipBody turns fuzz bytes into a body of prefixes, separators and runs.
func skipBody(data []byte) []byte {
	var b bytes.Buffer
	for i := 0; i+1 < len(data); i += 2 {
		c, r := int(data[i]), int(data[i+1])
		if c < 128 {
			b.WriteString(skipParts[c%len(skipParts)])
		} else {
			b.WriteString(strings.Repeat(string("aB7_-Q"[c%6]), 1+r*(c-127)/8))
		}
	}
	return b.Bytes()
}

// The cases where the stream holds bytes across many reads: a token run
// that is still open, a run that ends short, a token that a prefix inside
// it holds, and a run longer than a window. The reads are of one byte
// from just before the point where the output can move.
func TestTokenStreamSameAsFullScan(t *testing.T) {
	ts := skipSets(t)[0]
	for i, c := range []struct {
		body string
		ones int
	}{
		{"hello ghp_" + strings.Repeat("a", 3000) + " and plain words after it", 2900},
		{"x ghp_ab " + strings.Repeat("plain ", 20) + "sk-ant-oat01-" + strings.Repeat("B", 30) + " end", 0},
		{"x ghp_" + strings.Repeat("a", 300) + "ghp_" + strings.Repeat("b", 3900) + " tail", window - 50},
		{"x glpat-" + strings.Repeat("C", window+100) + " y", window - 50},
	} {
		sameAsFullScan(t, ts, []byte(c.body), uint64(i), 0, c.ones, i%2 == 1)
	}
	sets := skipSets(t)
	rng := rand.New(rand.NewPCG(5, 6))
	for i := range 40 {
		data := make([]byte, 2*(1+rng.IntN(12)))
		for j := range data {
			data[j] = byte(rng.IntN(256))
		}
		if body := skipBody(data); len(body) <= 2<<10 {
			sameAsFullScan(t, sets[i%len(sets)], body, uint64(i), rng.IntN(3)*200, 0, i%2 == 0)
		}
	}
}

func FuzzTokenStreamSameAsFullScan(f *testing.F) {
	sets := skipSets(f)
	f.Add(uint8(0), []byte{0, 0, 140, 40, 9, 0, 0, 0, 141, 40}, uint64(1), uint16(0), false)
	f.Add(uint8(1), []byte{3, 0, 135, 60, 9, 0}, uint64(2), uint16(64), true)
	f.Add(uint8(2), []byte{7, 0, 129, 10, 9, 0, 7, 0, 129, 10}, uint64(3), uint16(9), false)
	f.Add(uint8(3), []byte{140, 20, 18, 0, 140, 20}, uint64(4), uint16(0), false)
	f.Fuzz(func(t *testing.T, which uint8, data []byte, seed uint64, big uint16, pad bool) {
		body := skipBody(data)
		if len(body) > 12<<10 {
			return
		}
		sameAsFullScan(t, sets[int(which)%len(sets)], body, seed, int(big), 0, pad)
	})
}

// hit is the ok of span, with a shorter walk.
func TestHitIsTheOkOfSpan(t *testing.T) {
	sets := skipSets(t)
	rng := rand.New(rand.NewPCG(7, 8))
	for i := range 20000 {
		data := make([]byte, 2*(1+rng.IntN(8)))
		for j := range data {
			data[j] = byte(rng.IntN(256))
		}
		b := skipBody(data)
		if len(b) == 0 {
			continue
		}
		ts, s := sets[i%len(sets)], rng.IntN(len(b))
		if _, ok := ts.span(b, s); ts.hit(b, s) != ok {
			t.Fatalf("hit and span disagree at %d of %q", s, b)
		}
	}
}
