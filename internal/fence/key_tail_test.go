package fence

import (
	"bytes"
	"io"
	"math/rand/v2"
	"strconv"
	"testing"
)

// tokenSet.span stops a match at window bytes after its prefix. A real
// key is much shorter. A key of real length with a run of 5000 token bytes
// glued after it is stripped from its first byte to past its last byte,
// on the buffered path and on the stream, for each rule. The key lengths
// are the minimum of the rule and 512 bytes more. No issuer of these kinds
// makes a longer key. The tail continues the alphabet of the key, or mixes
// all token bytes. After the tail comes nothing, "AA", or an underscore
// and a run, because some rules need such bytes after the body.
func TestRealKeyBeforeLongTailIsStripped(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	ts := tokensFor(ctx.TokenRE)
	rng := rand.New(rand.NewPCG(15, 16))
	mixed := alnumUD + "."
	for _, s := range keyShapes() {
		var own []byte
		for _, c := range []byte(s.make(0)[len(s.make(0))-16:]) {
			if !bytes.ContainsRune(own, rune(c)) {
				own = append(own, c)
			}
		}
		for i, v := range []struct {
			extra      int
			alpha, end string
		}{
			{0, string(own), ""}, {512, string(own), ""}, {0, mixed, ""}, {512, mixed, ""},
			{0, mixed, "AA"}, {0, mixed, "_" + fill(alnum, 60)},
		} {
			key := s.make(v.extra)
			body := []byte("x " + key + fill(v.alpha, 5000) + v.end + " y")
			name := s.rule + "/" + strconv.Itoa(i)
			ms := ts.matches(body)
			if len(ms) == 0 {
				t.Fatalf("%s: no match", name)
			}
			if lo, hi := ts.token(ms[0]); lo != 2 || hi < 2+len(key) {
				t.Fatalf("%s: strip [%d,%d), key [2,%d)", name, lo, hi, 2+len(key))
			}
			want, pos := []byte{}, 0
			for _, m := range ms {
				lo, hi := ts.token(m)
				want = append(append(want, body[pos:lo]...), stripRepl...)
				pos = hi
			}
			want = append(want, body[pos:]...)
			var sizes []int
			for k := 0; k < len(body); k += sizes[len(sizes)-1] {
				sizes = append(sizes, 1+rng.IntN(1+rng.IntN(600)))
			}
			got, err := io.ReadAll(newTokenStream(&chunkReader{src: body, sizes: sizes}, ts, false))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: stream %.40q, buffered %.40q", name, got, want)
			}
			if i > 0 {
				continue
			}
			fwant, fgot, werr, gerr := bothPaths(t, ctx, pol, string(body), rng)
			if werr != nil || gerr != nil {
				t.Fatalf("%s: %v / %v", name, werr, gerr)
			}
			if !bytes.Equal(fgot, fwant) || !bytes.HasPrefix(fwant, []byte("x "+StripRepl)) {
				t.Fatalf("%s: fence buffered %.40q, stream %.40q", name, fwant, fgot)
			}
		}
	}
}
