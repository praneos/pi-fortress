package httpwire

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// Push gets a stream in any pieces and is told where it ends. It writes
// what ReplaceAll writes over the whole stream, and starts clean on the
// next stream.
func TestScrubberPushMatchesReplaceAll(t *testing.T) {
	pairs := [][2][]byte{{[]byte("sk-live-0123456789"), []byte("pf_x")}, {[]byte("ghp_abc"), []byte("pf_yyyyyyyyyy")}}
	rng := rand.New(rand.NewPCG(3, 4))
	alpha := []string{"sk-live-0123456789", "ghp_abc", "sk-", "ghp_", "x", "0", " "}
	sc := NewScrubber(nil, pairs)
	for i := 0; i < 3000; i++ {
		var src []byte
		for j := rng.IntN(10); j >= 0; j-- {
			src = append(src, alpha[rng.IntN(len(alpha))]...)
		}
		want := ReplaceAll(nil, src, pairs, nil)
		var got []byte
		for rest, done := src, false; !done; {
			n := rng.IntN(len(rest) + 1)
			done = n == len(rest)
			got = sc.Push(got, rest[:n], done)
			rest = rest[n:]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%q: got %q want %q", src, got, want)
		}
	}
}
