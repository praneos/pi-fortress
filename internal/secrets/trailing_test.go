package secrets

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// trailingByRescan is what the stream guard computed before: make the
// prefix shorter, to the start of the last span, while a span ends
// exactly at the cut.
func trailingByRescan(b []byte) int {
	n := len(b)
	for {
		sp := FindPlaceholderSpans(b[:n])
		if len(sp) == 0 || sp[len(sp)-1][1] != n {
			return n
		}
		n = sp[len(sp)-1][0]
	}
}

func TestTrailingPlaceholdersMatchesRescan(t *testing.T) {
	pieces := []string{"pf_", "b0b1b2b3b4b5b6b7", "_", "A", "CLAUDE_OAT", "a", "x", "9", "p", "f", "pf_b0b1b2b3b4b5b6b7_A"}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		for j := rng.IntN(12); j >= 0; j-- {
			sb.WriteString(pieces[rng.IntN(len(pieces))])
		}
		b := []byte(sb.String())
		if got, want := TrailingPlaceholders(b), trailingByRescan(b); got != want {
			t.Fatalf("%q: got %d want %d", b, got, want)
		}
	}
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", 0},
		{"xx", 2},
		{"xx pf_b0b1b2b3b4b5b6b7_A", 3},
		{"xx pf_b0b1b2b3b4b5b6b7_Apf_b0b1b2b3b4b5b6b7_B", 3},
		{"xx pf_b0b1b2b3b4b5b6b7_Ax", 25},
		{"pf_b0b1b2b3b4b5b6b7_", 20},
	} {
		if got := TrailingPlaceholders([]byte(tc.in)); got != tc.want {
			t.Errorf("%q: got %d want %d", tc.in, got, tc.want)
		}
	}
}
