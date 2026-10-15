package fence

import (
	"bytes"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
)

func realTokens(t testing.TB) *tokenSet {
	tr, err := LoadTokenRules(filepath.Join("..", "..", "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	ts := tokensFor(tr.All())
	if ts == nil {
		t.Fatal("no tokenSet")
	}
	return ts
}

// body is plausible proxied traffic: JSON-ish ASCII, no secret.
func body(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	const al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 {}\":,._-/\n"
	b := make([]byte, n)
	for i := range b {
		b[i] = al[r.Intn(len(al))]
	}
	return b
}

func BenchmarkPrefilterMatch(b *testing.B) {
	ts := realTokens(b)
	for _, n := range []int{4 << 10, 64 << 10, 1 << 20} {
		buf := body(n, 1)
		b.Run(fmt.Sprintf("clean/%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				if ts.match(buf) {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}

// hit is the same body with a real token near the end. The prefilter
// still scans all of it, then the NFA runs in one window.
func BenchmarkPrefilterMatchHit(b *testing.B) {
	ts := realTokens(b)
	for _, n := range []int{64 << 10, 1 << 20} {
		buf := body(n, 2)
		tok := []byte("ghp_" + string(bytes.Repeat([]byte("a"), 36)))
		copy(buf[n-len(tok)-8:], tok)
		b.Run(fmt.Sprintf("hit/%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				ts.match(buf)
			}
		})
	}
}

// decoy bodies carry many prefix hits that cannot complete. The
// bounded/minLen guard exists to make this case cheap.
func BenchmarkPrefilterDecoy(b *testing.B) {
	ts := realTokens(b)
	n := 64 << 10
	buf := body(n, 3)
	for i := 0; i+8 < n; i += 64 {
		copy(buf[i:], []byte("ghp_!"))
	}
	b.SetBytes(int64(n))
	b.ReportAllocs()
	for b.Loop() {
		ts.match(buf)
	}
}

// BenchmarkRawScanCost is the floor: one pass of the tuned substring
// search over the same body. match() cannot beat this times one.
func BenchmarkRawScanCost(b *testing.B) {
	buf := body(64<<10, 1)
	needle := []byte("ghp_")
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		if bytes.Index(buf, needle) >= 0 {
			b.Fatal("no")
		}
	}
}

// FuzzPrefilterMatch covers the bool on the hot path (tokenSet.match in
// scanner.classify).
// FuzzTokenWindows pins matches and replace. match walks the same candidate
// windows but returns on the first hit. Thus it needs its own proof that
// the prefilter only saves work.
func FuzzPrefilterMatch(f *testing.F) {
	for _, s := range []string{
		"ghp_" + string(bytes.Repeat([]byte("A"), 36)),
		"ghp_short", "AKIA!", "", "sk-ant-oat01-" + string(bytes.Repeat([]byte("z"), 25)),
	} {
		f.Add(s)
	}
	ts := realTokens(f)
	f.Fuzz(func(t *testing.T, s string) {
		b := []byte(s)
		if got, want := ts.match(b), ts.re.Match(b); got != want {
			t.Fatalf("%q: match=%v regexp=%v", s, got, want)
		}
	})
}
