package httpwire

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func scrubInput(n int, live string) []byte {
	var sb strings.Builder
	for sb.Len() < n-200 {
		sb.WriteString(`{"id":"01234567","text":"ordinary response content with nothing secret in it at all"},`)
	}
	sb.WriteString(`{"leak":"` + live + `"}`)
	return []byte(sb.String())
}

func scrubPairs8() [][2][]byte {
	var pairs [][2][]byte
	for i := 0; i < 8; i++ {
		live := "sk-ant-oat01-" + strings.Repeat(string(rune('A'+i)), 64)
		pairs = append(pairs, [2][]byte{[]byte(live), []byte("pf_0000000000000000_CLAUDE_OAT")})
	}
	return pairs
}

func BenchmarkScrubber1M(b *testing.B) {
	pairs := scrubPairs8()
	in := scrubInput(1<<20, string(pairs[3][0]))
	b.ReportAllocs()
	b.SetBytes(int64(len(in)))
	for b.Loop() {
		s := NewScrubber(bytes.NewReader(in), pairs)
		if _, err := io.Copy(io.Discard, s); err != nil {
			b.Fatal(err)
		}
		if s.Counts[3] != 1 {
			b.Fatal(s.Counts)
		}
	}
}

// scrubPairsRandom is n enrolled values with the shape of real OAuth
// tokens: random letters and digits. Thus no two share more than a chance
// byte.
func scrubPairsRandom(n int) [][2][]byte {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	seed := uint32(1)
	var pairs [][2][]byte
	for range n {
		body := make([]byte, 95)
		for j := range body {
			seed = seed*1664525 + 1013904223
			body[j] = alnum[seed>>24%uint32(len(alnum))]
		}
		pairs = append(pairs, [2][]byte{append([]byte("sk-ant-oat01-"), body...), []byte("pf_0000000000000000_CLAUDE_OAT")})
	}
	return pairs
}

// scrubDense is about n bytes of JSON in which each record carries one of
// the live values, in turn. This is the worst ordinary case for the
// per-hit overlap check.
func scrubDense(n int, pairs [][2][]byte) []byte {
	var sb strings.Builder
	for i := 0; sb.Len() < n; i++ {
		sb.WriteString(`{"id":"01234567","token":"` + string(pairs[i%len(pairs)][0]) + `"},`)
	}
	return []byte(sb.String())
}

// BenchmarkScrubberDense measures a body full of hits.
// BenchmarkScrubber1M does not. BenchmarkScrubberDense uses random values,
// as real keys are, and the repeated-letter fixtures. Each repeated-letter
// fixture overlaps itself at every offset. cover (replace.go) is for that
// case.
func BenchmarkScrubberDense(b *testing.B) {
	for _, tc := range []struct {
		name  string
		pairs [][2][]byte
	}{
		{"random8", scrubPairsRandom(8)},
		{"random64", scrubPairsRandom(64)},
		{"selfoverlap8", scrubPairs8()},
	} {
		b.Run(tc.name, func(b *testing.B) {
			in := scrubDense(1<<20, tc.pairs)
			b.ReportAllocs()
			b.SetBytes(int64(len(in)))
			for b.Loop() {
				s := NewScrubber(bytes.NewReader(in), tc.pairs)
				n, err := io.Copy(io.Discard, s)
				if err != nil {
					b.Fatal(err)
				}
				hits := 0
				for _, c := range s.Counts {
					hits += c
				}
				if hits == 0 || n == 0 {
					b.Fatal("nothing scrubbed")
				}
			}
		})
	}
}

// BenchmarkChunkedRead measures the decode of a body in many small
// chunks, with an extension on each size line and a trailer block.
func BenchmarkChunkedRead(b *testing.B) {
	var sb strings.Builder
	chunk := strings.Repeat("x", 256)
	for range 1024 {
		sb.WriteString("100;ext=1\r\n" + chunk + "\r\n")
	}
	sb.WriteString("0\r\nX-Trailer-A: one\r\nX-Trailer-B: two\r\n\r\n")
	in := []byte(sb.String())
	buf := make([]byte, 4096)
	br := bufio.NewReader(nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(in)))
	for b.Loop() {
		br.Reset(bytes.NewReader(in))
		r := newChunkedReader(br)
		n := 0
		for {
			m, err := r.Read(buf)
			n += m
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
		if n != 1024*256 {
			b.Fatal(n)
		}
	}
}
