package httpwire

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
	"time"
)

func TestReplaceAll(t *testing.T) {
	pairs := [][2][]byte{{[]byte("abc"), []byte("X")}, {[]byte("bcd"), []byte("YY")}, {[]byte("cd"), []byte("")}}
	counts := make([]int, 3)
	got := ReplaceAll(nil, []byte("abcd bcd cd abcabc zz"), pairs, counts)
	// "abcd": abc wins at 0. bcd starts inside it and runs one byte past, so
	// it covers the d and does not let it through.
	if string(got) != "XYY YY  XX zz" {
		t.Fatalf("%q", got)
	}
	if counts[0] != 3 || counts[1] != 2 || counts[2] != 1 {
		t.Fatal(counts)
	}
	if string(ReplaceAll(nil, []byte("plain"), pairs, nil)) != "plain" {
		t.Fatal("no-match changed input")
	}
	if string(ReplaceAll(nil, []byte("plain"), [][2][]byte{{nil, []byte("x")}}, nil)) != "plain" {
		t.Fatal("empty pattern must be ignored")
	}
}

type randReader struct {
	r   *bytes.Reader
	rnd *rand.Rand
}

func (rr *randReader) Read(p []byte) (int, error) {
	n := rr.rnd.Intn(len(p)) + 1
	return rr.r.Read(p[:n])
}

func TestScrubberMatchesReplaceAll(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	pairs := [][2][]byte{{[]byte("SECRET-ONE-VALUE"), []byte("r1")}, {[]byte("S2"), []byte("replacement-two")}, {[]byte("ONE"), []byte("!")}}
	alphabet := []string{"a", "b", " ", "S", "SECRET-ONE-VALUE", "S2", "ONE", "SEC", "-"}
	for round := 0; round < 200; round++ {
		var sb bytes.Buffer
		for sb.Len() < 3000 {
			sb.WriteString(alphabet[rnd.Intn(len(alphabet))])
		}
		in := sb.Bytes()
		want := ReplaceAll(nil, in, pairs, nil)
		sc := NewScrubber(&randReader{r: bytes.NewReader(in), rnd: rnd}, pairs)
		got, err := io.ReadAll(sc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d:\n got %q\nwant %q", round, got, want)
		}
	}
}

func TestIndexLongNeedle(t *testing.T) {
	needle := []byte("sk-ant-oat01-" + string(bytes.Repeat([]byte("A"), 64)))
	almost := append([]byte(nil), needle...)
	almost[len(almost)-1] = 'B'
	src := append(append(append([]byte("ssss s sk-ant-oat01-AAAA "), almost...), []byte(" mid ")...), needle...)
	if got, want := Index(src, needle), bytes.Index(src, needle); got != want {
		t.Fatalf("got %d want %d", got, want)
	}
	if Index([]byte("short"), needle) != -1 || Index(nil, needle) != -1 {
		t.Fatal("short haystack")
	}
	if Index([]byte("abc"), []byte("b")) != 1 {
		t.Fatal("short needle path")
	}
}

func TestIndexMatchesBytesIndex(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	alphabet := []byte("ssssaaaeeetttnnn -_kzQ\"{},:0123")
	for round := 0; round < 3000; round++ {
		src := make([]byte, rnd.Intn(400))
		for i := range src {
			src[i] = alphabet[rnd.Intn(len(alphabet))]
		}
		n := rnd.Intn(12) + 1
		var needle []byte
		if len(src) >= n && rnd.Intn(2) == 0 {
			start := rnd.Intn(len(src) - n + 1)
			needle = append([]byte(nil), src[start:start+n]...)
		} else {
			needle = make([]byte, n)
			for i := range needle {
				needle[i] = alphabet[rnd.Intn(len(alphabet))]
			}
		}
		if got, want := Index(src, needle), bytes.Index(src, needle); got != want {
			t.Fatalf("round %d: Index(%q, %q) = %d, bytes.Index = %d", round, src, needle, got, want)
		}
	}
}

// A server-sent event must reach the reader immediately when its tail
// cannot be the start of any secret.
func TestScrubberDoesNotDelaySmallEvents(t *testing.T) {
	pr, pw := io.Pipe()
	pairs := [][2][]byte{{[]byte("sk-ant-oat01-" + string(bytes.Repeat([]byte("A"), 64))), []byte("x")}}
	sc := NewScrubber(pr, pairs)
	go func() {
		_, _ = pw.Write([]byte("data: {\"delta\":\"hello\"}\n\n"))
	}()
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, _ := sc.Read(buf)
		done <- buf[:n]
	}()
	select {
	case got := <-done:
		if string(got) != "data: {\"delta\":\"hello\"}\n\n" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event held back waiting for more data")
	}
	go func() {
		_, _ = pw.Write([]byte("tail sk-ant-oat01-AAA"))
		_, _ = pw.Write([]byte(string(bytes.Repeat([]byte("A"), 61)) + " end"))
		_ = pw.Close()
	}()
	rest, err := io.ReadAll(sc)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "tail x end" {
		t.Fatalf("straddled secret not scrubbed: %q", rest)
	}
}

// Which of two overlapping live values wins must not depend on pairs
// order (map order upstream). Neither may leave bytes of the other in the
// clear.
func TestOverlappingValuesLeaveNothing(t *testing.T) {
	short, long := []byte("sk-live-1"), []byte("sk-live-1234567890")
	for _, tc := range []struct{ name, src, want string }{
		{"prefix", "a=sk-live-1234567890;", "a=[L];"},
		{"prefix, short alone", "a=sk-live-1;", "a=[S];"},
		{"head inside the short one", "xsk-live-1234567890", "x[L]"},
	} {
		for _, pairs := range [][][2][]byte{
			{{short, []byte("[S]")}, {long, []byte("[L]")}},
			{{long, []byte("[L]")}, {short, []byte("[S]")}},
		} {
			if got := string(ReplaceAll(nil, []byte(tc.src), pairs, nil)); got != tc.want {
				t.Errorf("%s: %q -> %q, want %q", tc.name, tc.src, got, tc.want)
			}
		}
	}
	// A value whose head is inside an earlier, different value: the tail is
	// covered. With length-preserving replacements the length stays the
	// same, so a streamed Content-Length still holds.
	a, b := []byte("AAAAxyz"), []byte("xyzBBBB")
	pad := func(n int) []byte { return bytes.Repeat([]byte("*"), n) }
	src := []byte("<AAAAxyzBBBB>")
	got := ReplaceAll(nil, src, [][2][]byte{{a, pad(len(a))}, {b, pad(len(b))}}, nil)
	if string(got) != "<***********>" {
		t.Errorf("chained overlap: %q", got)
	}
	// In one-byte reads, the chain still resolves. An overlap that might run
	// past the read is carried, not decided early.
	sc := NewScrubber(&randReader{bytes.NewReader(src), rand.New(rand.NewSource(1))}, [][2][]byte{{a, pad(len(a))}, {b, pad(len(b))}})
	streamed, err := io.ReadAll(sc)
	if err != nil || string(streamed) != "<***********>" {
		t.Errorf("streamed chained overlap: %q %v", streamed, err)
	}
}
