package httpwire

import (
	"strings"
	"testing"
)

func TestASCIIEqualFoldMatchesLowerForASCII(t *testing.T) {
	for x := 0; x < 128; x++ {
		for y := 0; y < 128; y++ {
			a, b := string(rune(x)), string(rune(y))
			if got, want := asciiEqualFold(a, b), strings.ToLower(a) == strings.ToLower(b); got != want {
				t.Fatalf("asciiEqualFold(%q, %q) = %v, want %v", a, b, got, want)
			}
		}
	}
	for _, c := range [][2]string{{"Content-Length", "content-length"}, {"HOST", "host"}, {"Host", "Hosts"}, {"", ""}, {"X-A", "X-B"}} {
		if got, want := asciiEqualFold(c[0], c[1]), strings.ToLower(c[0]) == strings.ToLower(c[1]); got != want {
			t.Fatalf("asciiEqualFold(%q, %q) = %v, want %v", c[0], c[1], got, want)
		}
	}
}

func TestASCIIEqualFoldDoesNotFoldUnicode(t *testing.T) {
	for _, c := range [][2]string{{"Keep-Alive", "Keep-Alive"}, {"Tranſfer-Encoding", "Transfer-Encoding"}} {
		if asciiEqualFold(c[0], c[1]) {
			t.Fatalf("asciiEqualFold(%q, %q) = true", c[0], c[1])
		}
	}
}

func FuzzASCIIEqualFold(f *testing.F) {
	f.Add("Content-Length", "content-length")
	f.Add("Host", "HOST")
	f.Fuzz(func(t *testing.T, a, b string) {
		if !isASCII(a) || !isASCII(b) {
			return
		}
		if got, want := asciiEqualFold(a, b), strings.ToLower(a) == strings.ToLower(b); got != want {
			t.Fatalf("asciiEqualFold(%q, %q) = %v, want %v", a, b, got, want)
		}
	})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
