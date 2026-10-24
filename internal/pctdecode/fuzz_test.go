package pctdecode

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// FuzzOnce: Once never panics, and its output is never longer than its
// input. Each valid escape becomes its one byte; all other bytes stay as
// written. Thus a string with no valid escape comes back unchanged, and
// each round that changes a string makes it at least two bytes shorter.
// A string with each "%" (and any other byte) encoded decodes back to
// itself in one round.
func FuzzOnce(f *testing.F) {
	for _, s := range []string{"", "/plain", "%41", "%4a%4A", "%2541", "%%41", "%4", "%", "a%zz%41b%", "%G1%1G", "%2f%2F", "%00", "%ff", "%252525"} {
		f.Add(s, []byte{0x0f})
	}
	f.Fuzz(func(t *testing.T, s string, mask []byte) {
		got := Once(s)
		if len(got) > len(s) {
			t.Fatalf("Once(%q) = %q is longer", s, got)
		}
		if want := naiveOnce(s); got != want {
			t.Fatalf("Once(%q) = %q, want %q", s, got, want)
		}
		if got != s && len(got) > len(s)-2 {
			t.Fatalf("Once(%q) = %q changed it but is not 2 bytes shorter", s, got)
		}
		if enc := encodeSome(s, mask); Once(enc) != s {
			t.Fatalf("Once(%q) = %q, want %q", enc, Once(enc), s)
		}
	})
}

// naiveOnce is the contract: a valid escape is "%" and two hex digits.
func naiveOnce(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if c, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(c))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// encodeSome percent-encodes each "%" in s, and each byte i where bit i%8
// of mask[i/8%len(mask)] is set. Hex digits alternate between cases.
func encodeSome(s string, mask []byte) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || len(mask) > 0 && mask[i/8%len(mask)]>>(i%8)&1 == 1 {
			if i%2 == 0 {
				fmt.Fprintf(&b, "%%%02x", c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
