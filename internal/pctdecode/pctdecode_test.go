package pctdecode

import "testing"

func TestOnce(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"/plain":    "/plain",
		"%41":       "A",
		"%4a%4A":    "JJ",
		"%2541":     "%41",
		"%%41":      "%A",
		"%4":        "%4",
		"%":         "%",
		"a%zz%41b%": "a%zzAb%",
		"%G1%1G":    "%G1%1G",
		"%2f%2F":    "//",
		"%00":       "\x00",
		"%ff":       "\xff",
	} {
		if got := Once(in); got != want {
			t.Errorf("Once(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHex(t *testing.T) {
	for c := 0; c < 256; c++ {
		b := byte(c)
		var want int
		switch {
		case b >= '0' && b <= '9':
			want = c - '0'
		case b >= 'a' && b <= 'f':
			want = c - 'a' + 10
		case b >= 'A' && b <= 'F':
			want = c - 'A' + 10
		default:
			want = -1
		}
		if IsHex(b) != (want >= 0) {
			t.Fatalf("IsHex(%q) = %v", b, IsHex(b))
		}
		if want >= 0 && int(Unhex(b)) != want {
			t.Fatalf("Unhex(%q) = %d, want %d", b, Unhex(b), want)
		}
	}
}
