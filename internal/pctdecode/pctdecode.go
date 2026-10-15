// Package pctdecode decodes the percent escapes of a request target. The
// fence and the DoH check use this one decoder, so that they decode a
// target the same way.
package pctdecode

import "strings"

// Once decodes each valid %XX escape in s one time.
func Once(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		// Keep an invalid escape as written, because a lenient origin
		// server also keeps it. If the code stops decoding the rest of the
		// target because of one stray "%", that makes a bypass possible.
		if s[i] == '%' && i+2 < len(s) && IsHex(s[i+1]) && IsHex(s[i+2]) {
			b = append(b, Unhex(s[i+1])<<4|Unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

// IsHex reports whether c is a hex digit in either case.
func IsHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// Unhex is the value of the hex digit c. c must pass IsHex.
func Unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
