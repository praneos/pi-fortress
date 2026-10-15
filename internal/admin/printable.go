package admin

import "strings"

// Printable is s with each rune outside printable ASCII changed to '?'.
// It is for text that a device or an agent chose (a DNS name, a lease
// hostname, a ledger IP) on its way to the terminal of the operator. A C1
// CSI or OSC would control the terminal. A bidi override would change the
// order of the row. A wide or zero-width rune would break the column
// layout. Legitimate names are ASCII or punycode, so they pass unchanged.
func Printable(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
