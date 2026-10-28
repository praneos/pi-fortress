package placeholder

import "testing"

// The shared matcher finds a placeholder in any letter case, or with a
// letter added. The hold keeps such a candidate open while the next read
// can still change it.
func TestPlaceholderSpansAndHoldFoldCase(t *testing.T) {
	for _, s := range []string{
		"pf_0123456789abcdef_claude_oat",
		"pf_0123456789abcdef_Claude_Oat",
		"pf_0123456789abcdef_CLAUDE_OATx",
		"PF_0123456789abcdef_CLAUDE_OAT",
		"pF_0123456789ABCDEF_CLAUDE_OAT",
	} {
		in := "a " + s + " b"
		sp := FindPlaceholderSpans([]byte(in))
		if len(sp) != 1 || sp[0] != [2]int{2, 2 + len(s)} {
			t.Errorf("%q: spans %v", in, sp)
		}
		open := "a " + s
		if got := PlaceholderHold([]byte(open)); got != len(s) {
			t.Errorf("%q: hold %d want %d", open, got, len(s))
		}
	}
	for _, tc := range []struct {
		in   string
		hold int
	}{{"abc P", 1}, {"abc pF", 2}, {"abc PF_0123", 7}} {
		if got := PlaceholderHold([]byte(tc.in)); got != tc.hold {
			t.Errorf("%q: hold %d want %d", tc.in, got, tc.hold)
		}
	}
}
