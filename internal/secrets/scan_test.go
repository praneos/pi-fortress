package secrets

import (
	"strings"
	"testing"

	"pi-fortress/internal/placeholder"
)

// refPlaceholder (fuzz_test.go) is the reference: the hand scanner must
// find exactly what the regexp finds, names and byte spans alike.
func TestPlaceholderScanMatchesRegexp(t *testing.T) {
	cases := []string{
		"",
		"pf_",
		"pf_a1b2c3d4e5f67890_CLAUDE_OAT",
		"xpf_A1B2C3D4E5F67890_GITHUB_TOKEN;pf_a1b2c3d4e5f67890_X",
		"pf_a1b2c3d4e5f67890_CLAUDE_OATx",
		"pf_a1b2c3d4e5f67890_lower",
		"pf_a1b2c3d4e5f6789_CLAUDE_OAT",
		"pf_a1b2c3d4e5f67890CLAUDE_OAT",
		"pf_a1b2c3d4e5f67890_A pf_a1b2c3d4e5f67890_B_9",
		"Bearer pf_a1b2c3d4e5f67890_CLAUDE_OAT\r\n",
		"pf_pf_a1b2c3d4e5f67890_K",
		strings.Repeat("pf_a1b2c3d4e5f67890_K", 3),
		"pf_a1b2c3d4e5f67890_K_",
	}
	for _, c := range cases {
		var want [][2]string
		for _, m := range refPlaceholder.FindAllStringSubmatch(c, -1) {
			want = append(want, [2]string{strings.ToLower(m[1]), m[2]})
		}
		got := FindPlaceholders(c)
		if len(got) != len(want) {
			t.Fatalf("%q: got %v want %v", c, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v want %v", c, got, want)
			}
		}
		spans := placeholder.FindPlaceholderSpans([]byte(c))
		idx := refPlaceholder.FindAllStringIndex(c, -1)
		if len(spans) != len(idx) {
			t.Fatalf("%q spans %v want %v", c, spans, idx)
		}
		for i := range spans {
			if spans[i][0] != idx[i][0] || spans[i][1] != idx[i][1] {
				t.Fatalf("%q spans %v want %v", c, spans, idx)
			}
		}
	}
}
