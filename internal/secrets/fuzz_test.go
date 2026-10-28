package secrets

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"pi-fortress/internal/placeholder"
)

var refPlaceholder = regexp.MustCompile(`(?i:pf)_([0-9a-fA-F]{16})_([A-Za-z][A-Za-z0-9_]*)`)

func FuzzFindPlaceholderSpans(f *testing.F) {
	f.Add("pf_a1b2c3d4e5f67890_CLAUDE_OAT")
	f.Add("xpf_A1B2C3D4E5F67890_K;pf_a1b2c3d4e5f67890_Xx pf_")
	f.Fuzz(func(t *testing.T, s string) {
		got := placeholder.FindPlaceholderSpans([]byte(s))
		want := refPlaceholder.FindAllStringIndex(s, -1)
		if len(got) != len(want) {
			t.Fatalf("%q: %v want %v", s, got, want)
		}
		for i := range got {
			if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
				t.Fatalf("%q: %v want %v", s, got, want)
			}
		}
		names := FindPlaceholders(s)
		for i, sp := range got {
			key := PlaceholderKey([]byte(s), sp)
			if key != Placeholder(names[i][0], names[i][1]) {
				t.Fatalf("%q: key %q vs %q", s, key, Placeholder(names[i][0], names[i][1]))
			}
		}
	})
}

func FuzzLoadFile(f *testing.F) {
	f.Add("a1b2c3d4e5f67890_CLAUDE_OAT=sk-ant-oat01-xyz\n# comment\nbad line\n")
	f.Add("A1B2C3D4E5F67890_K=\"quoted\"\nexport X=1\n")
	f.Fuzz(func(t *testing.T, text string) {
		path := filepath.Join(t.TempDir(), "secrets.env")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		m, err := loadFile(path, nil)
		if err != nil {
			return
		}
		for k, sl := range m.slots {
			if strings.ContainsAny(k, "\n\r") || strings.ContainsAny(sl.Live, "\n\r") {
				t.Fatalf("newline leaked into slot %q %+v", k, sl)
			}
		}
	})
}
