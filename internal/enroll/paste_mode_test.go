package enroll

import (
	"os"
	"path/filepath"
	"testing"
)

// The paste file holds placeholders, and a placeholder is a capability.
// Thus only the owner can read it: a new file, and also a file with the
// same name that an older mint left at 0644.
func TestAgentPasteFileIsOwnerOnly(t *testing.T) {
	kinds := map[string][]string{
		"agent-env.sh":           {"GITHUB_TOKEN"},
		"agent-credentials.json": {"CLAUDE_OAT", "CLAUDE_ORT"},
	}
	for name, k := range kinds {
		for _, old := range []bool{false, true} {
			dest := filepath.Join(t.TempDir(), name)
			if old {
				if err := os.WriteFile(dest, []byte("old\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dest, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteAgentPaste("a1b2c3d4e5f67890", k, dest); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(dest)
			if err != nil {
				t.Fatal(err)
			}
			if perm := st.Mode().Perm(); perm&0077 != 0 {
				t.Errorf("%s (pre-existing %v): mode %04o, want no group or other bits", name, old, perm)
			}
		}
	}
}
