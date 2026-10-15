package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blockedLog returns a path whose parent is a regular file. Thus each
// attempt to create or open it fails, for a reason that does not depend
// on the uid of the test.
func blockedLog(t *testing.T, name string) string {
	t.Helper()
	wall := filepath.Join(t.TempDir(), "wall")
	if err := os.WriteFile(wall, []byte("not a directory\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wall, name)
}

// TestSidecarOnceReportsDrainFailure runs the alert sidecar through the
// entry point that pf itself uses: the argv handler, not a struct built by
// hand. The defect was in the wiring between them. The tail reported the
// drain error to a writer that no caller set. Thus the message left the
// process through os.Stderr, and no writer that pf got saw it. Only an
// assertion on the writer that the CLI got can tell the two apart.
func TestSidecarOnceReportsDrainFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(args []string, stdout, stderr io.Writer) int
		args func(log, state string) []string
	}{
		{
			name: "alert",
			run:  runAlert,
			args: func(log, state string) []string {
				return []string{
					"-strip", log,
					"-offset", filepath.Join(state, "alert.offset"),
					"-last", filepath.Join(state, "alert.last"),
					"-policy", state,
					"once",
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := blockedLog(t, tc.name+".jsonl")
			var stderr bytes.Buffer
			tc.run(tc.args(log, t.TempDir()), io.Discard, &stderr)
			got := stderr.String()
			if !strings.Contains(got, "tail ") || !strings.Contains(got, log) {
				t.Fatalf("pf %s once said nothing about a drain it could not do; stderr = %q", tc.name, got)
			}
		})
	}
}
