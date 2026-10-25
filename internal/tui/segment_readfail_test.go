package tui

import (
	"os"
	"strings"
	"testing"
)

// When Enter cannot read a segment file, there is no current value to
// change from. Before, a change from "" wrote the non-default for each key:
// ADMIN=yes with no confirm, BLOCK_DIRECT_IP=off whatever its value. The
// seat saves nothing, and the read error stays on the screen.
func TestSegmentToggleSavesNothingWhenTheFileCannotBeRead(t *testing.T) {
	for _, key := range []string{"ADMIN", "BLOCK_DIRECT_IP", "PARANOID"} {
		c, path := segSettings(t)
		body := "# the operator's own seat\nIF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nthis line is not a key and a value\n"
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		f := run(t, c, NewFake(120, 48).Type(segmentDown(key)).Press(KeyEnter))
		if got, _ := os.ReadFile(path); string(got) != body {
			t.Fatalf("%s: Enter wrote the file it could not read:\n%s", key, got)
		}
		foot := lastLine(f.Last())
		if !strings.Contains(foot, "error:") || strings.Contains(foot, "saved") {
			t.Fatalf("%s: the read error is not on screen: %q", key, foot)
		}
	}
}
