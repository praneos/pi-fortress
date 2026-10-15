package render

import (
	"os"
	"path/filepath"
	"testing"
)

// segGoldenDir is the two plain segments that the goldens were rendered
// from before PARANOID existed: a desk with ADMIN and SSH_TO, and a guest
// with its gate off. Neither sets PARANOID, so neither can change.
func segGoldenDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, segs, "desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nADMIN=yes\nSSH_TO=10.77.0.10-10.77.0.12\n")
	write(t, segs, "guest.env", "IF=eth2\nNET=10.80.0.0/24\nIP=10.80.0.1\nBLOCK_DIRECT_IP=off\n")
	return segs
}

func TestNonParanoidSegmentsMatchGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/nft.segments.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := load(t, Options{Net: lab, SegmentsDir: segGoldenDir(t)}).Ruleset(labElements); got != string(want) {
		t.Fatalf("a segment without PARANOID drifted from testdata/nft.segments.golden:\n%s", got)
	}
}
