package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// Before, no fixture in this package or in the TUI had a box with a plain
// segment. That is why a front end could carry a list of two segment names
// for so long. The desk here is intentionally neither agent nor house.
func TestSegmentsListsPlainSegmentsAfterAgentAndHouse(t *testing.T) {
	c := testConfig(t)
	dir := filepath.Join(t.TempDir(), "segments.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	c.SegmentsDir = dir
	files := map[string]string{
		// Two good ones, to prove that the order inside segments.d is the order of
		// the file names, not of the directory.
		"desk.env":  "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n",
		"cctv.env":  "IF=eth0.80\nNET=10.80.0.0/24\nIP=10.80.0.1\n",
		"half.env":  "IF=eth0.81\nNET=10.81.0.0/24\n",
		"bad.env":   "IF=eth0.82\nNET=not-a-prefix\nIP=10.82.0.1\n",
		"notes.txt": "NET=10.83.0.0/24\nIP=10.83.0.1\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(t, c.HouseEnv, "HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\n")

	got := c.Segments()
	// Plain says for which of the four a seat can offer an editor. agent
	// belongs to net.env and house belongs to house.env. Neither is a file in
	// segments.d.
	want := []Segment{
		{Name: "agent", Net: "10.77.0.0/24", IP: "10.77.0.1"},
		{Name: "house", Net: "10.78.0.0/24", IP: "10.78.0.1"},
		{Name: "cctv", Net: "10.80.0.0/24", IP: "10.80.0.1", Plain: true},
		{Name: "desk", Net: "10.79.0.0/30", IP: "10.79.0.1", Plain: true},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("segment %d: %+v want %+v", i, got[i], want[i])
		}
	}
}

// No house.env means no house tab. A screen must not offer a segment that
// nothing terminates. Before, the fallback list offered it on all boxes.
func TestSegmentsOmitsAnUnconfiguredHouse(t *testing.T) {
	c := testConfig(t)
	write(t, c.HouseEnv, "")
	got := c.Segments()
	if len(got) != 1 || got[0].Name != "agent" {
		t.Fatalf("%+v", got)
	}
}
