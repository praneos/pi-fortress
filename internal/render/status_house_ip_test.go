package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// pf status read house.env raw and printed an empty "HOUSE_IP=" on the Pi
// (2026-09-14), while the interface held DefaultHouseIP. status.sh keeps
// its own copy of the fallback. Thus this test guards the two against drift.
func TestStatusFallsBackToDefaultHouseIP(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testsupport.RepoRoot(t), "vm", "pi", "status.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "HOUSE_IP:-"+DefaultHouseIP) {
		t.Fatalf("status.sh does not fall back to %s for HOUSE_IP", DefaultHouseIP)
	}
}
