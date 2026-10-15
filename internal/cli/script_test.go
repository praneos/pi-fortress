package cli

import "testing"

// pf ship stages a signed release, and applyPF selects the new binary
// from that tree. Before, the new binary then did an exec of the
// *installed* apply.sh: scriptDirs was a fixed global, and nothing looked
// beside the running executable. The apply.sh of the previous generation
// installs its own pf again. Thus it undid the swap: the verified release
// was not the applied release. The search must examine the staged directory first.
func TestScriptsAreLookedForBesideTheRunningBinaryFirst(t *testing.T) {
	got := scriptSearchFrom("/srv/pf-release-9/vm/pi/pf")
	if len(got) != len(scriptDirs)+1 {
		t.Fatalf("search path is %v", got)
	}
	if got[0] != "/srv/pf-release-9/vm/pi" {
		t.Fatalf("the staged tree is not searched first: %v", got)
	}
	for i, want := range scriptDirs {
		if got[i+1] != want {
			t.Fatalf("the installed locations were dropped: %v", got)
		}
	}
}
