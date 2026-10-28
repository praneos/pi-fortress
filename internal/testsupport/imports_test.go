package testsupport

import "testing"

// The walk must reach what a package imports. If it stopped at the first
// level, each NoImports check in the daemon tests would pass for nothing.
func TestImportParentsReachesTheWholeGraph(t *testing.T) {
	parent, err := importParents(RepoRoot(t), "internal/broker")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pi-fortress/internal/fence",       // direct
		"pi-fortress/internal/secrets",     // direct
		"pi-fortress/internal/tokenrules",  // through the fence
		"golang.org/x/crypto/scrypt",       // vendor, through secrets
		"regexp",                           // standard library
		"pi-fortress/internal/placeholder", // through secrets
	} {
		if _, ok := parent[want]; !ok {
			t.Errorf("the graph of internal/broker lacks %s", want)
		}
	}
	if parent["golang.org/x/crypto/scrypt"] != "pi-fortress/internal/secrets" {
		t.Errorf("scrypt reached through %q", parent["golang.org/x/crypto/scrypt"])
	}
	if parent["pi-fortress/internal/fence"] != "pi-fortress/internal/broker" {
		t.Errorf("fence reached through %q", parent["pi-fortress/internal/fence"])
	}
}
