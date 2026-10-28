package netgate

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// netgate holds CAP_NET_ADMIN, so all of its code must be small enough to
// read in full. Its non-test files import the standard library and these
// small packages of this module, and nothing else: no other module, no
// parser of network bytes. The check follows each package of this module
// that it reaches.
var netgateMayImport = map[string]bool{
	"pi-fortress/internal/gateset": true,
	"pi-fortress/internal/nfq":     true,
}

func TestNetgateImportsOnlyTheStandardLibrary(t *testing.T) {
	root := testsupport.RepoRoot(t)
	seen := map[string]bool{}
	queue := []string{"pi-fortress/internal/netgate"}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		bp, err := build.Default.ImportDir(filepath.Join(root, strings.TrimPrefix(p, "pi-fortress/")), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range bp.Imports {
			if seen[imp] {
				continue
			}
			seen[imp] = true
			switch {
			case strings.HasPrefix(imp, "pi-fortress/"):
				if !netgateMayImport[imp] {
					t.Errorf("%s imports %s", p, imp)
					continue
				}
				queue = append(queue, imp)
			case strings.Contains(strings.SplitN(imp, "/", 2)[0], "."):
				t.Errorf("%s imports %s, a package outside the standard library", p, imp)
			}
		}
	}
}
