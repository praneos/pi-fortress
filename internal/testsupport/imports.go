package testsupport

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "pi-fortress"

// importParents walks the imports of the non-test files of pkg (a path
// from the root of the checkout, for example "internal/dnsd"). It follows
// each import of this module into the checkout with go/build, and it
// records any other path (standard library, vendor) without it descending.
// The map gives, for each path that it reached, the package that first
// imported it. The start package maps to "". It needs no go tool.
func importParents(root, pkg string) (map[string]string, error) {
	start := modulePath + "/" + pkg
	parent := map[string]string{start: ""}
	for queue := []string{start}; len(queue) > 0; queue = queue[1:] {
		p := queue[0]
		if !strings.HasPrefix(p, modulePath+"/") {
			continue
		}
		bp, err := build.Default.ImportDir(filepath.Join(root, strings.TrimPrefix(p, modulePath+"/")), 0)
		if err != nil {
			return nil, err
		}
		for _, imp := range bp.Imports {
			if _, seen := parent[imp]; !seen {
				parent[imp] = p
				queue = append(queue, imp)
			}
		}
	}
	return parent, nil
}

// NoImports fails the test if pkg (see importParents) imports one of
// banned, directly or through another package of this module. A banned
// path is a package of this module ("pi-fortress/internal/fence") or any
// other import path ("golang.org/x/crypto/scrypt"). Each failure shows the
// chain of imports that leads to the banned path. The check reads the
// source of the checkout, so a test that runs from another tree sees that
// tree.
func NoImports(t *testing.T, pkg string, banned ...string) {
	t.Helper()
	parent, err := importParents(RepoRoot(t), pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range banned {
		if _, ok := parent[b]; !ok {
			continue
		}
		var chain []string
		for p := b; p != ""; p = parent[p] {
			chain = append([]string{p}, chain...)
		}
		t.Errorf("%s imports %s: %s", pkg, b, strings.Join(chain, " -> "))
	}
}
