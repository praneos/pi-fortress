package corepolicy

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func testForward(t *testing.T, allow, core string) *Forward {
	t.Helper()
	dir := t.TempDir()
	ap := filepath.Join(dir, "allow.domains")
	cp := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(ap, []byte(allow), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(core), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := LoadForward(ap, cp)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestForwardAllowed(t *testing.T) {
	f := testForward(t,
		"github.com\npf-core-echo.test\n# comment\n\n",
		"api.x.ai XAI_API_KEY\n*.example.com CLAUDE_OAT\npf-core-echo.test *\n")
	for _, tc := range []struct {
		name string
		lab  bool
		want bool
	}{
		{"github.com", false, true},
		{"api.github.com", false, true},
		{"deep.api.github.com", false, true},
		{"github.com.evil.example", false, false},
		{"api.x.ai", false, true},
		{"evil.api.x.ai", false, false},
		{"a.example.com", false, true},
		{"example.com", false, false},
		{"nothing.example", false, false},
		{"", false, false},
		{"API.GitHub.com.", false, true},
		{"x..github.com", false, false},
		{".github.com", false, false},
		{"x..a.example.com", false, false},
		{"x..api.x.ai", false, false},
		{OpenEcho, false, true},
		{CoreEcho, false, false},
		{CoreEcho, true, true},
	} {
		if got := f.Allowed(tc.name, tc.lab); got != tc.want {
			t.Errorf("Allowed(%q, lab=%v) = %v", tc.name, tc.lab, got)
		}
	}
	if (*Forward)(nil).Allowed("github.com", true) {
		t.Error("a nil oracle allowed a name")
	}
}

// Armed mode must not read a missing file as an empty list.
func TestLoadForwardRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	ap := filepath.Join(dir, "allow.domains")
	cp := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(ap, []byte("github.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadForward(ap, cp); err == nil {
		t.Fatal("a missing core.hosts was accepted")
	}
	if err := os.WriteFile(cp, []byte("api.x.ai XAI_API_KEY\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ap); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadForward(ap, cp); err == nil {
		t.Fatal("a missing allow.domains was accepted")
	}
}

// An empty allow.domains is acceptable. An empty union refuses all names.
func TestForwardEmptyUnion(t *testing.T) {
	f := testForward(t, "", "api.x.ai XAI_API_KEY\n")
	if !f.Allowed("api.x.ai", false) || f.Allowed("github.com", false) {
		t.Fatal("empty allow.domains did not fall back to core names only")
	}
	empty := testForward(t, "", "")
	if empty.Allowed("github.com", false) || empty.Allowed("api.x.ai", false) {
		t.Fatal("an empty union forwarded a name")
	}
	if !empty.Allowed(OpenEcho, false) {
		t.Fatal("the open echo needs no list")
	}
}

// Names() excludes entries for which Allowed would never see a real query.
// A malformed line does not increase the "paranoid=N" count that pf status
// prints. Its absence from Names() must not widen the oracle either.
// Allowed still refuses names that only such a line could make.
func TestForwardNamesExcludesUnusableNames(t *testing.T) {
	f := testForward(t,
		"github.com\na/b\n\x01evil.com\nlocalhost\nclaude.ai\npf-core-echo.test\n*.*.gitlab.com\n",
		"api.x.ai K\n*.example.com K\nup:port K\n"+strings.Repeat("z", 64)+".com K\npf-open-echo.test *\n")
	want := []string{"api.x.ai", "claude.ai", "example.com", "github.com"}
	if got := f.Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, n := range f.Names() {
		if n == OpenEcho || n == CoreEcho {
			t.Fatalf("echo fixture %q escaped into Names()", n)
		}
	}
	if f.Allowed("b", false) || f.Allowed("evil.com", false) || f.Allowed("port", false) || f.Allowed("a.gitlab.com", false) {
		t.Fatal("a name only a malformed line could have produced was allowed")
	}
}

// A "*.name" line in an allow list is the same as "name": the name and
// all names below it. pf tui writes it as "name". Only one "*." goes, and
// only before a name with a dot. A "*" that is left, or "*.com", allows
// nothing.
func TestAllowStarLineIsTheName(t *testing.T) {
	f := testForward(t, "*.Example.COM.\n*.*.gitlab.com\n*.com\n*\n*.\n", "")
	if got, want := f.Names(), []string{"example.com"}; !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, n := range []string{"example.com", "api.example.com", "a.b.example.com"} {
		if !f.Allowed(n, false) {
			t.Errorf("Allowed(%q) = false", n)
		}
	}
	for _, n := range []string{"evilexample.com", "gitlab.com", "a.gitlab.com", "x.a.gitlab.com", "foo.com", "*.gitlab.com"} {
		if f.Allowed(n, false) {
			t.Errorf("Allowed(%q) = true", n)
		}
	}
}

// A line of one label would allow all names below it: "com" is all of
// .com. Thus such a line allows nothing, also when it is what is left of a
// "*." line ("*.org"). core.hosts refuses a one-label host the same way.
func TestAllowOneLabelLineAllowsNothing(t *testing.T) {
	f := testForward(t, "com\n*.org\nLocalHost.\ngithub.com\n", "")
	if got, want := f.Names(), []string{"github.com"}; !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, n := range []string{"com", "foo.com", "a.b.com", "x.org", "localhost"} {
		if f.Allowed(n, false) {
			t.Errorf("Allowed(%q) = true", n)
		}
	}
	if !f.Allowed("api.github.com", false) {
		t.Fatal("github.com line lost")
	}
}

// The shipped seeds must resolve to a non-empty forward set.
func TestShippedForwardNamesNonEmpty(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "vm", "policy")
	f, err := LoadForward(filepath.Join(root, "allow.domains"), filepath.Join(root, "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Names()) == 0 {
		t.Fatal("the shipped policy upstreams nothing")
	}
}
