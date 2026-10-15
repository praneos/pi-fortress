package corepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

func TestGitPushAllowed(t *testing.T) {
	g, err := ParseGitPush(strings.NewReader(`
# comment
GitHub.com. Acme/Widget.git   # trailing comment
github.com acme/widget
github.com  solo/*
gitlab.com  grp/sub/repo
gitlab.com  grp/team/*
`))
	if err != nil {
		t.Fatal(err)
	}
	if g.Len() != 4 {
		t.Fatalf("len %d", g.Len())
	}
	for _, c := range []struct {
		host, repo string
		want       bool
	}{
		{"github.com", "acme/widget", true},
		{"GITHUB.COM.", "acme/widget", true},
		{"github.com", "acme/other", false},
		{"github.com", "acme/widget/x", false},
		{"api.github.com", "acme/widget", false},
		{"evil.com", "acme/widget", false},
		{"github.com", "solo/anything", true},
		{"github.com", "solo/a/b", false},
		{"github.com", "solo", false},
		{"github.com", "solox/a", false},
		{"gitlab.com", "grp/sub/repo", true},
		{"gitlab.com", "grp/sub", false},
		{"gitlab.com", "grp/team/r", true},
		{"gitlab.com", "grp/team/r/deeper", false},
		{"gitlab.com", "grp/x", false},
		{"", "acme/widget", false},
	} {
		if got := g.Allowed(c.host, c.repo); got != c.want {
			t.Errorf("Allowed(%q, %q) = %v", c.host, c.repo, got)
		}
	}
}

func TestGitPushEmptyDenies(t *testing.T) {
	var nilList *GitPush
	missing, err := LoadGitPush(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatal(err)
	}
	blank, err := ParseGitPush(strings.NewReader("# only comments\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*GitPush{nilList, missing, blank} {
		if g.Allowed("github.com", "acme/widget") || g.Len() != 0 {
			t.Fatal("empty list allowed a push")
		}
	}
}

func TestGitPushRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"github.com",
		"github.com acme",
		"github.com acme/widget extra",
		"github.com /widget",
		"github.com acme/",
		"github.com acme//widget",
		"github.com acme/../widget",
		"github.com ./widget",
		"github.com */widget",
		"github.com acme/*/x",
		"github.com acme/wid*",
		"github.com *",
		"github.com acme/.git",
		"github.com acme/wid%67et",
		"github.com acme/wid\\get",
		"localhost acme/widget",
		"git_hub.com acme/widget",
		"github.com:443 acme/widget",
	} {
		if _, err := ParseGitPush(strings.NewReader(line + "\n")); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
}

// The shipped file parses and allows nothing: default deny.
func TestGitPushShippedFileDenies(t *testing.T) {
	path := filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "git_push.allow")
	if _, err := os.Stat(path); err != nil {
		t.Skip("not shipped yet")
	}
	g, err := LoadGitPush(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Len() != 0 {
		t.Fatalf("shipped git_push.allow has %d entries", g.Len())
	}
}
