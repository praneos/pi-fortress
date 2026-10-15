// Package docslint holds checks over the prose in docs/: the parts that a
// test run can fail on, so that a reader does not have to see them. It is
// test-only: the shipped binaries do not read the guide.
package docslint

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// inlineLink is the [text](target) form and refDef is the [label]: target
// form. These are the two ways that a Markdown page names a different file.
// The code matches them only outside fenced blocks. A shell transcript in
// the guide has brackets and parentheses that are not links.
var (
	inlineLink = regexp.MustCompile(`!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	refDef     = regexp.MustCompile(`(?m)^\[[^\]\n]+\]:[ \t]+(\S+)`)
)

// TestEveryRelativeLinkInTheUserGuideResolvesToAFileThatExists changes the
// read-and-compare check "user_guide index. Every linked page exists"
// into a check that a run can fail independently.
// It walks each page, not only the README. A page renamed or moved under
// docs/user_guide breaks the sibling that pointed at it. Nobody reads
// all of the guide on a ship to find a link that now goes
// nowhere.
func TestEveryRelativeLinkInTheUserGuideResolvesToAFileThatExists(t *testing.T) {
	dir := filepath.Join(testsupport.RepoRoot(t), "docs", "user_guide")
	pages := guidePages(t, dir)
	// If not, a guide that lost its pages, or a RepoRoot that resolved to
	// a different location, would pass with nothing checked.
	if len(pages) < 2 {
		t.Fatalf("docs/user_guide holds %d .md pages, so there is nothing to cross-check", len(pages))
	}
	checked := 0
	for _, page := range pages {
		b, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		body := withoutFences(string(b))
		var targets []string
		for _, m := range inlineLink.FindAllStringSubmatch(body, -1) {
			targets = append(targets, m[1])
		}
		for _, m := range refDef.FindAllStringSubmatch(body, -1) {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			rel, ok := localPath(target)
			if !ok {
				continue
			}
			checked++
			// Relative to the linking page. A reader and all Markdown
			// renderers follow it this way.
			if _, err := os.Stat(filepath.Join(filepath.Dir(page), rel)); err != nil {
				t.Errorf("docs/user_guide/%s links to %q, which is not on disk: %v", pageName(dir, page), target, err)
			}
		}
	}
	// A second check on the matcher: if a regexp stopped matching,
	// a green run would mean nothing.
	if checked == 0 {
		t.Fatal("no relative links matched anywhere in docs/user_guide, so this test proves nothing")
	}
	t.Logf("%d relative links across %d pages", checked, len(pages))
}

// TestTheUserGuideStaysPublic checks the two invariants for the move of
// docs/user_guide/ to a public site:
//   - Each page in it is public. Thus a link from a page must also resolve
//     inside the directory.
//   - No page can send a public reader to a build target or a path that
//     exists only in a checkout.
func TestTheUserGuideStaysPublic(t *testing.T) {
	dir := filepath.Join(testsupport.RepoRoot(t), "docs", "user_guide")
	pages := guidePages(t, dir)
	if len(pages) < 2 {
		t.Fatalf("docs/user_guide holds %d .md pages, so there is nothing to check", len(pages))
	}
	inlineCode := regexp.MustCompile("`([^`\n]+)`")
	contains := repoInternalRef

	for _, page := range pages {
		b, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		body := string(b)
		name := pageName(dir, page)

		var targets []string
		for _, m := range inlineLink.FindAllStringSubmatch(withoutFences(body), -1) {
			targets = append(targets, m[1])
		}
		for _, m := range refDef.FindAllStringSubmatch(withoutFences(body), -1) {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			rel, ok := localPath(target)
			if !ok {
				continue
			}
			resolved := filepath.Join(filepath.Dir(page), rel)
			outside, err := filepath.Rel(dir, resolved)
			if err != nil || outside == ".." || strings.HasPrefix(outside, ".."+string(filepath.Separator)) {
				t.Errorf("docs/user_guide/%s links to %q, which leaves docs/user_guide", name, target)
			}
		}

		inFence := false
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "```") {
				inFence = !inFence
				continue
			}
			if inFence {
				// A fenced block is a shell transcript here. Check the
				// raw line, not only the text in backticks.
				if bad := contains(line); bad != "" {
					t.Errorf("docs/user_guide/%s runs a repo-internal command %q: %q", name, bad, trimmed)
				}
				continue
			}
			for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
				if bad := contains(m[1]); bad != "" {
					t.Errorf("docs/user_guide/%s names a repo-internal reference %q: %q", name, bad, m[1])
				}
			}
		}
	}
}

// repoInternal is the shape of a reference to a checkout: a build target,
// or a path that a checkout has and a binary-only reader does not have.
var repoInternal = []string{"make ", "vm/", "internal/", "scripts/", ".vagrant"}

// installedPolicyDir is the one absolute path with vm/ in it that a
// binary-only reader has. install.sh unpacks the release under
// /opt/pi-fortress. The operator edits the lists there, also
// core.hosts.local (base.PolicyDir). Only this exact prefix is exempt. A
// bare vm/policy, or any other path under the installed tree, still fails.
const installedPolicyDir = "/opt/pi-fortress/vm/policy/"

// repoInternalRef is the first repo-internal marker in s, or "".
func repoInternalRef(s string) string {
	s = strings.ReplaceAll(s, installedPolicyDir, "/")
	for _, bad := range repoInternal {
		if strings.Contains(s, bad) {
			return bad
		}
	}
	return ""
}

func TestOnlyTheInstalledPolicyDirIsExemptFromTheCheckoutPathBan(t *testing.T) {
	for in, want := range map[string]string{
		"/opt/pi-fortress/vm/policy/core.hosts.local": "",
		"/opt/pi-fortress/vm/policy/":                 "",
		"vm/policy/core.hosts.local":                  "vm/",
		"/opt/pi-fortress/vm/pi/net.env":              "vm/",
		"/opt/pi-fortress/vm/policy":                  "vm/",
		"/opt/pi-fortress/vm/policy/x vm/pi/apply.sh": "vm/",
	} {
		if got := repoInternalRef(in); got != want {
			t.Errorf("repoInternalRef(%q) = %q, want %q", in, got, want)
		}
	}
}

// guidePages is each .md page under dir, at all depths. The tutorials
// are in a subdirectory and are as public as the pages beside them.
func guidePages(t *testing.T, dir string) []string {
	t.Helper()
	var pages []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			pages = append(pages, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

// pageName is page relative to the guide. Thus a report names
// tutorials/README.md and not a bare README.md.
func pageName(dir, page string) string {
	if rel, err := filepath.Rel(dir, page); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(page)
}

// localPath is target as a path on disk relative to the page that wrote
// it. It is false for the links that a checkout cannot check: a different
// scheme (http, https, mailto), a protocol-relative or site-absolute URL,
// and a bare fragment or query for the same page.
func localPath(target string) (string, bool) {
	if i := strings.IndexAny(target, "#?"); i >= 0 {
		target = target[:i]
	}
	if target == "" || strings.HasPrefix(target, "/") {
		return "", false
	}
	// A scheme is a colon with no slash or dot before it. "./a.md" and
	// "a.b:c" are paths. "mailto:x" is not.
	if i := strings.IndexByte(target, ':'); i >= 0 && !strings.ContainsAny(target[:i], "/.") {
		return "", false
	}
	return filepath.FromSlash(target), true
}

// withoutFences removes ``` blocks. The guide is mostly shell transcripts.
// Their output has brackets and parentheses that would read as links. Then
// a run would fail on a line that no reader can click.
func withoutFences(s string) string {
	var b strings.Builder
	in := false
	for line := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			in = !in
			continue
		}
		if !in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// The walk must get to the tutorials. A glob of only the top level
// left all pages under docs/user_guide/tutorials unchecked.
func TestGuidePagesReachTheTutorials(t *testing.T) {
	dir := filepath.Join(testsupport.RepoRoot(t), "docs", "user_guide")
	sub := 0
	for _, p := range guidePages(t, dir) {
		if strings.Contains(pageName(dir, p), "/") {
			sub++
		}
	}
	if sub == 0 {
		t.Fatal("no page below the top of docs/user_guide was found")
	}
}
