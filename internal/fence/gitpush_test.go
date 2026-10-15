package fence

import (
	"net/url"
	"path"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
)

func TestGitPushTarget(t *testing.T) {
	const (
		ambiguous = "?"
		notPush   = ""
	)
	for _, c := range []struct{ method, target, want string }{
		{"POST", "/acme/widget.git/git-receive-pack", "acme/widget"},
		{"POST", "/acme/widget/git-receive-pack", "acme/widget"},
		{"POST", "/Acme/Widget.GIT/git-receive-pack", "acme/widget"},
		{"GET", "/acme/widget.git/info/refs?service=git-receive-pack", "acme/widget"},
		{"GET", "/acme/widget/info/refs?service=GIT-RECEIVE-PACK&x=1", "acme/widget"},
		{"GET", "/acme/widget/info/refs?service=git%2Dreceive%2Dpack", "acme/widget"},
		{"GET", "/acme/widget/info/refs?service=git%252Dreceive-pack", "acme/widget"},
		{"GET", "/acme/widget/info/refs?service=git-upload-pack&service=git-receive-pack", "acme/widget"},
		{"POST", "https://github.com/acme/widget.git/git-receive-pack", "acme/widget"},
		{"POST", "/grp/sub/repo.git/git-receive-pack", "grp/sub/repo"},
		{"PUT", "/acme/widget/git-receive-pack", "acme/widget"},
		{"post", "/acme/widget/git-receive-pack", "acme/widget"},
		{"POST", "/acme/widget.git.git/git-receive-pack", "acme/widget.git"},

		{"GET", "/acme/widget.git/info/refs?service=git-upload-pack", notPush},
		{"POST", "/acme/widget.git/git-upload-pack", notPush},
		{"GET", "/acme/receive-pack/info/refs?service=git-upload-pack", notPush},
		{"POST", "/acme/receive-pack.git/git-upload-pack", ambiguous},
		{"GET", "/docs/git-receive-pack", notPush},
		{"HEAD", "/acme/widget/git-receive-pack", notPush},
		{"GET", "/repos/acme/widget/issues?q=100%25off", notPush},
		{"POST", "/api/graphql", notPush},
		{"GET", "https://receive-pack.example/x", notPush},
		{"GET", "/", notPush},
		{"GET", "", notPush},

		{"POST", "/acme%2Fwidget/git-receive-pack", ambiguous},
		{"POST", "/acme/widget/git%2Dreceive-pack", ambiguous},
		{"POST", "/acme/widget/git%252Dreceive-pack", ambiguous},
		{"POST", "/acme/widget/git-receive-pack/", ambiguous},
		{"POST", "/acme//widget/git-receive-pack", ambiguous},
		{"POST", "//acme/widget/git-receive-pack", ambiguous},
		{"POST", "/acme/./widget/git-receive-pack", ambiguous},
		{"POST", "/other/../acme/widget/git-receive-pack", ambiguous},
		{"POST", "/acme/widget/x/../git-receive-pack", ambiguous},
		{"POST", "/acme/widget/git-receive-pack/.", ambiguous},
		{"POST", "/acme/widget/git-receive-pack;x=1", ambiguous},
		{"POST", "/acme/widget\\git-receive-pack", ambiguous},
		{"POST", "/acme/widget/git-receive-pack.json", ambiguous},
		{"POST", "/git-receive-pack", ambiguous},
		{"POST", "/acme/.git/git-receive-pack", ambiguous},
		{"POST", "/acme/..git/git-receive-pack", ambiguous},
		{"POST", "acme/widget/git-receive-pack", ambiguous},
		{"POST", "ftp://h/acme/widget/git-receive-pack", ambiguous},
		{"POST", "/acme/widget/git-receive-pack#x", ambiguous},
		{"GET", "/acme/widget/info/refs/?service=git-receive-pack", ambiguous},
		{"GET", "/acme/widget/info/./refs?service=git-receive-pack", ambiguous},
		{"GET", "/acme/widget/info/refs%3Fservice=git-receive-pack", ambiguous},
		{"GET", "/acme/widget/info/refs/x/..?service=git-receive-pack", ambiguous},
		{"GET", "/info/refs?service=git-receive-pack", ambiguous},
		{"GET", "/acme/widget/info/refs?service=%25%32%35%32%35%32%35%32%35%32%35", ambiguous},
		{"GET", "/acme/widget/info/refs?q=" + strings.Repeat("%25", 6) + "72eceive-pack", "acme/widget"},
	} {
		repo, push, ok := GitPushTarget(c.method, c.target)
		got := notPush
		switch {
		case push && ok:
			got = repo
		case push:
			got = ambiguous
		}
		if got != c.want || (!ok && repo != "") {
			t.Errorf("%s %q: got %q (push=%v ok=%v repo=%q), want %q", c.method, c.target, got, push, ok, repo, c.want)
		}
	}
}

func testGitPushList(t testing.TB) *corepolicy.GitPush {
	g, err := corepolicy.ParseGitPush(strings.NewReader("github.com acme/widget\ngithub.com team/*\n"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGitPushRefused(t *testing.T) {
	g := testGitPushList(t)
	const push = "/acme/widget.git/git-receive-pack"
	for _, c := range []struct {
		list                      *corepolicy.GitPush
		host, sni, method, target string
		refused                   bool
	}{
		{g, "github.com", "github.com", "POST", push, false},
		{g, "github.com", "", "POST", push, false},
		{g, "github.com", "github.com", "POST", "/team/x/git-receive-pack", false},
		{g, "github.com", "github.com", "POST", "/acme/other/git-receive-pack", true},
		{g, "evil.example", "github.com", "POST", push, true},
		{g, "github.com", "evil.example", "POST", push, true},
		{g, "", "", "POST", push, true},
		{g, "github.com", "github.com", "POST", "/acme//widget/git-receive-pack", true},
		{nil, "github.com", "github.com", "POST", push, true},
		{nil, "github.com", "github.com", "GET", "/acme/widget/info/refs?service=git-receive-pack", true},
		{nil, "github.com", "github.com", "GET", "/acme/widget/info/refs?service=git-upload-pack", false},
		{nil, "github.com", "github.com", "POST", "/acme/widget/git-upload-pack", false},
	} {
		if got, _, _ := GitPushRefused(c.list, c.host, c.sni, c.method, c.target); got != c.refused {
			t.Errorf("%s %s host=%q sni=%q: refused=%v", c.method, c.target, c.host, c.sni, got)
		}
	}
}

// Each request pays for the check. Thus a request that is not a push
// must not allocate.
func TestGitPushNoAllocs(t *testing.T) {
	g := testGitPushList(t)
	for _, target := range []string{
		"/v1/messages",
		"/repos/acme/widget/issues?q=100%25off&x=%41%42",
		"/acme/widget.git/info/refs?service=git-upload-pack",
		"/acme/widget.git/git-upload-pack",
		"/search?q=" + strings.Repeat("receive-pac", 50),
	} {
		n := testing.AllocsPerRun(100, func() {
			_, _, _ = GitPushRefused(g, "github.com", "github.com", "POST", target)
		})
		if n != 0 {
			t.Errorf("%q: %v allocs", target, n)
		}
	}
}

// refGitPush is a reference read of a target: the standard URL parser, one
// percent-decode, and path.Clean. It returns the repo that an origin with
// that normalization would push to, or "" when it sees no push.
func refGitPush(method, target string) string {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return ""
	}
	p := strings.ToLower(path.Clean("/" + u.Path))
	var dir string
	switch {
	case method != "GET" && method != "HEAD" && path.Base(p) == "git-receive-pack":
		dir = path.Dir(p)
	case path.Base(p) == "refs" && path.Base(path.Dir(p)) == "info" && strings.EqualFold(u.Query().Get("service"), "git-receive-pack"):
		dir = path.Dir(path.Dir(p))
	default:
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(dir, "/"), ".git")
}

func FuzzGitPushTarget(f *testing.F) {
	for _, s := range []string{
		"/acme/widget.git/git-receive-pack",
		"/acme/widget.git/info/refs?service=git-receive-pack",
		"/acme/other/git-receive-pack",
		"/acme/other/x/../../widget/git-receive-pack",
		"/acme/widget/../other/git-receive-pack",
		"/acme%2Fother/git-receive-pack",
		"/team/x/../../acme/other/info/refs?service=git-receive-pack",
		"https://github.com/acme/other/git-receive-pack",
		"/acme/other/info/refs?service=git%2Dreceive-pack",
		"/acme/other/info/refs/?service=git-receive-pack",
		"/acme/widget.git/info/refs?service=git-upload-pack",
	} {
		f.Add("POST", s)
		f.Add("GET", s)
	}
	g := testGitPushList(f)
	f.Fuzz(func(t *testing.T, method, target string) {
		refused, repo, clean := GitPushRefused(g, "github.com", "github.com", method, target)
		if refused {
			return
		}
		if clean && !g.Allowed("github.com", repo) {
			t.Fatalf("%s %q: forwarded push to unlisted %q", method, target, repo)
		}
		if ref := refGitPush(method, target); ref != "" && !g.Allowed("github.com", ref) {
			t.Fatalf("%s %q: forwarded, reference reads a push to unlisted %q (fence repo %q)", method, target, ref, repo)
		}
	})
}
