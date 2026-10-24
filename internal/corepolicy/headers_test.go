package corepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func headersOf(p *Policy, sni string) map[string][]string {
	out := p.HeadersFor(sni)
	for _, kinds := range out {
		sort.Strings(kinds)
	}
	return out
}

func TestBindingHeadersParse(t *testing.T) {
	p, err := Load(writePolicy(t, "core.hosts", "x.example API_KEY:api-key,X-Goog-Api-Key OTHER\ngitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := headersOf(p, "x.example"), map[string][]string{"api-key": {"API_KEY"}, "x-goog-api-key": {"API_KEY"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("x.example headers %v want %v", got, want)
	}
	if !KindAllowed("API_KEY", p.KindsFor("x.example")) || !KindAllowed("OTHER", p.KindsFor("x.example")) {
		t.Fatalf("kinds %v", p.KindsFor("x.example"))
	}
	if got := headersOf(p, "gitlab.com"); !reflect.DeepEqual(got, map[string][]string{"private-token": {"GITLAB_TOKEN"}}) {
		t.Fatalf("gitlab headers %v", got)
	}
	if got := p.HeadersFor("evil.example"); got != nil {
		t.Fatalf("unlisted host has headers %v", got)
	}
}

// One host and kind on several lines add together. This applies in one
// file or across core.hosts and core.hosts.local. A local line that names
// one kind must not remove the other kinds that the shipped line binds.
func TestBindingsUnionAcrossLinesAndFiles(t *testing.T) {
	p, err := Load(writePolicy(t, "core.hosts", "x.example A:H1\nx.example A:H2 B\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := headersOf(p, "x.example"), map[string][]string{"h1": {"A"}, "h2": {"A"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("headers %v want %v", got, want)
	}
	shipped := writePolicy(t, "core.hosts", "api.anthropic.com CLAUDE_OAT CLAUDE_ORT ANTHROPIC_API_KEY\napi.openai.com OPENAI_API_KEY\n")
	local := writePolicy(t, "core.hosts.local", "api.anthropic.com ANTHROPIC_API_KEY:Api-Key\napi.anthropic.com ANTHROPIC_API_KEY:X-Other\napi.openai.com CANARY\n")
	p, err = LoadFiles(shipped, local, filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"CLAUDE_OAT", "CLAUDE_ORT", "ANTHROPIC_API_KEY"} {
		if !KindAllowed(k, p.KindsFor("api.anthropic.com")) {
			t.Fatalf("the local line dropped %s: %v", k, p.KindsFor("api.anthropic.com"))
		}
	}
	if got, want := headersOf(p, "api.anthropic.com"), map[string][]string{"api-key": {"ANTHROPIC_API_KEY"}, "x-other": {"ANTHROPIC_API_KEY"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("headers %v want %v", got, want)
	}
	if !KindAllowed("OPENAI_API_KEY", p.KindsFor("api.openai.com")) || !KindAllowed(KindCanary, p.KindsFor("api.openai.com")) {
		t.Fatalf("openai kinds %v", p.KindsFor("api.openai.com"))
	}
}

// A header goes with the entry that KindsFor reads. A header declared under
// a wildcard covers the names below it. But a name with its own line gets
// only what that line says.
func TestBindingHeadersFollowTheEntry(t *testing.T) {
	p, err := Load(writePolicy(t, "core.hosts", "*.ex.example A:X-Tok\nb.ex.example A\nother.example A\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := headersOf(p, "a.ex.example"); !reflect.DeepEqual(got, map[string][]string{"x-tok": {"A"}}) {
		t.Fatalf("wildcard headers %v", got)
	}
	for _, sni := range []string{"b.ex.example", "other.example"} {
		if got := p.HeadersFor(sni); len(got) != 0 {
			t.Fatalf("%s got %v", sni, got)
		}
	}
	p, err = Load(writePolicy(t, "core.hosts", "echo.test *:PRIVATE-TOKEN\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := headersOf(p, "echo.test"); !reflect.DeepEqual(got, map[string][]string{"private-token": {AllKinds}}) {
		t.Fatalf("* headers %v", got)
	}
}

// A Host below the SNI takes the line of the SNI. When the Host has a line
// of its own that grants something else, the SNI line must not reach it.
// Otherwise SNI ex.example with Host b.ex.example gets the kinds that the
// line for b.ex.example takes away.
func TestAuthorityHostKeepsItsOwnLine(t *testing.T) {
	p, err := Load(writePolicy(t, "core.hosts", "*.ex.example A:X-Tok\nb.ex.example\nh.ex.example A\nsame.ex.example A:X-Tok\n"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		sni, host string
		ok        bool
	}{
		{"ex.example", "ex.example", true},
		{"ex.example", "c.ex.example", true},
		{"ex.example", "same.ex.example", true},
		{"b.ex.example", "b.ex.example", true},
		{"ex.example", "b.ex.example", false},
		{"ex.example", "B.Ex.Example.:443", false},
		{"ex.example", "h.ex.example", false},
		{"b.ex.example", "x.b.ex.example", false},
	}
	for _, c := range cases {
		if got := p.Authority(c.sni, c.host); got != c.ok {
			t.Errorf("Authority(%q, %q) = %v, want %v", c.sni, c.host, got, c.ok)
		}
	}
}

func TestBindingHeaderDenyList(t *testing.T) {
	for _, h := range []string{
		"User-Agent", "referer", "Origin", "Host", "Via", "Forwarded", "X-Forwarded-For", "x-forwarded-host",
		"X-Real-IP", "Content-Type", "content-length", "Transfer-Encoding", "Connection", "Keep-Alive",
		"Upgrade", "TE", "Te", "Trailer", "Proxy-Authorization", "proxy-connection",
		"Cookie", "cookie", "COOKIE", "Set-Cookie",
	} {
		path := writePolicy(t, "core.hosts", "github.com GITHUB_TOKEN\napi.github.com GITHUB_TOKEN:X-Ok,"+h+"\n")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), path+":2:") || !strings.Contains(err.Error(), h) {
			t.Fatalf("%s: err %v", h, err)
		}
		if ValidHeader(h) == nil {
			t.Fatalf("ValidHeader(%q) passed", h)
		}
	}
	for _, h := range []string{"PRIVATE-TOKEN", "api-key", "x-goog-api-key", "Authorization", "X-Api-Key", "X-Forwarded"} {
		if err := ValidHeader(h); err != nil {
			t.Fatalf("ValidHeader(%q): %v", h, err)
		}
	}
}

func TestBindingHeaderGrammar(t *testing.T) {
	for _, tok := range []string{"A:", "A:x,,y", "A:,x", "A:bad@hdr", "A:a/b", "A:a(b)", "A:é", "A:x;y", "A:x:y", "a_lower:X-Tok", ":X-Tok", "*x:X-Tok"} {
		path := writePolicy(t, "core.hosts", "# header\n\nx.example "+tok+"\n")
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path+":3:") {
			t.Fatalf("%q: err %v", tok, err)
		}
	}
	p, err := Load(writePolicy(t, "core.hosts", "x.example lower notakind A # A:User-Agent in a comment\n"))
	if err != nil {
		t.Fatalf("bare tokens that are not kinds are skipped, as before: %v", err)
	}
	if got := p.KindsFor("x.example"); !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("kinds %v", got)
	}
}

// FuzzLoadBindings: for all core.hosts lines, each header that the policy
// keeps is a lowercase token that is not on the deny-list. It is declared
// for a kind that the same entry binds.
func FuzzLoadBindings(f *testing.F) {
	f.Add("gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\n*.x.example A:h1,H2 B\n")
	f.Add("x.example A:User-Agent\n")
	f.Add("x.example A:,\ny.example *:Cookie # c\n")
	f.Fuzz(func(t *testing.T, body string) {
		path := filepath.Join(t.TempDir(), "core.hosts")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(path)
		if err != nil {
			return
		}
		for _, tables := range []struct {
			kinds   map[string]map[string]struct{}
			headers map[string]map[string]map[string]struct{}
		}{{p.HostKinds, p.HostHeaders}, {p.SuffixKinds, p.SuffixHeaders}} {
			for host, byKind := range tables.headers {
				for kind, hdrs := range byKind {
					if _, ok := tables.kinds[host][kind]; !ok {
						t.Fatalf("%s: header for unbound kind %s", host, kind)
					}
					for h := range hdrs {
						if h != strings.ToLower(h) || ValidHeader(h) != nil {
							t.Fatalf("%s %s kept header %q", host, kind, h)
						}
					}
				}
			}
		}
	})
}
