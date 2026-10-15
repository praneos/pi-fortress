package corepolicy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func policyPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "vm", "policy", "core.hosts"))
}

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Load(policyPath(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasKind(kinds []string, want string) bool {
	return KindAllowed(want, kinds)
}

func TestParseCoreHosts(t *testing.T) {
	p := load(t)
	if _, ok := p.Hosts["api.anthropic.com"]; !ok {
		t.Fatal("missing anthropic")
	}
	if _, ok := p.Hosts["github.com"]; !ok {
		t.Fatal("missing github")
	}
	hosts, err := LoadDomains(filepath.Join(filepath.Dir(policyPath(t)), "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hosts["github.com"]; !ok {
		t.Fatal("first-token load ignores kinds")
	}
	allow, err := LoadDomains(filepath.Join(filepath.Dir(policyPath(t)), "allow.domains"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := allow["github.com"]; !ok {
		t.Fatal("allow.domains first token only")
	}
	if _, ok := p.HostKinds["github.com"]["CLAUDE_OAT"]; ok {
		t.Fatal("github must not get claude")
	}
	if _, ok := p.HostKinds["github.com"]["GITHUB_TOKEN"]; !ok {
		t.Fatal("github token kind")
	}
	if _, ok := p.HostKinds["api.anthropic.com"]["CLAUDE_OAT"]; !ok {
		t.Fatal("anthropic oat")
	}
	if _, ok := p.HostKinds["pf-core-echo.test"][AllKinds]; !ok {
		t.Fatal("echo wildcard")
	}
}

func TestAuthority(t *testing.T) {
	p := load(t)
	cases := []struct {
		sni, host string
		ok        bool
	}{
		{"api.anthropic.com", "api.anthropic.com", true},
		{"api.anthropic.com", "api.anthropic.com:443", true},
		{"github.com", "api.github.com", true},
		{"", "api.anthropic.com", false},
		{"evil.example", "api.anthropic.com", false},
		{"api.anthropic.com", "evil.example", false},
		{"evil.example", "evil.example", false},
	}
	for _, c := range cases {
		got := p.Authority(c.sni, c.host)
		if got != c.ok {
			t.Fatalf("Authority(%q,%q)=%v want %v", c.sni, c.host, got, c.ok)
		}
	}
}

func TestKinds(t *testing.T) {
	p := load(t)
	anth := p.KindsFor("api.anthropic.com")
	gh := p.KindsFor("github.com")
	apiGH := p.KindsFor("api.github.com")
	echo := p.KindsFor("pf-core-echo.test")
	evil := p.KindsFor("evil.example")
	if !hasKind(anth, "CLAUDE_OAT") || hasKind(anth, "GITHUB_TOKEN") {
		t.Fatalf("anthropic kinds %v", anth)
	}
	if !hasKind(gh, "GITHUB_TOKEN") || hasKind(gh, "CLAUDE_OAT") {
		t.Fatalf("github kinds %v", gh)
	}
	if !hasKind(apiGH, "GITHUB_TOKEN") || hasKind(apiGH, "CLAUDE_OAT") {
		t.Fatalf("api.github.com kinds %v", apiGH)
	}
	if !hasKind(echo, "CLAUDE_OAT") || !hasKind(echo, "GITHUB_TOKEN") {
		t.Fatalf("echo kinds %v", echo)
	}
	if len(evil) != 0 {
		t.Fatalf("evil kinds %v", evil)
	}
	if HostIn("github.com.evil.example", map[string]struct{}{"github.com": {}}) {
		t.Fatal("suffix-flip")
	}
	if !HostIn("api.github.com", map[string]struct{}{"github.com": {}}) {
		t.Fatal("host_in suffix")
	}
	for _, n := range []string{"x..api.github.com", ".api.github.com", "x..github.com", "..github.com"} {
		if HostIn(n, map[string]struct{}{"github.com": {}}) {
			t.Fatalf("HostIn(%q) read an empty label as a subdomain", n)
		}
	}
}

func TestCoreHostsExactUnlessWildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(path, []byte("github.com GITHUB_TOKEN\n*.internal.example CLAUDE_OAT\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"github.com": true, "evil.github.com": false, "gist.github.com": false, "internal.example": true, "a.internal.example": true, "internal.example.evil": false, "x..internal.example": false, ".internal.example": false, "a..b.internal.example": false} {
		if got := len(p.KindsFor(name)) > 0; got != want {
			t.Fatalf("%s inject=%v want %v", name, got, want)
		}
		if got := p.HostAllowed(name); got != want {
			t.Fatalf("%s allowed=%v want %v", name, got, want)
		}
	}
}

// B. One name written both exactly and as "*." shared a row in the kind
// table. Thus the two lines overwrote each other. The kinds of the host
// came from the line that the file listed second.
func TestExactAndWildcardEntriesDoNotCollide(t *testing.T) {
	exact := "example.com KIND_A\n"
	wild := "*.example.com KIND_B\n"
	want := map[string][]string{
		"example.com":     {"KIND_A"},
		"api.example.com": {"KIND_B"},
	}
	for _, order := range []string{exact + wild, wild + exact} {
		path := filepath.Join(t.TempDir(), "core.hosts")
		if err := os.WriteFile(path, []byte(order), 0644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for host, kinds := range want {
			got := p.KindsFor(host)
			if len(got) != len(kinds) || !hasKind(got, kinds[0]) {
				t.Fatalf("%q in file order %q: KindsFor = %v, want %v", host, order, got, kinds)
			}
		}
	}
}
