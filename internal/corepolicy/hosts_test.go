package corepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHostsWithKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts")
	body := "github.com GITHUB_TOKEN\napi.github.com GITHUB_TOKEN\n*.ghe.example GITHUB_TOKEN\necho.test *\nplain.example\napi.anthropic.com CLAUDE_OAT\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.HostsWithKind("GITHUB_TOKEN"), []string{"api.github.com", "github.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// No line in the shipped policy binds CANARY. A wildcard does not cover
// it. A line that names it binds it.
func TestCanaryOnlyWhereNamed(t *testing.T) {
	p := load(t)
	if got := p.HostsWithKind(KindCanary); len(got) != 0 {
		t.Fatalf("shipped policy binds CANARY: %v", got)
	}
	for _, host := range []string{"pf-core-echo.test", "api.anthropic.com", "api.openai.com", "github.com", "evil.example"} {
		if KindAllowed(KindCanary, p.KindsFor(host)) {
			t.Fatalf("CANARY allowed toward %s", host)
		}
	}
	if !KindAllowed("GITHUB_TOKEN", []string{AllKinds}) || KindAllowed(KindCanary, []string{AllKinds}) {
		t.Fatal("wildcard")
	}
	path := filepath.Join(t.TempDir(), "core.hosts")
	if err := os.WriteFile(path, []byte("api.openai.com OPENAI_API_KEY CANARY\necho.test *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bound, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !KindAllowed(KindCanary, bound.KindsFor("api.openai.com")) || KindAllowed(KindCanary, bound.KindsFor("echo.test")) {
		t.Fatal("bound policy")
	}
	if got := bound.HostsWithKind(KindCanary); !reflect.DeepEqual(got, []string{"api.openai.com"}) {
		t.Fatalf("got %v", got)
	}
}

// A leading dot in core.hosts is the exact host, as if the dot were not
// there. It is not a "*." line: the line binds the name, not the names
// below it. Before, the dotted key matched no name. The host then got no
// credential, but the compiler still shielded it from the block list.
func TestLeadingDotIsTheExactHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts")
	if err := os.WriteFile(path, []byte(".api.anthropic.com CLAUDE_OAT\n..bad.example GITHUB_TOKEN\n*.ghe.example GITHUB_TOKEN\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HostAllowed("api.anthropic.com") || !KindAllowed("CLAUDE_OAT", p.KindsFor("api.anthropic.com")) {
		t.Fatal("dotted line binds nothing")
	}
	if p.HostAllowed("x.api.anthropic.com") || len(p.KindsFor("x.api.anthropic.com")) != 0 {
		t.Fatal("dotted line reads as a suffix line")
	}
	if got := p.HostsWithKind("CLAUDE_OAT"); !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("got %v", got)
	}
	if p.HostAllowed("bad.example") {
		t.Fatal("two leading dots read as the host")
	}
	if !p.HostAllowed("x.ghe.example") || !p.HostAllowed("ghe.example") {
		t.Fatal("suffix line")
	}
	// The paranoid forward set reads the column the same way.
	f := testForward(t, "", ".api.anthropic.com CLAUDE_OAT\n")
	if !f.Allowed("api.anthropic.com", false) || f.Allowed("x.api.anthropic.com", false) {
		t.Fatal("forward set reads the dotted line in a different way")
	}
}
