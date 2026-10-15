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
