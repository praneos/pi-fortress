package corepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// A host with one label, or with "_", can never get a credential: the
// fence reads such a Host as not a name. The load skips the line with a
// warning. It does not stop the load. The forward set skips it too.
func TestOneLabelOrUnderscoreHostIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts.local")
	body := "localhost CLAUDE_OAT\n_x.example.com GITHUB_TOKEN\n*.a_b.example GITHUB_TOKEN\npf-core-echo.test *\napi.anthropic.com CLAUDE_OAT\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"localhost", "_x.example.com", "a_b.example"} {
		if _, ok := p.Hosts[h]; ok {
			t.Errorf("%s is a host", h)
		}
	}
	if !p.HostAllowed("api.anthropic.com") || !KindAllowed("GITHUB_TOKEN", p.KindsFor("pf-core-echo.test")) {
		t.Fatal("a good line is lost")
	}
	want := [][]string{
		{`core.hosts.local line 1: "localhost"`, "one label"},
		{`core.hosts.local line 2: "_x.example.com"`, `"_"`},
		{`core.hosts.local line 3: "*.a_b.example"`, `"_"`},
	}
	if len(p.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", p.Warnings, len(want))
	}
	for i, w := range want {
		for _, s := range w {
			if !strings.Contains(p.Warnings[i], s) {
				t.Errorf("warning %d %q lacks %q", i, p.Warnings[i], s)
			}
		}
	}
	if f := testForward(t, "", "localhost CLAUDE_OAT\n_x.example.com GITHUB_TOKEN\n"); f.Allowed("localhost", false) || f.Allowed("_x.example.com", false) {
		t.Fatal("the forward set keeps a refused line")
	}
}

// "*" in the host column is valid only as one "*." before a name. A bare
// "*" is not a match-all, and "*.*.example.com" is not two wildcards: each
// matches no name. The load skips the line with a warning that says so.
// "*" in a kind column is all kinds, and stays.
func TestBareOrRepeatedWildcardHostIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts.local")
	if err := os.WriteFile(path, []byte("* CLAUDE_OAT\n*.*.example.com GITHUB_TOKEN\napi.example.com *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Suffix) != 0 || len(p.Hosts) != 1 {
		t.Fatalf("hosts %v suffix %v", p.Hosts, p.Suffix)
	}
	if !KindAllowed("GITHUB_TOKEN", p.KindsFor("api.example.com")) {
		t.Fatal(`the "*" kind is lost`)
	}
	want := []string{`core.hosts.local line 1: "*"`, `core.hosts.local line 2: "*.*.example.com"`}
	if len(p.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", p.Warnings, len(want))
	}
	for i, w := range want {
		if !strings.Contains(p.Warnings[i], w) || !strings.Contains(p.Warnings[i], `one "*."`) {
			t.Errorf("warning %d %q lacks %q and the wildcard rule", i, p.Warnings[i], w)
		}
	}
	if f := testForward(t, "", "*.*.example.com GITHUB_TOKEN\n"); f.Allowed("x.*.example.com", false) {
		t.Fatal("the forward set keeps a repeated wildcard")
	}
}

// A host with an empty label, a label over 63 bytes or a name over 253
// bytes can never get a credential: the fence reads such a Host as not a
// name. The load skips the line with a warning. Before, the host was
// listed and bound nothing. "..example.com" also shielded example.com
// from the block list.
func TestEmptyLabelOrLongHostIsRefused(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 63)+".", 4) + "test"
	path := filepath.Join(t.TempDir(), "core.hosts.local")
	body := "..example.com GITHUB_TOKEN\n" + strings.Repeat("a", 64) + ".example.com GITHUB_TOKEN\n" + long + " GITHUB_TOKEN\napi.example.com GITHUB_TOKEN\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.HostsWithKind("GITHUB_TOKEN"), []string{"api.example.com"}) {
		t.Fatalf("hosts %v", p.HostsWithKind("GITHUB_TOKEN"))
	}
	want := [][]string{
		{`core.hosts.local line 1: "..example.com"`, "empty label"},
		{`core.hosts.local line 2: "aaaa`, "63"},
		{`core.hosts.local line 3: "aaaa`, "253"},
	}
	if len(p.Warnings) != len(want) {
		t.Fatalf("warnings %q, want %d", p.Warnings, len(want))
	}
	for i, w := range want {
		for _, s := range w {
			if !strings.Contains(p.Warnings[i], s) {
				t.Errorf("warning %d %q lacks %q", i, p.Warnings[i], s)
			}
		}
	}
	if f := testForward(t, "", body); f.Allowed("x.example.com", false) || !f.Allowed("api.example.com", false) {
		t.Fatal("the forward set keeps a refused line")
	}
}
