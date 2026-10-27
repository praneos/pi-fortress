package enroll

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
)

func headerDir(t *testing.T, core, local string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.hosts"), []byte(core), 0644); err != nil {
		t.Fatal(err)
	}
	if local != "" {
		if err := os.WriteFile(filepath.Join(dir, "core.hosts.local"), []byte(local), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PI_FORTRESS_POLICY", dir)
	return dir
}

func mintRun(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	store := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(store, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	full := append([]string{"--secrets", store, "mint", "--out", filepath.Join(t.TempDir(), "paste")}, args...)
	rc := MainIO(full, nil, &out, &errb)
	raw, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	return rc, out.String(), errb.String(), string(raw)
}

func readLocal(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "core.hosts.local"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const glLive = "glpat-live-value-0123456789"

// mint --header declares the header for each host whose line binds the
// kind, in core.hosts.local: the file of the operator that apply puts over
// core.hosts. A second run changes nothing. With more names, it adds them
// to the same column, and keeps what was there and the operator comments.
func TestMintHeaderWritesCoreHostsLocal(t *testing.T) {
	dir := headerDir(t, "gitlab.com GITLAB_TOKEN\n*.gl.example GITLAB_TOKEN\npf-core-echo.test *\napi.github.com GITHUB_TOKEN\n",
		"# mine\nci.example GITLAB_TOKEN:Job-Token # runner\nother.example OTHER\n")
	rc, out, errs, _ := mintRun(t, "--kind", "GITLAB_TOKEN", "--value", glLive, "--header", "PRIVATE-TOKEN")
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	want := "# mine\nci.example GITLAB_TOKEN:Job-Token,PRIVATE-TOKEN # runner\nother.example OTHER\n*.gl.example GITLAB_TOKEN:PRIVATE-TOKEN\ngitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\n"
	if got := readLocal(t, dir); got != want {
		t.Fatalf("core.hosts.local:\n%s\nwant:\n%s", got, want)
	}
	st, err := os.Stat(filepath.Join(dir, "core.hosts.local"))
	if err != nil || st.Mode().Perm() != 0644 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
	if !strings.Contains(out, "sudo pf apply") || !strings.Contains(out, "gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN") || strings.Contains(out+errs, glLive) {
		t.Fatalf("stdout:\n%s", out)
	}
	if rc, _, errs, _ = mintRun(t, "--kind", "GITLAB_TOKEN", "--value", glLive, "--header", "private-token"); rc != 0 || readLocal(t, dir) != want {
		t.Fatalf("second mint rc=%d %s changed the file:\n%s", rc, errs, readLocal(t, dir))
	}
	if rc, _, errs, _ = mintRun(t, "--kind", "GITLAB_TOKEN", "--value", glLive, "--header", "Private-Token, X-Extra"); rc != 0 {
		t.Fatalf("third mint rc=%d %s", rc, errs)
	}
	want = strings.ReplaceAll(want, "PRIVATE-TOKEN", "PRIVATE-TOKEN,X-Extra")
	if got := readLocal(t, dir); got != want {
		t.Fatalf("core.hosts.local:\n%s\nwant:\n%s", got, want)
	}
	pol, err := corepolicy.LoadFiles(filepath.Join(dir, "core.hosts"), filepath.Join(dir, "core.hosts.local"))
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.HeadersFor("a.gl.example"); !reflect.DeepEqual(got, map[string][]string{"private-token": {"GITLAB_TOKEN"}, "x-extra": {"GITLAB_TOKEN"}}) {
		t.Fatalf("headers %v", got)
	}
	if got := pol.HeadersFor("pf-core-echo.test"); len(got) != 0 {
		t.Fatalf("a * line gained headers: %v", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("a temp file was left behind: %v", entries)
	}
}

// The Claude pair carries headers on its access token. The refresh
// token is body-only, whatever core.hosts says.
func TestMintHeaderClaudeBindsTheAccessToken(t *testing.T) {
	dir := headerDir(t, "api.anthropic.com CLAUDE_OAT CLAUDE_ORT ANTHROPIC_API_KEY\n", "")
	oat, ort := OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40)
	if rc, _, errs, _ := mintRun(t, "--kind", "CLAUDE", "--oat", oat, "--ort", ort, "--header", "X-Session"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	if got := readLocal(t, dir); got != "api.anthropic.com CLAUDE_OAT:X-Session\n" {
		t.Fatalf("core.hosts.local %q", got)
	}
}

func TestMintHeaderRefusals(t *testing.T) {
	for _, c := range []struct {
		name, core, kind, header string
		rc                       int
		say                      []string
	}{
		{"deny-listed", "gitlab.com GITLAB_TOKEN\n", "GITLAB_TOKEN", "User-Agent", 2, []string{"User-Agent", "never carry"}},
		{"deny-listed prefix", "gitlab.com GITLAB_TOKEN\n", "GITLAB_TOKEN", "PRIVATE-TOKEN,X-Forwarded-Host", 2, []string{"X-Forwarded-Host"}},
		{"not a token", "gitlab.com GITLAB_TOKEN\n", "GITLAB_TOKEN", "a/b", 2, []string{"token"}},
		{"empty", "gitlab.com GITLAB_TOKEN\n", "GITLAB_TOKEN", "", 2, []string{"empty"}},
		{"unbound kind", "gitlab.com GITLAB_TOKEN\npf-core-echo.test *\n", "NOPE_TOKEN", "X-Tok", 1, []string{"core.hosts.local", "`<host> NOPE_TOKEN`"}},
		{"bad local", "gitlab.com GITLAB_TOKEN:Via\n", "GITLAB_TOKEN", "X-Tok", 1, []string{"core.hosts:1:"}},
		{"empty label host", "..gitlab.example GITLAB_TOKEN\n", "GITLAB_TOKEN", "X-Tok", 1, []string{"`<host> GITLAB_TOKEN`"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := headerDir(t, c.core, "")
			rc, out, errs, store := mintRun(t, "--kind", c.kind, "--value", glLive, "--header", c.header)
			if rc != c.rc {
				t.Fatalf("rc=%d want %d: %s", rc, c.rc, errs)
			}
			for _, s := range c.say {
				if !strings.Contains(errs, s) {
					t.Fatalf("stderr %q does not say %q", errs, s)
				}
			}
			if store != "" || strings.Contains(out, "slot=") {
				t.Fatalf("a refused mint minted a slot: %q %q", store, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "core.hosts.local")); !os.IsNotExist(err) {
				t.Fatalf("core.hosts.local written: %v", err)
			}
			if strings.Contains(out+errs, glLive) {
				t.Fatal("the credential was echoed")
			}
		})
	}
}

// Without --header, mint is unchanged: no policy read, no
// core.hosts.local, nothing new on stdout.
func TestMintWithoutHeaderLeavesPolicyAlone(t *testing.T) {
	dir := headerDir(t, "gitlab.com GITLAB_TOKEN:Via\n", "")
	rc, out, errs, store := mintRun(t, "--kind", "GITLAB_TOKEN", "--value", glLive)
	if rc != 0 || !strings.Contains(store, "_GITLAB_TOKEN="+glLive) {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	if strings.Contains(out, "core.hosts") || strings.Contains(out, "pf apply") {
		t.Fatalf("stdout:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "core.hosts.local")); !os.IsNotExist(err) {
		t.Fatalf("core.hosts.local written: %v", err)
	}
}
