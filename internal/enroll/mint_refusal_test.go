package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMintRefusalsBeforeAnyWrite(t *testing.T) {
	headerDir(t, "gitlab.com GITLAB_TOKEN\n", "")
	for _, c := range []struct {
		name   string
		args   []string
		rc     int
		stderr string
	}{
		{"no kind", []string{"--value", glLive}, 2, "usage: pf enroll mint --kind KIND [--oat ...] [--ort ...] [--value ...] [--stdin] [--out PATH] [--expires 90d|RFC3339|none] [--header H[,H...]]\n"},
		{"bad flag", []string{"--nope"}, 2, ""},
		{"bad expires", []string{"--kind", "GITLAB_TOKEN", "--value", glLive, "--expires", "soon"}, 2, "bad --expires: "},
		{"bad kind", []string{"--kind", "a-b", "--value", glLive}, 2, "invalid secret kind: a-b\n"},
		{"bad kind with header", []string{"--kind", "a-b", "--value", glLive, "--header", "X-Tok"}, 2, "invalid secret kind: a-b\n"},
		{"bad header before bad kind", []string{"--kind", "a-b", "--value", glLive, "--header", "a/b"}, 2, "bad --header: "},
		{"bad claude pair", []string{"--kind", "CLAUDE", "--oat", "x", "--ort", "y"}, 2, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc, out, errs, store := mintRun(t, c.args...)
			if rc != c.rc {
				t.Fatalf("rc=%d want %d: %s", rc, c.rc, errs)
			}
			if !strings.HasPrefix(errs, c.stderr) || (c.stderr != "" && strings.HasSuffix(c.stderr, "\n") && errs != c.stderr) {
				t.Fatalf("stderr %q want %q", errs, c.stderr)
			}
			if store != "" || out != "" {
				t.Fatalf("refused mint wrote: %q %q", store, out)
			}
		})
	}
}

func TestMintHeaderAlreadyInStdout(t *testing.T) {
	headerDir(t, "gitlab.com GITLAB_TOKEN\n", "gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\n")
	rc, out, errs, _ := mintRun(t, "--kind", "GITLAB_TOKEN", "--value", glLive, "--header", "PRIVATE-TOKEN", "--expires", "none")
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs)
	}
	if strings.Contains(out, "expires=") || !strings.Contains(out, "\nwrote ") || !strings.Contains(out, "\n\nalready in ") || !strings.HasSuffix(out, "core.hosts.local: gitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\nsudo pf apply makes it live\n") {
		t.Fatalf("stdout:\n%s", out)
	}
}

// A token in argv still mints, with one warning on stderr that names the
// flag and --stdin, but not the token. --stdin gives no warning.
func TestMintWarnsOnArgvToken(t *testing.T) {
	oat, ort := OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40)
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"value", []string{"--kind", "GITLAB_TOKEN", "--value", glLive}, "warning: --value: a token in the command line"},
		{"claude pair", []string{"--kind", "CLAUDE", "--oat", oat, "--ort", ort}, "warning: --oat, --ort: a token in the command line"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc, out, errs, store := mintRun(t, c.args...)
			if rc != 0 || store == "" {
				t.Fatalf("rc=%d %s", rc, errs)
			}
			if !strings.HasPrefix(errs, c.want) || !strings.Contains(errs, "use --stdin") || strings.Count(errs, "warning:") != 1 {
				t.Fatalf("stderr %q", errs)
			}
			if strings.Contains(out+errs, glLive) || strings.Contains(out+errs, oat) || strings.Contains(out+errs, ort) {
				t.Fatalf("token in output: %q %q", out, errs)
			}
		})
	}
	store := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(store, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	args := []string{"--secrets", store, "mint", "--out", filepath.Join(t.TempDir(), "paste"), "--kind", "GITLAB_TOKEN", "--stdin"}
	if rc := MainIO(args, strings.NewReader(glLive+"\n"), &out, &errb); rc != 0 || strings.Contains(errb.String(), "warning:") {
		t.Fatalf("stdin mint rc=%d stderr %q", rc, errb.String())
	}
}
