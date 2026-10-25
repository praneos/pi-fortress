package policycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// core.hosts and core.hosts.local also compile to nothing. compile loads
// them so that a header that can never carry a credential stops pf apply,
// with the file and line, before anything installs.
func TestCompileRefusesADeniedCredentialHeader(t *testing.T) {
	run := func(local string) error {
		dir, out := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "core.hosts"), []byte("gitlab.com GITLAB_TOKEN\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "core.hosts.local"), []byte(local), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
		return err
	}
	if err := run("# seed\ngitlab.com GITLAB_TOKEN:PRIVATE-TOKEN\n"); err != nil {
		t.Fatal(err)
	}
	err := run("# seed\n\ngitlab.com GITLAB_TOKEN:User-Agent\n")
	if err == nil || !strings.Contains(err.Error(), "core.hosts.local:3:") || !strings.Contains(err.Error(), "User-Agent") {
		t.Fatalf("denied header accepted: %v", err)
	}
}

// A core.hosts line whose host can never get a credential is a warning in
// the compile, not an error. The line did nothing before, so a Pi that
// worked must still apply.
func TestCompileWarnsOnAOneLabelCoreHost(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.hosts.local"), []byte("# seed\nlocalhost CLAUDE_OAT\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sum, err := Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Warnings) != 1 || !strings.Contains(sum.Warnings[0], `core.hosts.local line 2: "localhost"`) {
		t.Fatalf("warnings %q", sum.Warnings)
	}
}
