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
