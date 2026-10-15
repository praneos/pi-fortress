package policycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// git_push.allow compiles to nothing. compile loads it so that a malformed
// line stops the apply. compile also counts the entries.
func TestCompileGitPush(t *testing.T) {
	run := func(body string) (Summary, error) {
		dir, out := t.TempDir(), t.TempDir()
		if body != "" {
			if err := os.WriteFile(filepath.Join(dir, "git_push.allow"), []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
		}
		return Compile(dir, Out{NFT: filepath.Join(out, "e.nft"), DNS: filepath.Join(out, "d.conf")})
	}
	sum, err := run("# seed\ngithub.com acme/widget\ngithub.com team/*\n")
	if err != nil || sum.GitPushes != 2 || !strings.Contains(sum.Line(), "2 git_pushes") {
		t.Fatalf("sum=%+v line=%q err=%v", sum, sum.Line(), err)
	}
	if sum, err = run(""); err != nil || sum.GitPushes != 0 || strings.Contains(sum.Line(), "git_pushes") {
		t.Fatalf("absent: sum=%+v err=%v", sum, err)
	}
	if _, err = run("github.com acme/../widget\n"); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("malformed accepted: %v", err)
	}
}
