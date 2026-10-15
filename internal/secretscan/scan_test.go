package secretscan

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randomBody is n random letters and digits, the alphabet that each token
// shape above accepts.
func randomBody(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// wgKey is a WireGuard private key: 32 random bytes, base64.
func wgKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// The scan finds keys that look real. It does not find the many fixtures
// in this repository.
func TestScanTellsKeysFromFixtures(t *testing.T) {
	for _, s := range []string{
		"sk-ant-api03-" + randomBody(95) + "AA",
		"Authorization: Bearer sk-ant-oat01-" + randomBody(90),
		"token ghp_" + randomBody(36),
		"PrivateKey = " + wgKey(),
		"-----BEGIN OPENSSH PRIVATE KEY-----\n" + randomBody(70) + "\n" + randomBody(70) + "\n",
		"xai-" + randomBody(80),
	} {
		if len(Scan([]byte(s))) == 0 {
			t.Errorf("missed: %.30s...", s)
		}
	}
	for _, s := range []string{
		"sk-ant-oat01-" + strings.Repeat("A", 90),
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"PrivateKey = " + strings.Repeat("A", 43) + "=",
		"-----BEGIN PRIVATE KEY-----\ncakeymaterial\n",
		"sk-ant-oat01-sk-ant-ort01-refresh_tokenAuthorizationauthorizationrefresh_busy_waiting_for_the_broker",
		"sk-ant-api03-" + strings.Repeat("x", 48),
	} {
		if h := Scan([]byte(s)); len(h) != 0 {
			t.Errorf("fixture flagged as %v: %.40s...", h, s)
		}
	}
}

// The tracked tree holds no credential. vendor/ is third-party and out of
// scope. All other files, also docs and testdata, go out in a push or the
// public export. Outside a git checkout (an exported tree, or a box with no
// git), the test scans each file under the root. Thus the test never
// passes because it found nothing to read.
func TestTrackedFilesHoldNoSecrets(t *testing.T) {
	root := testsupport.RepoRoot(t)
	files, err := gitFiles(root)
	if err != nil {
		t.Logf("git ls-files: %v; walking the tree instead", err)
		if files, err = walkFiles(root); err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no files to scan")
	}
	for _, f := range files {
		path := filepath.Join(root, filepath.FromSlash(f))
		b, err := os.ReadFile(path)
		if err != nil {
			// git lists it, but it is deleted in the worktree: nothing on disk
			// can leak. A submodule is a directory that git lists as one entry.
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if fi, serr := os.Stat(path); serr == nil && fi.IsDir() {
				continue
			}
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, h := range Scan(b) {
			t.Errorf("%s: byte %d: %s key %s", f, h.Offset, h.Rule, h.Secret)
		}
	}
}

// gitFiles is the git list of tracked files under root, without vendor/.
func gitFiles(root string) ([]string, error) {
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if f != "" && !strings.HasPrefix(f, "vendor/") {
			files = append(files, f)
		}
	}
	return files, nil
}

// walkFiles is each regular file under root, except vendor/ and .git.
func walkFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Name() == ".git" || rel == "vendor" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

// The fallback reads the tree that it gets: this file and the module
// root, and nothing under vendor/ or .git.
func TestWalkFilesFallback(t *testing.T) {
	files, err := walkFiles(testsupport.RepoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasPrefix(f, "vendor/") || f == ".git" || strings.HasPrefix(f, ".git/") {
			t.Fatalf("walked into %s", f)
		}
		seen[f] = true
	}
	for _, want := range []string{"go.mod", "internal/secretscan/scan_test.go"} {
		if !seen[want] {
			t.Fatalf("%s not walked (%d files)", want, len(files))
		}
	}
}

// SECRETSCAN_FILES names built artifacts to scan (make release-gate sets
// it to the release binaries). Without it, this is a no-op.
func TestArtifactsHoldNoSecrets(t *testing.T) {
	list := os.Getenv("SECRETSCAN_FILES")
	if list == "" {
		t.Skip("SECRETSCAN_FILES not set")
	}
	for _, f := range strings.Fields(list) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range Scan(b) {
			t.Errorf("%s: byte %d: %s key %s", f, h.Offset, h.Rule, h.Secret)
		}
	}
}
