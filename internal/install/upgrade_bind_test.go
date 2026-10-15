package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeRelease writes ROOT/VER/ the way make release publishes it: a
// bundle per arch with its own .sig, and SHA256SUMS over them signed by
// key.
func fakeRelease(t *testing.T, root, key, ver string) string {
	t.Helper()
	d := filepath.Join(root, ver)
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, arch := range []string{"amd64", "arm64"} {
		name := fmt.Sprintf("pf-bundle-%s-%s.tar", ver, arch)
		body := []byte("pretend bundle " + ver + " " + arch)
		if err := os.WriteFile(filepath.Join(d, name), body, 0644); err != nil {
			t.Fatal(err)
		}
		sign(t, key, filepath.Join(d, name))
		sum := sha256.Sum256(body)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+name)
	}
	sort.Strings(lines)
	writeSums(t, key, filepath.Join(d, SumsName), lines)
	return d
}

func writeSums(t *testing.T, key, path string, lines []string) {
	t.Helper()
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + ".sig")
	sign(t, key, path)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0644); err != nil {
		t.Fatal(err)
	}
}

type bindRig struct {
	root, trusted, other, signers string
}

func newBindRig(t *testing.T) *bindRig {
	dir := t.TempDir()
	trusted, line := signingKey(t, dir, "trusted")
	other, _ := signingKey(t, dir, "other")
	signers := filepath.Join(dir, "release-signers")
	if err := os.WriteFile(signers, []byte(line+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r := &bindRig{root: filepath.Join(dir, "serve"), trusted: trusted, other: other, signers: signers}
	fakeRelease(t, r.root, trusted, "v1")
	fakeRelease(t, r.root, trusted, "v2")
	return r
}

// fetch runs FetchAndVerify for v2 amd64 against whatever r.root serves.
func (r *bindRig) fetch(t *testing.T) (string, error) {
	t.Helper()
	srv := httptest.NewServer(http.FileServer(http.Dir(r.root)))
	defer srv.Close()
	work := t.TempDir()
	tar, err := FetchAndVerify(srv.Client(), srv.URL, "v2", "amd64", r.signers, work)
	if err != nil {
		if ents, _ := os.ReadDir(work); len(ents) != 0 {
			t.Errorf("a refused fetch left %v behind", ents)
		}
		return "", err
	}
	ents, _ := os.ReadDir(work)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if want := "pf-bundle.tar pf-bundle.tar.sig"; strings.Join(names, " ") != want {
		t.Errorf("incoming holds %v, want only %s for pf ship install", names, want)
	}
	return tar, nil
}

func TestFetchAndVerifyBindsTagAndArch(t *testing.T) {
	r := newBindRig(t)
	tar, err := r.fetch(t)
	if err != nil {
		t.Fatalf("the right tag and arch: %v", err)
	}
	if raw, _ := os.ReadFile(tar); string(raw) != "pretend bundle v2 amd64" {
		t.Fatalf("fetched %q", raw)
	}
}

func TestFetchAndVerifyRefusesWhatTheSignedSumsDoNotName(t *testing.T) {
	v2 := func(r *bindRig, name string) string { return filepath.Join(r.root, "v2", name) }
	v1 := func(r *bindRig, name string) string { return filepath.Join(r.root, "v1", name) }
	cases := []struct {
		name, want string
		rig        func(t *testing.T, r *bindRig)
	}{
		{"the other arch's bundle under this name", "does not match its SHA256SUMS entry", func(t *testing.T, r *bindRig) {
			copyFile(t, v2(r, "pf-bundle-v2-arm64.tar"), v2(r, "pf-bundle-v2-amd64.tar"))
			copyFile(t, v2(r, "pf-bundle-v2-arm64.tar.sig"), v2(r, "pf-bundle-v2-amd64.tar.sig"))
		}},
		{"an old tag's bundle and SHA256SUMS", "does not list pf-bundle-v2-amd64.tar", func(t *testing.T, r *bindRig) {
			copyFile(t, v1(r, "pf-bundle-v1-amd64.tar"), v2(r, "pf-bundle-v2-amd64.tar"))
			copyFile(t, v1(r, "pf-bundle-v1-amd64.tar.sig"), v2(r, "pf-bundle-v2-amd64.tar.sig"))
			copyFile(t, v1(r, SumsName), v2(r, SumsName))
			copyFile(t, v1(r, SumsName+".sig"), v2(r, SumsName+".sig"))
		}},
		{"an old tag's bundle under the new SHA256SUMS", "does not match its SHA256SUMS entry", func(t *testing.T, r *bindRig) {
			copyFile(t, v1(r, "pf-bundle-v1-amd64.tar"), v2(r, "pf-bundle-v2-amd64.tar"))
			copyFile(t, v1(r, "pf-bundle-v1-amd64.tar.sig"), v2(r, "pf-bundle-v2-amd64.tar.sig"))
		}},
		{"a SHA256SUMS without the bundle's name", "does not list pf-bundle-v2-amd64.tar", func(t *testing.T, r *bindRig) {
			raw, _ := os.ReadFile(v2(r, SumsName))
			var keep []string
			for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if !strings.Contains(l, "amd64") {
					keep = append(keep, l)
				}
			}
			writeSums(t, r.trusted, v2(r, SumsName), keep)
		}},
		{"a SHA256SUMS naming the bundle twice", "does not list pf-bundle-v2-amd64.tar exactly once", func(t *testing.T, r *bindRig) {
			raw, _ := os.ReadFile(v2(r, SumsName))
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			writeSums(t, r.trusted, v2(r, SumsName), append(lines, lines...))
		}},
		{"a SHA256SUMS signed by another key", "SHA256SUMS", func(t *testing.T, r *bindRig) {
			raw, _ := os.ReadFile(v2(r, SumsName))
			writeSums(t, r.other, v2(r, SumsName), strings.Split(strings.TrimSpace(string(raw)), "\n"))
		}},
		{"a release with no SHA256SUMS", "SHA256SUMS", func(t *testing.T, r *bindRig) {
			os.Remove(v2(r, SumsName))
		}},
		{"a release with no SHA256SUMS.sig", "SHA256SUMS.sig", func(t *testing.T, r *bindRig) {
			os.Remove(v2(r, SumsName+".sig"))
		}},
		{"a named bundle whose own .sig is another key's", "refusing unverified bundle", func(t *testing.T, r *bindRig) {
			os.Remove(v2(r, "pf-bundle-v2-amd64.tar.sig"))
			sign(t, r.other, v2(r, "pf-bundle-v2-amd64.tar"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newBindRig(t)
			c.rig(t, r)
			_, err := r.fetch(t)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want a refusal containing %q", err, c.want)
			}
		})
	}
}

func TestBuildUpgradeURLRefusesAPathForATag(t *testing.T) {
	for _, bad := range []string{"../v1", "v1/../../x", "v1 v2", "-v1", strings.Repeat("v", 129)} {
		if _, _, err := BuildUpgradeURL("https://pi-fortress-block.test/dl", bad, "amd64"); err == nil {
			t.Errorf("version %q accepted", bad)
		}
	}
}

// localUpgrade is pf upgrade -bundle against the fake release's files on
// disk, with Wrap recording whether pf ship install would have run.
func localUpgrade(t *testing.T, r *bindRig, bundle, version string) (wrapped bool, staged []byte, err error) {
	t.Helper()
	u := DefaultUpgrade()
	u.Arch = "amd64"
	u.Version = version
	u.Bundle, u.Sig = bundle, bundle+".sig"
	u.SignersPath = r.signers
	u.Dir = filepath.Join(t.TempDir(), "opt")
	u.UpgradeDir = filepath.Join(t.TempDir(), "upgrade")
	u.Stdout, u.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	u.Wrap = func(_, _ string, args []string, _, _ io.Writer) error {
		wrapped = true
		for i, a := range args {
			if a == "-incoming" {
				staged, _ = os.ReadFile(filepath.Join(args[i+1], "pf-bundle.tar"))
			}
		}
		return nil
	}
	err = u.doUpgrade()
	return wrapped, staged, err
}

func TestUpgradeLocalBundleBindsTagAndArch(t *testing.T) {
	r := newBindRig(t)
	good := filepath.Join(r.root, "v2", "pf-bundle-v2-amd64.tar")
	wrapped, staged, err := localUpgrade(t, r, good, "")
	if err != nil || !wrapped || string(staged) != "pretend bundle v2 amd64" {
		t.Fatalf("the right tag and arch: wrapped=%v staged=%q err=%v", wrapped, staged, err)
	}

	cases := []struct {
		name, bundle, version, want string
		rig                         func(t *testing.T)
	}{
		{"the other arch's file", filepath.Join(r.root, "v2", "pf-bundle-v2-arm64.tar"), "", "is not named pf-bundle-<tag>-amd64.tar", nil},
		{"a -version of another tag", good, "v1", "-version v1 but -bundle is pf-bundle-v2-amd64.tar", nil},
		{"no SHA256SUMS beside it", good, "", "no SHA256SUMS", func(t *testing.T) {
			os.Remove(filepath.Join(r.root, "v2", SumsName))
		}},
		{"another arch's bytes under this name", good, "", "does not match its SHA256SUMS entry", func(t *testing.T) {
			copyFile(t, filepath.Join(r.root, "v2", "pf-bundle-v2-arm64.tar"), good)
			copyFile(t, filepath.Join(r.root, "v2", "pf-bundle-v2-arm64.tar.sig"), good+".sig")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.rig != nil {
				r = newBindRig(t)
				good = filepath.Join(r.root, "v2", "pf-bundle-v2-amd64.tar")
				c.bundle = good
				c.rig(t)
			}
			wrapped, _, err := localUpgrade(t, r, c.bundle, c.version)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want a refusal containing %q", err, c.want)
			}
			if wrapped {
				t.Fatal("pf ship install ran on a refused bundle")
			}
		})
	}
}

// TestUpgradeLocalBundleStagesACopyNotALink: -bundle names a file that
// its caller may still be able to write. A hard link would let it
// change after the checks.
func TestUpgradeLocalBundleStagesACopyNotALink(t *testing.T) {
	r := newBindRig(t)
	good := filepath.Join(r.root, "v2", "pf-bundle-v2-amd64.tar")
	u := DefaultUpgrade()
	u.Arch = "amd64"
	u.Bundle, u.Sig = good, good+".sig"
	u.SignersPath = r.signers
	u.Dir = filepath.Join(t.TempDir(), "opt")
	u.UpgradeDir = filepath.Join(t.TempDir(), "upgrade")
	u.Stdout, u.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	u.Wrap = func(_, _ string, args []string, _, _ io.Writer) error {
		for i, a := range args {
			if a != "-incoming" {
				continue
			}
			a1, _ := os.Stat(filepath.Join(args[i+1], "pf-bundle.tar"))
			a2, _ := os.Stat(good)
			if a1 == nil || os.SameFile(a1, a2) {
				t.Error("the staged bundle is the caller's file, not a private copy")
			}
		}
		return nil
	}
	if err := u.doUpgrade(); err != nil {
		t.Fatal(err)
	}
}
