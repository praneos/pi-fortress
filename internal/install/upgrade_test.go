package install

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildUpgradeURL(t *testing.T) {
	cases := []struct {
		base, version, arch string
		wantTar, wantSig    string
		wantErr             bool
	}{
		{"https://dl.example.com/pf", "v1.2.3", "arm64",
			"https://dl.example.com/pf/v1.2.3/pf-bundle-v1.2.3-arm64.tar",
			"https://dl.example.com/pf/v1.2.3/pf-bundle-v1.2.3-arm64.tar.sig", false},
		{"https://dl.example.com/pf/", "", "amd64", "", "", true},       // no version: a tag is required
		{"https://dl.example.com/pf/", "latest", "amd64", "", "", true}, // no fixed latest path exists
		{"", "v1", "arm64", "", "", true},
		{"https://dl.example.com", "v1", "", "", "", true},
	}
	for _, c := range cases {
		tar, sig, err := BuildUpgradeURL(c.base, c.version, c.arch)
		if c.wantErr {
			if err == nil {
				t.Errorf("BuildUpgradeURL(%q,%q,%q): expected an error", c.base, c.version, c.arch)
			}
			continue
		}
		if err != nil {
			t.Fatalf("BuildUpgradeURL(%q,%q,%q): %v", c.base, c.version, c.arch, err)
		}
		if tar != c.wantTar || sig != c.wantSig {
			t.Errorf("BuildUpgradeURL(%q,%q,%q) = (%q,%q), want (%q,%q)", c.base, c.version, c.arch, tar, sig, c.wantTar, c.wantSig)
		}
	}
}

func TestResolveReleaseURL(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "release.url")
	if _, err := ResolveReleaseURL("", missing); err == nil {
		t.Fatal("expected a refusal with no env and no file")
	}
	if err := os.WriteFile(missing, []byte("https://from-file.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveReleaseURL("", missing)
	if err != nil || got != "https://from-file.example.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = ResolveReleaseURL("https://from-env.example.com", missing)
	if err != nil || got != "https://from-env.example.com" {
		t.Fatalf("env should win: got %q, %v", got, err)
	}
}

// signingKey makes an ed25519 key pair on disk and returns the private
// key path and the allowed_signers line for its public half, namespaced
// the way VerifyBundle expects.
func signingKey(t *testing.T, dir, name string) (priv, allowedSignersLine string) {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	saved := sshKeygen
	sshKeygen = path
	t.Cleanup(func() { sshKeygen = saved })
	priv = filepath.Join(dir, name)
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -t ed25519: %v: %s", err, out)
	}
	pub, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		t.Fatalf("unexpected pubkey format: %s", pub)
	}
	return priv, DistPrincipal + ` namespaces="` + DistNamespace + `" ` + fields[0] + " " + fields[1]
}

func sign(t *testing.T, priv, file string) string {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", priv, "-n", DistNamespace, file)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v: %s", err, out)
	}
	return file + ".sig"
}

// TestFetchAndVerifyRefusesBadSignature is the required httptest coverage.
// A bundle signed by a key that the box does not trust must be refused
// before anything is staged. FetchAndVerify must not leave the bundle behind.
func TestFetchAndVerifyRefusesBadSignature(t *testing.T) {
	dir := t.TempDir()
	trusted, allowedLine := signingKey(t, dir, "trusted")
	untrusted, _ := signingKey(t, dir, "untrusted")
	_ = trusted

	bundle := filepath.Join(dir, "pf-bundle-v1-amd64.tar")
	if err := os.WriteFile(bundle, []byte("not a real tar, verification only checks the signature"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath := sign(t, untrusted, bundle) // signed by the WRONG key

	signers := filepath.Join(dir, "release-signers")
	if err := os.WriteFile(signers, []byte(allowedLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pf-bundle-v1-amd64.tar", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, bundle)
	})
	mux.HandleFunc("/v1/pf-bundle-v1-amd64.tar.sig", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, sigPath)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	work := t.TempDir()
	_, err := FetchAndVerify(srv.Client(), srv.URL, "v1", "amd64", signers, work)
	if err == nil {
		t.Fatal("expected a signature-verification refusal")
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatalf("a refused bundle must not be left behind: %v", entries)
	}
}

// TestFetchAndVerifyAcceptsGoodSignature is the positive case: a bundle
// signed by the trusted key downloads and verifies clean.
func TestFetchAndVerifyAcceptsGoodSignature(t *testing.T) {
	dir := t.TempDir()
	trusted, allowedLine := signingKey(t, dir, "trusted")

	bundle := filepath.Join(dir, "pf-bundle-v1-amd64.tar")
	if err := os.WriteFile(bundle, []byte("pretend bundle bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath := sign(t, trusted, bundle)

	signers := filepath.Join(dir, "release-signers")
	if err := os.WriteFile(signers, []byte(allowedLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pf-bundle-v1-amd64.tar", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, bundle)
	})
	mux.HandleFunc("/v1/pf-bundle-v1-amd64.tar.sig", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, sigPath)
	})
	sums := releaseSums(t, trusted, bundle)
	mux.HandleFunc("/v1/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, sums)
	})
	mux.HandleFunc("/v1/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, sums+".sig")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	work := t.TempDir()
	got, err := FetchAndVerify(srv.Client(), srv.URL, "v1", "amd64", signers, work)
	if err != nil {
		t.Fatalf("expected the good signature to verify: %v", err)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("verified bundle missing: %v", err)
	}
}

// TestUpgradeRunRoutesThroughShipInstall: pf upgrade no longer stages
// or swaps anything itself. It puts a verified bundle in a new
// incoming directory and wraps `pf ship install` with the dist identity.
func TestUpgradeRunRoutesThroughShipInstall(t *testing.T) {
	dir := t.TempDir()
	priv, allowedLine := signingKey(t, dir, "dist")

	bundle := filepath.Join(dir, "pf-bundle-v1-amd64.tar")
	if err := os.WriteFile(bundle, []byte("pretend bundle bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath := sign(t, priv, bundle)
	releaseSums(t, priv, bundle)

	signers := filepath.Join(dir, "release-signers")
	if err := os.WriteFile(signers, []byte(allowedLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	u := DefaultUpgrade()
	u.Arch = "amd64"
	u.Bundle, u.Sig = bundle, sigPath
	u.SignersPath = signers
	u.Dir = filepath.Join(dir, "opt", "pi-fortress")
	u.UpgradeDir = filepath.Join(dir, "upgrade")
	u.Stdout, u.Stderr = &bytes.Buffer{}, &bytes.Buffer{}

	var gotUnit, gotExe string
	var gotArgs []string
	var incomingDuringCall string
	u.Wrap = func(unit, exe string, args []string, stdout, stderr io.Writer) error {
		gotUnit, gotExe, gotArgs = unit, exe, append([]string{}, args...)
		// the incoming dir must exist, with the pair under it,
		// while the wrapped command runs
		for i, a := range args {
			if a == "-incoming" {
				incomingDuringCall = args[i+1]
			}
		}
		if _, err := os.Stat(filepath.Join(incomingDuringCall, "pf-bundle.tar")); err != nil {
			t.Errorf("bundle not staged in incoming before Wrap ran: %v", err)
		}
		return nil
	}

	if err := u.doUpgrade(); err != nil {
		t.Fatalf("doUpgrade: %v", err)
	}

	want := ShipInstallArgs(incomingDuringCall, signers, u.Dir)
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("Wrap args = %v, want %v", gotArgs, want)
	}
	if gotUnit != "pf-upgrade-"+filepath.Base(incomingDuringCall) {
		t.Fatalf("unit = %q, want pf-upgrade-<incoming basename>", gotUnit)
	}
	if gotExe == "" {
		t.Fatal("exe not set")
	}
	if filepath.Dir(incomingDuringCall) != u.UpgradeDir {
		t.Fatalf("incoming %q not under UpgradeDir %q", incomingDuringCall, u.UpgradeDir)
	}
	if _, err := os.Stat(incomingDuringCall); !os.IsNotExist(err) {
		t.Fatalf("incoming dir %s should be cleaned up after Run: %v", incomingDuringCall, err)
	}
}

// TestUpgradeRunRefusesBadSignatureBeforeWrapping is the same as
// TestFetchAndVerifyRefusesBadSignature for the -bundle/-sig direct path.
// A bad signature must be refused before Wrap (and thus pf ship install)
// runs.
func TestUpgradeRunRefusesBadSignatureBeforeWrapping(t *testing.T) {
	dir := t.TempDir()
	_, untrustedLine := signingKey(t, dir, "trusted")
	untrusted, _ := signingKey(t, dir, "untrusted")

	bundle := filepath.Join(dir, "pf-bundle-v1-amd64.tar")
	if err := os.WriteFile(bundle, []byte("not a real tar"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath := sign(t, untrusted, bundle)

	signers := filepath.Join(dir, "release-signers")
	if err := os.WriteFile(signers, []byte(untrustedLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	u := DefaultUpgrade()
	u.Bundle, u.Sig = bundle, sigPath
	u.SignersPath = signers
	u.Dir = filepath.Join(dir, "opt", "pi-fortress")
	u.UpgradeDir = filepath.Join(dir, "upgrade")
	u.Stdout, u.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	wrapped := false
	u.Wrap = func(unit, exe string, args []string, stdout, stderr io.Writer) error {
		wrapped = true
		return nil
	}

	if err := u.doUpgrade(); err == nil {
		t.Fatal("expected a signature-verification refusal")
	}
	if wrapped {
		t.Fatal("pf ship install must not run when the signature is bad")
	}
}

// TestUpgradeConfirmExecsRunConfirm checks that -confirm never touches
// incoming/Wrap. It is a direct exec of `pf ship confirm`.
func TestUpgradeConfirmExecsRunConfirm(t *testing.T) {
	u := DefaultUpgrade()
	u.Confirm = true
	called := false
	u.RunConfirm = func(stdout, stderr io.Writer) error { called = true; return nil }
	u.Wrap = func(unit, exe string, args []string, stdout, stderr io.Writer) error {
		t.Fatal("Wrap must not run for -confirm")
		return nil
	}
	if err := u.Run(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("RunConfirm not called")
	}
}

func TestResolveReleaseURLRefusesAnythingButHTTPS(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "release.url")
	if err := os.WriteFile(file, []byte("http://pi-fortress-block.test/dl\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveReleaseURL("", file); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("an http release.url: err = %v, want an https refusal", err)
	}
	for _, bad := range []string{"http://pi-fortress-block.test/dl", "file:///tmp/x", "ftp://pi-fortress-block.test/x", "https://"} {
		if _, err := ResolveReleaseURL(bad, file); err == nil {
			t.Errorf("PF_RELEASE_URL=%q accepted", bad)
		}
	}
	if got, err := ResolveReleaseURL("https://pi-fortress-block.test/dl", file); err != nil || got != "https://pi-fortress-block.test/dl" {
		t.Fatalf("https: %q, %v", got, err)
	}
}

func TestHTTPSOnlyRedirectRefusesADowngrade(t *testing.T) {
	to := func(raw string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	if err := httpsOnlyRedirect(to("http://pi-fortress-block.test/x"), nil); err == nil {
		t.Fatal("a redirect to http was followed")
	}
	if err := httpsOnlyRedirect(to("https://pi-fortress-block.test/x"), nil); err != nil {
		t.Fatalf("a redirect to https was refused: %v", err)
	}
	via := make([]*http.Request, 10)
	if err := httpsOnlyRedirect(to("https://pi-fortress-block.test/x"), via); err == nil {
		t.Fatal("an eleventh redirect was followed")
	}
}

// releaseSums writes the signed SHA256SUMS that make release publishes
// beside bundle. It lists bundle under its own name. It returns the path
// of SHA256SUMS.
func releaseSums(t *testing.T, key, bundle string) string {
	t.Helper()
	sum, err := sha256File(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(bundle), SumsName)
	writeSums(t, key, path, []string{sum + "  " + filepath.Base(bundle)})
	return path
}
