package www

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newClaimsDir is a claims directory with its RedeemedDir, as apply makes
// them.
func newClaimsDir(t *testing.T) string {
	t.Helper()
	claims := filepath.Join(t.TempDir(), "claims")
	for _, d := range []string{claims, RedeemedDir(claims)} {
		if err := os.MkdirAll(d, 0770); err != nil {
			t.Fatal(err)
		}
	}
	return claims
}

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.sh"), []byte("#!/bin/bash\necho pi-fortress setup\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.env"), []byte("do-not-serve\n"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &Server{Bind: "127.0.0.1", Port: 80, Dir: dir}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestServesSetupAndCA(t *testing.T) {
	_, ts := testServer(t)
	c := ts.Client()
	res, err := c.Get(ts.URL + "/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "pi-fortress setup") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	res, err = c.Get(ts.URL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
}

func TestDoesNotListOrLeak(t *testing.T) {
	_, ts := testServer(t)
	c := ts.Client()
	for _, path := range []string{"/", "/secret.env", "/../www_test.go", "/setup.sh/../secret.env"} {
		res, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == 200 || strings.Contains(string(body), "do-not-serve") {
			t.Fatalf("%s -> %d %s", path, res.StatusCode, body)
		}
	}
}

func TestHEAD(t *testing.T) {
	_, ts := testServer(t)
	res, err := ts.Client().Head(ts.URL + "/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if res.ContentLength <= 0 {
		t.Fatal(res.ContentLength)
	}
}

func TestPOSTRejected(t *testing.T) {
	_, ts := testServer(t)
	res, err := ts.Client().Post(ts.URL+"/setup.sh", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(res.StatusCode)
	}
}

func TestBindRejectsUnspecified(t *testing.T) {
	s := &Server{Bind: "0.0.0.0", Port: 8080, Dir: t.TempDir()}
	if err := s.Serve(t.Context()); err == nil || !strings.Contains(err.Error(), "0.0.0.0") {
		t.Fatalf("%v", err)
	}
}

// With no ca.pem in its directory, www serves the CA file that caPath
// falls back to. A claim carries the hash of that file, so the agent
// must be able to get it.
func TestServesFallbackCA(t *testing.T) {
	fb := t.TempDir()
	egress, mitm := filepath.Join(fb, "egress-ca.pem"), filepath.Join(fb, "mitm-ca.pem")
	old := caFallbacks
	caFallbacks = []string{egress, mitm}
	t.Cleanup(func() { caFallbacks = old })
	s, ts := testServer(t)
	if err := os.Remove(filepath.Join(s.Dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ path, body string }{{mitm, "mitm-ca"}, {egress, "egress-ca"}} {
		if err := os.WriteFile(f.path, []byte(f.body+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Get(ts.URL + "/ca.pem")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || string(body) != f.body+"\n" {
			t.Fatalf("%s: %d %q", f.path, res.StatusCode, body)
		}
	}
}
