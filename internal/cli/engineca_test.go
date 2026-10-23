package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/audit"
)

func TestEngineCARotationVerbs(t *testing.T) {
	orig := applyLockPath
	applyLockPath = filepath.Join(t.TempDir(), "apply.lock")
	t.Cleanup(func() { applyLockPath = orig })
	dir := t.TempDir()
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	caPath := filepath.Join(dir, "ca.pem")
	run := func(want int, args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := Main(args, &out, &errb); code != want {
			t.Fatalf("pf %s: code %d, want %d; stderr %s", strings.Join(args, " "), code, want, errb.String())
		}
		return out.String() + errb.String()
	}
	run(0, "engine", "-init-ca", "-ca", caPath, "-ca-cert", filepath.Join(dir, "ca-cert.pem"), "-ca-trust", filepath.Join(dir, "ca-trust.pem"))
	if out := run(0, "engine", "ca", "status", "-ca", caPath); !strings.Contains(out, "current  pi-fortress") {
		t.Fatalf("status: %s", out)
	}
	out := run(0, "engine", "ca", "rotate", "-ca", caPath, "-apply=false")
	if !strings.Contains(out, "next ") || !strings.Contains(out, "pf engine ca promote") || !strings.Contains(out, "sudo pf apply") {
		t.Fatalf("rotate: %s", out)
	}
	if n := bytes.Count(mustRead(t, filepath.Join(dir, "ca-trust.pem")), []byte("BEGIN CERTIFICATE")); n != 3 {
		t.Fatalf("trust set after rotate holds %d certs, want 3", n)
	}
	if out := run(0, "engine", "ca", "promote", "-ca", caPath, "-apply=false"); !strings.Contains(out, "old ") {
		t.Fatalf("promote: %s", out)
	}
	run(0, "engine", "ca", "retire", "-ca", caPath, "-apply=false")
	if n := bytes.Count(mustRead(t, filepath.Join(dir, "ca-trust.pem")), []byte("BEGIN CERTIFICATE")); n != 1 {
		t.Fatalf("trust set after retire holds %d certs, want 1", n)
	}
	run(1, "engine", "ca", "retire", "-ca", caPath, "-apply=false")
	run(2, "engine", "ca", "bogus", "-ca", caPath)
	run(2, "engine", "ca", "status", "extra", "-ca", caPath)
	if n := bytes.Count(mustRead(t, log), []byte(`"engine ca `)); n != 4 {
		t.Fatalf("audit log has %d engine ca entries, want 4 (rotate, promote, retire, failed retire)", n)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
