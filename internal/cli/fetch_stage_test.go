package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/feedstage"
	"pi-fortress/internal/fetch"
)

// notAsRoot skips a test that runs the real fetch: fetch.Run refuses root.
func notAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("pf fetch does not run as root")
	}
}

// In stage mode pf fetch takes -fresh and the run id from the request of
// root, writes the run id into the stage, and writes no audit entry (the
// unit cannot see the log; root writes the entry).
func TestFetchStageModeTakesTheRequestOfRoot(t *testing.T) {
	notAsRoot(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	in := filepath.Join(dir, "in")
	stage := filepath.Join(dir, "state", "stage")
	cache := filepath.Join(dir, "state", "cache")
	if err := os.MkdirAll(in, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "sources.json"), []byte(`{"feeds":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	run := strings.Repeat("0a", 16)
	req := filepath.Join(in, "request")
	if err := os.WriteFile(req, feedstage.Request{Fresh: 30 * time.Minute, Run: run}.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := []string{"-request", req, "-policy", in, "-out", stage, "-cache", cache}
	if code := runFetch(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(stage, feedstage.RunFile))
	if err != nil || string(b) != run+"\n" {
		t.Fatalf("run file %q %v", b, err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("stage mode wrote an audit entry: %v", err)
	}

	for name, a := range map[string][]string{
		"no cache":        {"-request", req, "-policy", in, "-out", stage},
		"no out":          {"-request", req, "-policy", in, "-cache", cache},
		"fresh and req":   {"-request", req, "-policy", in, "-out", stage, "-cache", cache, "-fresh", "5m"},
		"missing request": {"-request", filepath.Join(in, "none"), "-policy", in, "-out", stage, "-cache", cache},
	} {
		stderr.Reset()
		if code := runFetch(a, &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, stderr.String())
		}
	}
	if err := os.WriteFile(req, []byte("fresh 0s\nrun x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runFetch(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "request") {
		t.Fatalf("a bad request: exit %d: %s", code, stderr.String())
	}
}

// pf fetch as root exits 2 with the message of fetch.Run, and writes no
// lists line and no audit entry.
func TestFetchAsRootExits2(t *testing.T) {
	old := runFetcher
	runFetcher = func(*fetch.Fetcher) ([]string, int, int, error) { return nil, 0, 0, fetch.ErrRoot }
	t.Cleanup(func() { runFetcher = old })
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	var stdout, stderr strings.Builder
	code := runFetch([]string{"-policy", dir}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 ||
		stderr.String() != "pf fetch does not run as root; use pf apply or pf feeds run\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("a refused run wrote an audit entry: %v", err)
	}
}
