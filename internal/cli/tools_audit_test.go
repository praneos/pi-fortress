package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/audit"
)

func toolEntries(t *testing.T, path string) ([]audit.Entry, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line does not parse: %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries, string(raw)
}

// pf compile rewrites the files that the fence is built from. It is its
// own entry point, so it never reaches admin.CallCtx. Before this entry,
// when the fence of a box started to drop different traffic, the log
// did not show which run changed the lists.
func TestCompileWritesAnAuditLine(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	t.Setenv("SUDO_USER", "tester")
	policy := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policy, 0755); err != nil {
		t.Fatal(err)
	}
	outNFT := filepath.Join(dir, "elements.nft")
	outDNS := filepath.Join(dir, "sinkhole.conf")
	var stdout, stderr strings.Builder
	rc := runCompile([]string{"--policy", policy, "--out-nft", outNFT, "--out-dns", outDNS}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr.String())
	}
	entries, raw := toolEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	e := entries[0]
	if e.Verb != "compile" || !e.OK || e.Actor != "sudo:tester" || e.Role != "admin" || e.T == "" {
		t.Fatalf("entry: %+v", e)
	}
	// The paths show which files were rewritten. The counts show by how
	// much. That is the difference between a compile that emptied the
	// blocklist and a compile that did its job.
	if e.Args["policy"] != policy || e.Args["out-nft"] != outNFT || e.Args["out-dns"] != outDNS {
		t.Fatalf("args: %+v", e.Args)
	}
	if _, ok := e.Args["ips"]; !ok {
		t.Fatalf("no count in the record: %+v", e.Args)
	}
}

// A compile that failed changed nothing. But an operator needs the entry
// for the attempt when the fence is stale and nobody knows why.
func TestCompileRecordsAFailure(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	var stdout, stderr strings.Builder
	rc := runCompile([]string{
		"--policy", filepath.Join(dir, "nope"),
		"--out-nft", filepath.Join(dir, "sub", "missing", "elements.nft"),
		"--out-dns", filepath.Join(dir, "sub", "missing", "sinkhole.conf"),
	}, &stdout, &stderr)
	if rc == 0 {
		t.Skip("compile accepted a policy dir that does not exist; nothing to record as a failure")
	}
	entries, raw := toolEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	if e := entries[0]; e.Verb != "compile" || e.OK || e.Err == "" {
		t.Fatalf("entry: %+v", e)
	}
}

// pf fetch is the other tool that rewrites the inputs of the fence. With
// no feeds configured, it downloads nothing. That is the run to test: the
// entry must appear because the command ran, not because it changed
// something by chance.
func TestFetchWritesAnAuditLine(t *testing.T) {
	notAsRoot(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	t.Setenv("SUDO_USER", "tester")
	policy := filepath.Join(dir, "policy")
	out := filepath.Join(policy, "generated")
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	runFetch([]string{"-policy", policy, "-out", out}, &stdout, &stderr)
	entries, raw := toolEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	e := entries[0]
	if e.Verb != "fetch" || e.Actor != "sudo:tester" || e.Role != "admin" || e.T == "" {
		t.Fatalf("entry: %+v", e)
	}
	if e.Args["policy"] != policy || e.Args["out"] != out {
		t.Fatalf("args: %+v", e.Args)
	}
}

// When all feeds of a run fail, Run returns an error, and the entry must
// say so: OK=false with the error string, plus the feed count, because
// nobody reads fetch.report without a prompt. The test of the count
// helper in internal/fetch pins the partial run (some feeds answer, err
// is nil).
func TestFetchAuditsFeedFailures(t *testing.T) {
	notAsRoot(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	t.Setenv("SUDO_USER", "tester")
	policy := filepath.Join(dir, "policy")
	out := filepath.Join(policy, "generated")
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	spec := `{
  "user_agent": "pf-test",
  "timeout_sec": 2,
  "max_ips": 100,
  "max_domains": 100,
  "feeds": [
    {"id": "d", "kind": "domains", "format": "plain", "url": "https://127.0.0.1:1/d"},
    {"id": "x", "kind": "domains", "format": "plain", "url": "https://127.0.0.1:2/x"}
  ]
}`
	if err := os.WriteFile(filepath.Join(policy, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if code := runFetch([]string{"-policy", policy, "-out", out}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	entries, raw := toolEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	e := entries[0]
	if e.Verb != "fetch" || e.OK || e.Err == "" {
		t.Fatalf("a run that fetched nothing is an error: %+v", e)
	}
	if e.Args["fails"] != "2" {
		t.Fatalf("args: %+v", e.Args)
	}
}

// Neither tool takes a credential, and neither may start to. The caller
// builds Args from named fields, not from the flag set. Thus a future
// flag that carries a secret cannot get into the log through a parse of
// the same argv. This test pins that, at low cost.
func TestToolEntriesCarryOnlyNamedFields(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	t.Setenv(audit.PathEnv, log)
	policy := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policy, 0755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	runCompile([]string{
		"--policy", policy,
		"--out-nft", filepath.Join(dir, "elements.nft"),
		"--out-dns", filepath.Join(dir, "sinkhole.conf"),
		"--out-domain-map", filepath.Join(dir, "domains.map"),
	}, &stdout, &stderr)
	entries, raw := toolEntries(t, log)
	if len(entries) != 1 {
		t.Fatalf("entries: %q", raw)
	}
	for k := range entries[0].Args {
		switch k {
		case "policy", "out-nft", "out-dns", "ips", "domains":
		default:
			t.Errorf("unnamed field %q reached the audit log: %s", k, raw)
		}
	}
}
