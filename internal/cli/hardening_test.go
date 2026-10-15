package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBrokerRequiresAgentNet(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(f), "..", ".."))
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secrets, nil, 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-sock", filepath.Join(dir, "broker.sock"),
		"-policy", filepath.Join(root, "vm", "policy", "core.hosts"),
		"-rules", filepath.Join(root, "vm", "policy", "key_prefixes.rules"),
		"-allow", filepath.Join(root, "vm", "policy", "allow.domains"),
		"-secrets", secrets,
	}
	for _, extra := range [][]string{nil, {"-agent-net", ""}, {"-agent-net", "10.77.0.0"}, {"-agent-net", "nope/24"}} {
		var stderr bytes.Buffer
		if code := runBroker(append(append([]string{}, base...), extra...), nil, &stderr); code == 0 {
			t.Fatalf("args %v: broker started without an agent net", extra)
		} else if !strings.Contains(stderr.String(), "agent-net") {
			t.Fatalf("args %v: stderr %q", extra, stderr.String())
		}
	}
}

// Each -inspect-listen goes through the wildcard check of -listen. The
// agent address and a repeated address are refused before the CA is read.
func TestEngineChecksEachInspectListen(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "missing.pem")
	for _, extra := range [][]string{
		{"0.0.0.0:8080"},
		{":8080"},
		{"10.77.0.1:8080"},
		{"10.79.0.1:8080", "10.79.0.1:8080"},
	} {
		var errb bytes.Buffer
		args := []string{"engine", "-ca", ca, "-listen", "10.77.0.1:8080"}
		for _, l := range extra {
			args = append(args, "-inspect-listen", l)
		}
		if code := Main(args, io.Discard, &errb); code == 0 || !strings.Contains(errb.String(), "-inspect-listen") {
			t.Errorf("-inspect-listen %q: code=%d stderr=%q", extra, code, errb.String())
		}
	}
}

func TestBrokerRefusesBadFenceNet(t *testing.T) {
	root := filepath.Join("..", "..")
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secrets, nil, 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-sock", filepath.Join(dir, "broker.sock"),
		"-policy", filepath.Join(root, "vm", "policy", "core.hosts"),
		"-rules", filepath.Join(root, "vm", "policy", "key_prefixes.rules"),
		"-allow", filepath.Join(root, "vm", "policy", "allow.domains"),
		"-secrets", secrets, "-agent-net", "10.77.0.0/24",
	}
	for _, tc := range []struct{ net, want string }{
		{"nope/30", "-fence-net"},
		{"10.77.0.0/25", "overlaps -agent-net"},
		{"10.0.0.0/8", "overlaps -agent-net"},
	} {
		var stderr bytes.Buffer
		if code := runBroker(append(append([]string{}, base...), "-fence-net", tc.net), nil, &stderr); code == 0 || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("-fence-net %s: code=%d stderr=%q", tc.net, code, stderr.String())
		}
	}
}

// 192.0.2.1 is not on this host. The desk address can be absent at boot,
// and the engine must still start.
func TestInspectListenBindsAnAbsentAddress(t *testing.T) {
	ln, err := listenFreebind("192.0.2.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}
