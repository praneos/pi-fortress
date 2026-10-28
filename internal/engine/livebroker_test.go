package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/broker"
	"pi-fortress/internal/ca"
	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/testsupport"
	"pi-fortress/internal/tokenrules"
)

func startLiveBroker(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	body := strings.Join([]string{
		secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN") + "=lab_fence_github",
		secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_OAT") + "=sk-ant-oat01-" + strings.Repeat("A", 64),
		secrets.EnvKey("b0b1b2b3b4b5b6b7", "CLAUDE_ORT") + "=sk-ant-ort01-" + strings.Repeat("B", 64),
		secrets.EnvKey("c0c1c2c3c4c5c6c7", "CLAUDE_OAT") + "=sk-ant-oat01-" + strings.Repeat("C", 64),
		secrets.EnvKey("c0c1c2c3c4c5c6c7", "CLAUDE_ORT") + "=sk-ant-ort01-" + strings.Repeat("D", 64),
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	pol, err := corepolicy.Load(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	re, err := tokenrules.LoadTokenRE(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	b := &broker.Broker{
		Policy:  pol,
		Store:   secrets.Open(path),
		TokenRE: re,
		Idle:    5 * time.Second,
		LabEcho: true,
	}
	sock := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = b.Handle(ctx, c)
			}(c)
		}
	}()
	return sock, path
}

func tlsHTTP(t *testing.T, addr, sni string, store *ca.Store, raw string) string {
	t.Helper()
	tc := clientTLS(t, addr, sni, store, nil)
	defer tc.Close()
	if _, err := io.WriteString(tc, raw); err != nil {
		t.Fatal(err)
	}
	_ = tc.CloseWrite()
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := httpwire.ReadResponse(bufio.NewReader(tc), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	return string(resp.Body)
}

func TestLiveBrokerSecretsTable(t *testing.T) {
	sock, path := startLiveBroker(t)
	coreAddr, coreCA, _, _ := startEngine(t, sock, netip.MustParseAddrPort("192.0.2.2:443"), nil)
	openAddr, openCA, _, _ := startEngine(t, sock, netip.MustParseAddrPort("192.0.2.3:443"), nil)

	oatA := "sk-ant-oat01-" + strings.Repeat("A", 64)
	oatB := "sk-ant-oat01-" + strings.Repeat("C", 64)
	phGH := "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"
	phOatA := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	phOrtA := "pf_b0b1b2b3b4b5b6b7_CLAUDE_ORT"
	phOatB := "pf_c0c1c2c3c4c5c6c7_CLAUDE_OAT"

	got := tlsHTTP(t, coreAddr, "pf-core-echo.test", coreCA,
		"GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer "+phGH+"\r\n\r\n")
	if !strings.Contains(got, "lab_fence_github") || !strings.Contains(got, `"substituted": true`) {
		t.Fatalf("core github: %s", got)
	}

	got = tlsHTTP(t, coreAddr, "pf-core-echo.test", coreCA,
		"GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer "+phOatA+"\r\n\r\n")
	if !strings.Contains(got, oatA) || strings.Contains(got, oatB) || strings.Contains(got, phOatA) {
		t.Fatalf("core oat A: %s", got)
	}

	got = tlsHTTP(t, coreAddr, "pf-core-echo.test", coreCA,
		"GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer "+phOatB+"\r\n\r\n")
	if !strings.Contains(got, oatB) || strings.Contains(got, oatA) || strings.Contains(got, phOatB) {
		t.Fatalf("core oat B: %s", got)
	}

	got = tlsHTTP(t, coreAddr, "pf-core-echo.test", coreCA,
		"GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nAuthorization: Bearer pf_CLAUDE_OAT\r\n\r\n")
	if !strings.Contains(got, "pf_CLAUDE_OAT") || strings.Contains(got, oatA) {
		t.Fatalf("unslotted: %s", got)
	}

	// A host that is not an authority for the kind refuses. The refusal
	// says nothing about which of the causes it was.
	for _, tc := range []struct{ name, ph string }{
		{"open github", phGH}, {"open oat", phOatA},
	} {
		got = tlsHTTP(t, openAddr, "pf-open-echo.test", openCA,
			"GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer "+tc.ph+"\r\n\r\n")
		if !strings.Contains(got, broker.RefusedBody) || strings.Contains(got, tc.ph) || strings.Contains(got, "lab_fence_github") || strings.Contains(got, oatA) {
			t.Fatalf("%s: %s", tc.name, got)
		}
	}

	got = tlsHTTP(t, openAddr, "pf-open-echo.test", openCA,
		"GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer lab_fence_github\r\n\r\n")
	if !strings.Contains(got, `"stripped": true`) || strings.Contains(got, "lab_fence_github") {
		t.Fatalf("open strip live: %s", got)
	}

	got = tlsHTTP(t, openAddr, "pf-open-echo.test", openCA,
		"GET / HTTP/1.1\r\nHost: pf-open-echo.test\r\nAuthorization: Bearer "+oatA+"\r\n\r\n")
	if !strings.Contains(got, `"stripped": true`) || strings.Contains(got, oatA) {
		t.Fatalf("open strip oat: %s", got)
	}

	body := `{"grant_type":"refresh_token","refresh_token":"` + phOrtA + `"}`
	raw := "POST /v1/oauth/token HTTP/1.1\r\nHost: pf-core-echo.test\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	got = tlsHTTP(t, coreAddr, "pf-core-echo.test", coreCA, raw)
	if !strings.Contains(got, phOatA) || !strings.Contains(got, phOrtA) || strings.Contains(got, strings.Repeat("N", 8)) {
		t.Fatalf("oauth: %s", got)
	}
	env, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "b0b1b2b3b4b5b6b7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("N", 64)) {
		t.Fatalf("harvest: %s", env)
	}
	if !strings.Contains(string(env), "c0c1c2c3c4c5c6c7_CLAUDE_OAT=sk-ant-oat01-"+strings.Repeat("C", 64)) {
		t.Fatalf("slot B clobbered: %s", env)
	}

	// A Host that claims a core name under a foreign SNI gets the same
	// refusal as the foreign host above: no credential, and no way to
	// tell the two cases apart from the answer.
	got = tlsHTTP(t, coreAddr, "evil.example", coreCA,
		"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer "+phOatA+"\r\n\r\n")
	if strings.Contains(got, oatA) || strings.Contains(got, phOatA) || !strings.Contains(got, broker.RefusedBody) {
		t.Fatalf("host spoof: %s", got)
	}
}
