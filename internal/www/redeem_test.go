package www

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// issueTestClaim issues a claim in the claims directory of s.
func issueTestClaim(t *testing.T, s *Server) (string, Claim) {
	t.Helper()
	if _, err := os.Stat("/vagrant/vm/agent/setup.sh"); err == nil {
		t.Skip("a lab VM serves /vagrant's setup.sh, not the test's")
	}
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(claims, "a1b2c3d4e5f67890", []string{"GITHUB_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	return claims, c
}

func spent(claims, code string) bool {
	_, err := os.Lstat(markerPath(claims, code))
	return err == nil
}

// A request that fails a check gets the 404 of an unknown code. It does not
// spend the code. When the cause goes away, the same code redeems.
func TestRedeemThatFailsACheckLeavesTheCodeUnspent(t *testing.T) {
	s, _ := testServer(t)
	claims, c := issueTestClaim(t, s)
	path := filepath.Join(claims, c.Code+".json")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	setup := filepath.Join(s.Dir, "setup.sh")
	ca := filepath.Join(s.Dir, "ca.pem")
	setupRaw, _ := os.ReadFile(setup)
	caRaw, _ := os.ReadFile(ca)
	restore := func() {
		t.Helper()
		for p, raw := range map[string][]byte{path: good, setup: setupRaw, ca: caRaw} {
			if err := os.WriteFile(p, raw, 0640); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name   string
		change func()
	}{
		{"an expired claim", func() {
			raw := strings.Replace(string(good), `"expires":"`+c.Expires.Format(time.RFC3339Nano), `"expires":"2000-01-01T00:00:00Z`, 1)
			_ = os.WriteFile(path, []byte(raw), 0640)
		}},
		{"a kind outside the grammar", func() {
			_ = os.WriteFile(path, []byte(strings.Replace(string(good), `"GITHUB_TOKEN"`, `"BAD KIND'"`, 1)), 0640)
		}},
		{"a claim that does not parse", func() { _ = os.WriteFile(path, []byte("{"), 0640) }},
		{"a setup.sh that changed after the issue", func() { _ = os.WriteFile(setup, []byte("#!/bin/bash\necho other\n"), 0644) }},
		{"a ca.pem that changed after the issue", func() { _ = os.WriteFile(ca, []byte("other\n"), 0644) }},
	}
	for _, tc := range cases {
		tc.change()
		if _, err := RedeemClaim(claims, c.Code); err != ErrNoClaim {
			t.Fatalf("%s: err %v, want ErrNoClaim", tc.name, err)
		}
		if spent(claims, c.Code) {
			t.Fatalf("%s: the refused redeem spent the code", tc.name)
		}
		restore()
	}
	if _, err := RedeemClaim(claims, c.Code); err != nil {
		t.Fatalf("the code did not redeem after the checks passed: %v", err)
	}
	if !spent(claims, c.Code) {
		t.Fatal("a redeem that passed made no marker")
	}
	if _, err := RedeemClaim(claims, c.Code); err != ErrNoClaim {
		t.Fatalf("second redeem: err %v, want ErrNoClaim", err)
	}
}

// The marker is made after the checks. One-time use must still hold: of
// many redeems of one valid code at the same time, exactly one succeeds.
func TestRedeemIsOnceUnderConcurrency(t *testing.T) {
	s, _ := testServer(t)
	claims, c := issueTestClaim(t, s)
	const n = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		wins  int
		start = make(chan struct{})
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := RedeemClaim(claims, c.Code); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d of %d parallel redeems of one code succeeded, want 1", wins, n)
	}
}

// The command of the operator checks the script against the hash of the
// script for PI_IP, the address that www binds. A request with a different
// Host gets that same script. It does not get a script that fails the hash
// and spends the code.
func TestClaimScriptTakesThePiFromTheBind(t *testing.T) {
	s, _ := testServer(t)
	_, c := issueTestClaim(t, s)
	r := httptest.NewRequest(http.MethodGet, "/claim/"+c.Code, nil)
	r.Host = "10.9.9.9"
	r.RemoteAddr = "10.77.0.10:40000"
	w := httptest.NewRecorder()
	s.serve(w, r)
	_, lines := ClaimCommand(s.Bind, c)
	if w.Code != http.StatusOK || lines[0] != "h="+sum(w.Body.Bytes()) {
		t.Fatalf("status %d; script for Host 10.9.9.9 does not match the command for %s:\n%s", w.Code, s.Bind, w.Body.String())
	}
}
