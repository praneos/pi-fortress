package www

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// The claim carries the hashes of the files that www serves. The command
// that the operator pastes checks the claim script that www will render
// from that claim, byte for byte.
func TestClaimCommandMatchesTheServedScript(t *testing.T) {
	s, ts := testServer(t)
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(claims, "a1b2c3d4e5f67890", []string{"GITHUB_TOKEN"}, "github.com")
	if err != nil {
		t.Fatal(err)
	}
	setup, _ := os.ReadFile(filepath.Join(s.Dir, "setup.sh"))
	ca, _ := os.ReadFile(filepath.Join(s.Dir, "ca.pem"))
	if _, err := os.Stat("/vagrant/vm/agent/setup.sh"); err == nil {
		t.Skip("a lab VM serves /vagrant's setup.sh, not the test's")
	}
	if c.SetupSHA256 != sum(setup) || c.CASHA256 != sum(ca) {
		t.Fatalf("claim hashes %s %s, want %s %s", c.SetupSHA256, c.CASHA256, sum(setup), sum(ca))
	}
	// The Host of the test server is 127.0.0.1:<port>. www reads it as the
	// address of the Pi, as it reads 10.77.0.1 for a real agent.
	cmd, lines := ClaimCommand("127.0.0.1", c)
	_, body := get(t, ts.URL+"/claim/"+c.Code)
	if lines[0] != "h="+sum([]byte(body)) {
		t.Fatalf("command hash %q is not the served script's %s", lines[0], sum([]byte(body)))
	}
	if !strings.Contains(body, `echo "`+c.SetupSHA256+`  $S" | sha256sum -c`) || !strings.Contains(body, `sudo bash "$S" "$PI" '`+c.CASHA256+`'`) {
		t.Fatalf("script does not check setup.sh or hand setup.sh the CA hash:\n%s", body)
	}
	if strings.HasSuffix(cmd, "| sh") || cmd != lines[0]+"; "+lines[1]+" "+lines[2] {
		t.Fatalf("one-line form %q", cmd)
	}
	// The claim overlay of the TUI draws each line at column 0 behind a
	// two-space indent. So a line has 78 columns on an 80-column terminal. The
	// widest Pi address is the worst case.
	for _, pi := range []string{"127.0.0.1", "255.255.255.255"} {
		_, lines := ClaimCommand(pi, c)
		for _, l := range lines {
			if shown := "  " + l; len(shown) > 80 {
				t.Errorf("shown line is %d columns: %s", len(shown), shown)
			}
		}
	}
}

// runPasted runs the one-line command of the operator in /bin/sh. It uses a
// fake curl that answers /claim/ with claimBody and /setup.sh with
// setupBody, and a fake sudo that records its arguments.
func runPasted(t *testing.T, c Claim, claimBody, setupBody string) (string, string, error) {
	t.Helper()
	dir, bin, home := t.TempDir(), t.TempDir(), t.TempDir()
	cb, sb, args := filepath.Join(dir, "claim"), filepath.Join(dir, "setup"), filepath.Join(dir, "sudo.args")
	os.WriteFile(cb, []byte(claimBody), 0644)
	os.WriteFile(sb, []byte(setupBody), 0644)
	fakeBin(t, bin, "curl", `case "$*" in
*/claim/*) cat '`+cb+`' >"$2" ;;
*/setup.sh*) cat '`+sb+`' >"$4" ;;
*) exit 22 ;;
esac
`)
	fakeBin(t, bin, "sudo", `echo "$@" >'`+args+`'`)
	cmd, _ := ClaimCommand("10.77.0.1", c)
	sh := exec.Command("/bin/sh", "-c", cmd)
	sh.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := sh.CombinedOutput()
	got, _ := os.ReadFile(args)
	return string(out), string(got), err
}

func TestPastedClaimRunsOnlyTheCheckedScripts(t *testing.T) {
	setup := "#!/bin/bash\necho setup\n"
	c := Claim{Code: "ABCDEF", Slot: "a1b2c3d4e5f67890", Kinds: []string{"ANTHROPIC_API_KEY"},
		SetupSHA256: sum([]byte(setup)), CASHA256: strings.Repeat("ab", 32)}
	good := ClaimScript("10.77.0.1", c)

	out, sudo, err := runPasted(t, c, good, setup)
	if err != nil || !strings.Contains(out, "enrolled") || !strings.Contains(sudo, " 10.77.0.1 "+c.CASHA256) {
		t.Fatalf("the honest claim did not enrol: %v\n%s\nsudo: %s", err, out, sudo)
	}

	// A host that answers for the address of the Pi swaps the claim script.
	out, sudo, err = runPasted(t, c, good+"echo owned\n", setup)
	if err == nil || strings.Contains(out, "owned") || strings.Contains(out, "enrolled") || sudo != "" {
		t.Fatalf("a swapped claim script ran: %v\n%s\nsudo: %s", err, out, sudo)
	}

	// Or it does not change the claim, and swaps setup.sh. setup.sh runs as root.
	out, sudo, err = runPasted(t, c, good, setup+"echo owned\n")
	if err == nil || strings.Contains(out, "enrolled") || sudo != "" {
		t.Fatalf("a swapped setup.sh reached sudo: %v\n%s\nsudo: %s", err, out, sudo)
	}
}

// A claim issued when the gateway had no setup.sh or ca.pem carries no hash
// to check either file against. So it must enrol nothing. It must not run
// the content that answers for the address of the gateway.
func TestClaimWithoutHashesRunsNothing(t *testing.T) {
	setup := "#!/bin/bash\necho setup\n"
	for _, c := range []Claim{
		{Code: "ABCDEF", Slot: "a1b2c3d4e5f67890", Kinds: []string{"ANTHROPIC_API_KEY"}, CASHA256: strings.Repeat("ab", 32)},
		{Code: "ABCDEF", Slot: "a1b2c3d4e5f67890", Kinds: []string{"ANTHROPIC_API_KEY"}, SetupSHA256: sum([]byte(setup))},
	} {
		out, sudo, err := runPasted(t, c, ClaimScript("10.77.0.1", c), setup)
		if err == nil || strings.Contains(out, "enrolled") || sudo != "" || !strings.Contains(out, "issue another") {
			t.Fatalf("a claim without both hashes ran: %v\n%s\nsudo: %s", err, out, sudo)
		}
	}
}
