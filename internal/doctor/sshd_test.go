package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sshdTree writes sshd_config and each sshd_config.d file into a temp
// dir and returns the path of sshd_config.
func sshdTree(t *testing.T, main string, drop map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for n, body := range drop {
		if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The Debian main file: Include first, PAM on, keyboard-interactive off.
const debianSSHD = "Include /SSHD/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n"

func sshdRung(t *testing.T, main string, drop map[string]string) Result {
	t.Helper()
	p := sshdTree(t, "", drop)
	main = strings.ReplaceAll(main, "/SSHD", filepath.Dir(p))
	if err := os.WriteFile(p, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	r, ok := SSHPasswordRung(p)
	if !ok {
		t.Fatal("no ssh rung with an sshd_config present")
	}
	return r
}

func TestSSHPasswordRungDefaultIsPasswords(t *testing.T) {
	r := sshdRung(t, debianSSHD, nil)
	if r.Status != Warn || !strings.Contains(r.Detail, "sshd default") {
		t.Fatalf("stock config = %v %q, want a warn naming the default", r.Status, r.Detail)
	}
}

func TestSSHPasswordRungKeyOnlyDropIn(t *testing.T) {
	r := sshdRung(t, debianSSHD, map[string]string{
		"99-pi-fortress.conf": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n",
	})
	if r.Status != OK {
		t.Fatalf("key-only drop-in = %v %q, want ok", r.Status, r.Detail)
	}
}

// sshd takes the first value. A file that sorts before ours wins.
func TestSSHPasswordRungEarlierFileWins(t *testing.T) {
	r := sshdRung(t, debianSSHD, map[string]string{
		"50-cloud-init.conf":  "PasswordAuthentication yes\n",
		"99-pi-fortress.conf": "PasswordAuthentication no\n",
	})
	if r.Status != Warn || !strings.Contains(r.Detail, "50-cloud-init.conf") {
		t.Fatalf("earlier yes = %v %q, want a warn naming 50-cloud-init.conf", r.Status, r.Detail)
	}
}

func TestSSHPasswordRungKbdInteractiveThroughPAM(t *testing.T) {
	r := sshdRung(t, "Include /SSHD/sshd_config.d/*.conf\nUsePAM yes\n", map[string]string{
		"99-x.conf": "PasswordAuthentication no\n",
	})
	if r.Status != Warn || !strings.Contains(r.Detail, "PAM") {
		t.Fatalf("kbd-interactive with PAM = %v %q, want a warn", r.Status, r.Detail)
	}
}

func TestSSHPasswordRungMatchBlockIsInconclusive(t *testing.T) {
	r := sshdRung(t, debianSSHD+"Match User op\n  PasswordAuthentication yes\n", map[string]string{
		"99-pi-fortress.conf": "PasswordAuthentication no\n",
	})
	if r.Status != Warn || !strings.Contains(r.Detail, "Match") {
		t.Fatalf("Match yes = %v %q, want a warn naming Match", r.Status, r.Detail)
	}
}

func TestSSHPasswordRungUnreadableIsInconclusive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	p := sshdTree(t, "", map[string]string{"99-pi-fortress.conf": "PasswordAuthentication no\n"})
	locked := filepath.Join(filepath.Dir(p), "sshd_config.d", "10-locked.conf")
	if err := os.WriteFile(locked, []byte("Port 22\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	main := "Include " + filepath.Join(filepath.Dir(p), "sshd_config.d", "*.conf") + "\nKbdInteractiveAuthentication no\n"
	if err := os.WriteFile(p, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ := SSHPasswordRung(p)
	if r.Status != Warn || !strings.Contains(r.Detail, "inconclusive") {
		t.Fatalf("unreadable drop-in = %v %q, want inconclusive", r.Status, r.Detail)
	}
}

func TestSSHPasswordRungNoSSHD(t *testing.T) {
	if _, ok := SSHPasswordRung(filepath.Join(t.TempDir(), "sshd_config")); ok {
		t.Fatal("a rung for a box with no sshd_config")
	}
}
