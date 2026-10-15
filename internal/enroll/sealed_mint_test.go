package enroll

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

func sealedStore(t *testing.T) (path string, before []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "secrets.env")
	body := secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN") + "=ghp_example\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Open(path).Seal([]byte("passphrase")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, before
}

// pf enroll runs in its own process with its own store and no key, so
// it cannot seal a row that it mints. It must say so before it reads the
// tokens of the operator from stdin, and before it writes the agent paste
// file. A refusal that arrives after the paste is consumed has already
// cost them the clipboard.
func TestMintOnASealedStoreRefusesBeforeItReadsTheToken(t *testing.T) {
	path, before := sealedStore(t)
	stdin := strings.NewReader("sk-ant-oat01-aaaaaaaaaaaaaaaa\nsk-ant-ort01-bbbbbbbbbbbbbbbb\n")
	unread := stdin.Len()
	paste := filepath.Join(t.TempDir(), "paste")
	var out, errb bytes.Buffer
	code := MainIO([]string{"--secrets", path, "mint", "--kind", "claude", "--stdin", "--out", paste}, stdin, &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1: out=%q err=%q", code, out.String(), errb.String())
	}
	for _, want := range []string{"store is locked", "sudo pf enroll unseal", "sudo pf enroll seal", "sudo pf unlock"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("the refusal never names %q: %s", want, errb.String())
		}
	}
	if out.Len() != 0 {
		t.Errorf("a refused mint printed on stdout: %s", out.String())
	}
	if stdin.Len() != unread {
		t.Errorf("the refusal read %d bytes off stdin before it fired", unread-stdin.Len())
	}
	if _, err := os.Stat(paste); err == nil {
		t.Error("a refused mint still wrote the agent paste")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("the store was rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// An empty value is still a mint. A new slot writes no secret, and that
// was the argument to let it through. But it is refused all the same, so
// there is one rule about a sealed store, not two.
func TestMintWithNoValueIsRefusedToo(t *testing.T) {
	path, before := sealedStore(t)
	var out, errb bytes.Buffer
	if code := MainIO([]string{"--secrets", path, "mint", "--kind", "GITHUB_TOKEN"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1: out=%q err=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "store is locked") {
		t.Errorf("errb=%q", errb.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("the store was rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// The refusal applies only to mint. delete rewrites lines and never needs
// a value. An operator must be able to drop a slot from a box that they
// cannot unlock, so delete continues to work.
func TestDeleteStillWorksOnASealedStore(t *testing.T) {
	path, _ := sealedStore(t)
	var out, errb bytes.Buffer
	if code := MainIO([]string{"--secrets", path, "delete", "--slot", "a1b2c3d4e5f67890"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out.String(), errb.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "a1b2c3d4e5f67890") {
		t.Fatalf("the slot survived the delete:\n%s", raw)
	}
	if !strings.Contains(string(raw), "#pf-sealed") {
		t.Fatalf("the delete dropped the sealed header:\n%s", raw)
	}
}

// state goes to a process that never holds the key. So on a sealed
// store, only the broker knows whether the store is open. Before this,
// no command could print the line "sealed, unlocked".
func TestStateOfASealedStoreIsTheBrokersToSay(t *testing.T) {
	path, _ := sealedStore(t)
	old := brokerState
	t.Cleanup(func() { brokerState = old })
	for reply, want := range map[string]string{
		"sealed unlocked": "sealed, unlocked\n",
		"sealed locked":   "sealed, locked: pf unlock\n",
		"":                "sealed; the broker did not say whether it holds the key: pf unlock -state\n",
	} {
		brokerState = func() string { return reply }
		var out, errb strings.Builder
		if code := MainIO([]string{"--secrets", path, "state"}, strings.NewReader(""), &out, &errb); code != 0 {
			t.Fatalf("broker says %q: exit %d, %s", reply, code, errb.String())
		}
		if out.String() != want {
			t.Errorf("broker says %q: state printed %q, want %q", reply, out.String(), want)
		}
	}
}
