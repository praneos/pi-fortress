package broker

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/secrets"
)

func adminStore(t *testing.T) (*secrets.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	body := secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN") + "=lab_fence_github\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	st := secrets.Open(path)
	if err := st.Seal([]byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	st.Lock()
	return st, path
}

func ask(t *testing.T, a *Admin, line string) string {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() { _ = a.Serve(context.Background(), c2) }()
	// net.Pipe is unbuffered. If the server stops the read of a request (one
	// past the length cap), this write blocks forever.
	go func() { _, _ = c1.Write([]byte(line + "\n")) }()
	buf := make([]byte, 512)
	_ = c1.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, _ := c1.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func TestAdminUnlockCycle(t *testing.T) {
	st, _ := adminStore(t)
	var slept []time.Duration
	a := &Admin{Store: st, Sleep: func(d time.Duration) { slept = append(slept, d) }}

	if got := ask(t, a, secrets.AdminState); got != "sealed locked" {
		t.Fatal(got)
	}
	pass := func(p string) string {
		return secrets.AdminUnlock + " " + base64.StdEncoding.EncodeToString([]byte(p))
	}
	if got := ask(t, a, pass("wrong horse")); !strings.HasPrefix(got, "err ") {
		t.Fatal(got)
	}
	// A wrong passphrase is still wrong after the store is open. The reply
	// does not say which part failed.
	if got := ask(t, a, pass("wrong horse")); !strings.HasPrefix(got, "err ") {
		t.Fatal(got)
	}
	if len(slept) != 1 || slept[0] != adminBackoffStep {
		t.Fatalf("backoff %v: the second attempt must wait, the first must not", slept)
	}
	if got := ask(t, a, pass("correct horse")); got != "ok" {
		t.Fatal(got)
	}
	if got := ask(t, a, secrets.AdminState); got != "sealed unlocked" {
		t.Fatal(got)
	}
	snap, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap[secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN")].Live != "lab_fence_github" {
		t.Fatalf("%+v", snap)
	}
	if got := ask(t, a, secrets.AdminLock); got != "ok" {
		t.Fatal(got)
	}
	if got := ask(t, a, secrets.AdminState); got != "sealed locked" {
		t.Fatal(got)
	}
	// A success clears the penalty.
	slept = nil
	if got := ask(t, a, pass("wrong horse")); !strings.HasPrefix(got, "err ") {
		t.Fatal(got)
	}
	if len(slept) != 0 {
		t.Fatalf("backoff %v was not reset by the success", slept)
	}
}

func TestAdminRejectsJunk(t *testing.T) {
	st, _ := adminStore(t)
	a := &Admin{Store: st, Sleep: func(time.Duration) {}}
	for _, line := range []string{"", "SUBSTITUTE", "UNLOCK !!!not base64!!!", strings.Repeat("A", 9<<10)} {
		if got := ask(t, a, line); !strings.HasPrefix(got, "err ") {
			t.Fatalf("%q -> %q", line, got)
		}
	}
	if got := ask(t, a, secrets.AdminState); got != "sealed locked" {
		t.Fatalf("junk changed the state: %s", got)
	}
}
