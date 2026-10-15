package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"pi-fortress/internal/broker"
)

func TestServeAdminSocketIsOwnerOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfadm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	if err := os.WriteFile(sock, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := serveAdmin(ctx, sock, &broker.Broker{}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		t.Fatalf("admin socket mode %v, want a 0600 socket", st.Mode())
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestServeAdminListenFailure(t *testing.T) {
	if err := serveAdmin(context.Background(), filepath.Join(t.TempDir(), "no", "admin.sock"), &broker.Broker{}); err == nil {
		t.Fatal("serveAdmin listened in a directory that does not exist")
	}
}
