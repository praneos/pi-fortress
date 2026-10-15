package base

import (
	"os"
	"path/filepath"
	"testing"
)

// A file that is not there is a configuration. A file that is there and
// cannot be read is a fault. LoadEnv gave the empty map for both. Thus a
// caller that validated against the contents of the file validated
// against nothing and let everything through.
func TestLoadEnvFileTellsAbsentFromUnreadable(t *testing.T) {
	dir := t.TempDir()
	env, err := LoadEnvFile(filepath.Join(dir, "absent.env"))
	if err != nil || len(env) != 0 {
		t.Fatalf("absent file: %v, %v; want an empty map and no error", env, err)
	}

	p := filepath.Join(dir, "house.env")
	if err := os.WriteFile(p, []byte("HOUSE_NET=192.168.50.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Mode 0 stops every reader except root. Root ignores the mode, and pf
	// runs as root on the Pi. Thus a root run cannot cause this failure.
	if os.Geteuid() != 0 {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		if env, err := LoadEnvFile(p); err == nil {
			t.Fatalf("unreadable file read as %v with no error", env)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	env, err = LoadEnvFile(p)
	if err != nil || env["HOUSE_NET"] != "192.168.50.0/24" {
		t.Fatalf("readable file: %v, %v", env, err)
	}
	// LoadEnv keeps its lenient contract for the callers that only
	// show what they found.
	if got := LoadEnv(filepath.Join(dir, "absent.env")); len(got) != 0 {
		t.Fatalf("LoadEnv(absent) = %v", got)
	}
}
