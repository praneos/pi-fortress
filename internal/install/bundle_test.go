package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBundleDoesNotRunTheSSHKeygenFirstOnPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ssh-keygen"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	signers := filepath.Join(dir, "release-signers")
	bundle := filepath.Join(dir, "bundle.tar")
	for _, p := range []string{signers, bundle, bundle + ".sig"} {
		if err := os.WriteFile(p, []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyBundle(signers, bundle, bundle+".sig", DistNamespace, DistPrincipal); err == nil {
		t.Fatal("VerifyBundle accepted a bundle with no valid signature; it ran the ssh-keygen from PATH")
	}
}
