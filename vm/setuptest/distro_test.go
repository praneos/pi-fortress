//go:build distro

package setuptest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"pi-fortress/internal/testsupport"
)

func TestSetupDistros(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skip distro checks (no docker)")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("need openssl to mint a dummy CA")
	}
	root := testsupport.RepoRoot(t)
	setup := filepath.Join(root, "vm", "agent", "setup.sh")
	if _, err := os.Stat(setup); err != nil {
		t.Fatal(err)
	}
	workdir := t.TempDir()
	ca := filepath.Join(workdir, "ca.pem")
	key := filepath.Join(workdir, "key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", key, "-out", ca, "-days", "1", "-nodes", "-subj", "/CN=pi-fortress-test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, out)
	}

	cases := []struct {
		name, image, prep string
	}{
		{"ubuntu", "ubuntu:24.04", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null;"},
		{"debian", "debian:12", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null;"},
		{"fedora", "fedora:41", "true;"},
		{"rocky", "rockylinux:9", "true;"},
		{"arch", "archlinux:latest", "pacman -Sy --noconfirm ca-certificates >/dev/null;"},
		{"opensuse", "opensuse/leap:15.6", "true;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := exec.Command("docker", "run", "--rm",
				"-e", "PI_IP=10.77.0.1",
				"-e", "PI_FORTRESS_CA=/ca.pem",
				"-e", "PI_FORTRESS_SKIP_NET=1",
				"-v", setup+":/setup.sh:ro",
				"-v", ca+":/ca.pem:ro",
				c.image,
				"bash", "-c", c.prep+" bash /setup.sh",
			)
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, out)
			}
		})
	}
}
