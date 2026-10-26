package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

// wwwDir is a www directory that serves a setup.sh and a ca.pem, with an
// empty claims directory. Without the two files, no claim is issued.
func wwwDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"setup.sh": "#!/bin/sh\n", "ca.pem": "-----BEGIN CERTIFICATE-----\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "claims"), 0770); err != nil {
		t.Fatal(err)
	}
	return dir
}

// At the default 80x24 terminal, the operator copies the claim command from
// the screen as shown. Thus the full 64-digit hash and all of each command
// line must be on the screen. One digit less is a checksum that never
// matches. A lost && is a shell that runs half a command.
func TestClaimOverlayUnclippedAt80Columns(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = wwwDir(t)
	c.Net = map[string]string{"AGENT_IP": "10.77.0.10", "PI_IP": "255.255.255.255"}
	if _, err := secrets.Open(c.SecretsPath).MintKinds([]string{"OPENAI_API_KEY"}, map[string]string{"OPENAI_API_KEY": "sk-live"}); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(80, 24).Type(keys(netAgent, secKeys)+"c")).Last()
	rows := strings.Split(last, "\n")
	find := func(sub string) string {
		for _, r := range rows {
			if strings.Contains(r, sub) {
				return strings.TrimRight(r, " ")
			}
		}
		t.Fatalf("no row with %q:\n%s", sub, last)
		return ""
	}
	if !regexp.MustCompile(`^  h=[0-9a-f]{64}$`).MatchString(find("h=")) {
		t.Fatalf("hash line clipped: %q\n%s", find("h="), last)
	}
	if !regexp.MustCompile(`^  f=\$\(mktemp\) && curl -fsSo "\$f" http://255\.255\.255\.255/claim/[A-HJ-NP-Z2-9]{8} &&$`).MatchString(find("/claim/")) {
		t.Fatalf("fetch line clipped: %q\n%s", find("/claim/"), last)
	}
	if got := find("sha256sum -c"); got != `  echo "$h  $f" | sha256sum -c && sh "$f"` {
		t.Fatalf("check line clipped: %q", got)
	}
}

// The claim code redeems the slot for anyone who reads it. The passphrase
// prompt hides what it takes for that reason, but the claim code shows in
// bold. Thus the overlay says that the code is a secret, at 80 columns and
// with the line that closes it still on the screen.
func TestClaimOverlaySaysTheCodeIsSecret(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = wwwDir(t)
	if _, err := secrets.Open(c.SecretsPath).MintKinds([]string{"OPENAI_API_KEY"}, map[string]string{"OPENAI_API_KEY": "sk-live"}); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(80, 24).Type(keys(netAgent, secKeys)+"c")).Last()
	for _, want := range []string{"secret until redeemed; do not share this screen", "any key closes"} {
		if !strings.Contains(last, want) {
			t.Fatalf("the claim overlay has no %q:\n%s", want, last)
		}
	}
}
