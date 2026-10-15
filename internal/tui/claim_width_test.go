package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

// At the default 80x24 terminal, the operator copies the claim command from
// the screen as shown. Thus the full 64-digit hash and all of each command
// line must be on the screen. One digit less is a checksum that never
// matches. A lost && is a shell that runs half a command.
func TestClaimOverlayUnclippedAt80Columns(t *testing.T) {
	c, _ := testConfig(t)
	c.WWWDir = t.TempDir()
	_ = os.MkdirAll(filepath.Join(c.WWWDir, "claims"), 0770)
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
	if !regexp.MustCompile(`^  f=\$\(mktemp\) && curl -fsSo "\$f" http://255\.255\.255\.255/claim/[A-Z0-9]{6} &&$`).MatchString(find("/claim/")) {
		t.Fatalf("fetch line clipped: %q\n%s", find("/claim/"), last)
	}
	if got := find("sha256sum -c"); got != `  echo "$h  $f" | sha256sum -c && sh "$f"` {
		t.Fatalf("check line clipped: %q", got)
	}
}
