package corepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The policy compares names as ASCII bytes. It never decodes punycode.
// An "xn--" label that decodes to ASCII ("xn--github-" to "github") is a
// different name, so it does not match the entry that the decoded form
// names. A program that decodes punycode before it compares names can
// see both forms as one name.
func TestPunycodeLabelIsNotDecoded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts")
	if err := os.WriteFile(path, []byte("github.com\n*.example.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"xn--github-.com", "XN--GITHUB-.COM", "xn--github-.com.",
		"github.xn--com-", "xn--example-.org", "api.xn--example-.org",
	} {
		if p.HostAllowed(name) {
			t.Errorf("%q matched an entry for its decoded form", name)
		}
	}
	for _, name := range []string{"github.com", "api.example.org", "xn--bcher-kva.example.org"} {
		if !p.HostAllowed(name) {
			t.Errorf("%q: want allowed", name)
		}
	}
	if p.Authority("github.com", "xn--github-.com") {
		t.Error("Host xn--github-.com accepted under SNI github.com")
	}
	if p.Authority("xn--github-.com", "github.com") {
		t.Error("SNI xn--github-.com accepted")
	}
	// A deny table sees the "xn--" form as another name. It is not a way
	// around the deny entry: DNS and TLS also use the name as bytes, so
	// the "xn--" form never reaches the host of the deny entry.
	if HostIn("xn--evil-.example", map[string]struct{}{"evil.example": {}}) {
		t.Error("xn--evil-.example matched evil.example")
	}
}

// ALabels gives the xn-- form (RFC 3492) of each label that is not ASCII.
// The pairs come from RFC 3492 and from the IANA IDN test names.
func TestALabels(t *testing.T) {
	for in, want := range map[string]string{
		"münchen.de":     "xn--mnchen-3ya.de",
		"bücher.example": "xn--bcher-kva.example",
		"Bücher.Example": "xn--bcher-kva.example",
		"*.münchen.de":   "*.xn--mnchen-3ya.de",
		"例え.テスト":         "xn--r8jz45g.xn--zckzah",
		"github.com":     "github.com",
	} {
		if got := ALabels(in); got != want {
			t.Errorf("ALabels(%q) = %q, want %q", in, got, want)
		}
	}
}

// A core.hosts host that is not ASCII never matches: the SNI and the Host
// carry the xn-- form. The line is skipped, with a warning that gives the
// form to write. The forward set skips it too.
func TestNonASCIIHostIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.hosts.local")
	if err := os.WriteFile(path, []byte("github.com GITHUB_TOKEN\nmünchen.de CLAUDE_OAT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Hosts["münchen.de"]; ok || len(p.HostsWithKind("CLAUDE_OAT")) != 0 {
		t.Fatal("the non-ASCII line binds a host")
	}
	if !p.HostAllowed("github.com") {
		t.Fatal("the line before it is lost")
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "core.hosts.local line 2") || !strings.Contains(p.Warnings[0], "xn--mnchen-3ya.de") {
		t.Fatalf("warnings: %q", p.Warnings)
	}
	if f := testForward(t, "", "münchen.de CLAUDE_OAT\n"); f.Allowed("münchen.de", false) {
		t.Fatal("the forward set keeps the non-ASCII line")
	}
}
