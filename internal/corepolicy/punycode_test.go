package corepolicy

import (
	"os"
	"path/filepath"
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
