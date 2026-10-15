package corepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fuzz policy below builds these tables. They stay separate, as in
// Forward. allow includes subdomains. An exact core host does not. A "*."
// core host includes subdomains but not itself.
var (
	fuzzAllowText = "github.com\npf-core-echo.test\n# comment\n\n  claude.ai  \n"
	fuzzCoreText  = "api.x.ai XAI_API_KEY\n*.example.com CLAUDE_OAT\ngithub.com GITHUB_TOKEN\npf-core-echo.test *\n"

	fuzzAllow  = []string{"github.com", "pf-core-echo.test", "claude.ai"}
	fuzzExact  = []string{"api.x.ai", "github.com"}
	fuzzSuffix = []string{"example.com"}
)

// refAllowed decides from the policy text, not from the maps that
// LoadForward built. Thus a widening in the loader, in normHost or in
// coreListed appears here as a disagreement. It does not appear as a name
// that the agent can suddenly reach.
func refAllowed(name string, lab bool) bool {
	n := normHost(name)
	switch n {
	case OpenEcho:
		return true
	case CoreEcho:
		return lab
	}
	if n == "" || strings.HasPrefix(n, ".") || strings.Contains(n, "..") {
		return false
	}
	for _, a := range fuzzAllow {
		if n == a || strings.HasSuffix(n, "."+a) {
			return true
		}
	}
	for _, h := range fuzzExact {
		if n == h {
			return true
		}
	}
	for _, s := range fuzzSuffix {
		if strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}

func fuzzForward(t *testing.T) *Forward {
	t.Helper()
	dir := t.TempDir()
	ap, cp := filepath.Join(dir, "allow.domains"), filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(ap, []byte(fuzzAllowText), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(fuzzCoreText), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := LoadForward(ap, cp)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// FuzzForwardAllowed: when paranoid is armed, this function decides if the
// agent segment can reach a name at all. Thus the test compares it with the
// policy text, for all names that a client can put in an SNI or a Host header.
func FuzzForwardAllowed(f *testing.F) {
	for _, s := range []string{
		"github.com", "api.github.com", "evilgithub.com", "github.com.evil.example",
		"api.x.ai", "evil.api.x.ai", "example.com", "a.example.com",
		"API.GitHub.COM.", "github.com..", " github.com ", "", ".", "..",
		"x..github.com", ".github.com", "x..a.example.com",
		OpenEcho, CoreEcho, "x." + CoreEcho, "claude.ai", "sub.claude.ai",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, name string, lab bool) {
		// All callers normalize. Some normalize a name that another caller
		// already normalized. The two passes must agree.
		if n := normHost(name); normHost(n) != n {
			t.Fatalf("normHost(%q) = %q, and again %q", name, n, normHost(n))
		}
		fw := fuzzForward(t)
		got := fw.Allowed(name, lab)
		if want := refAllowed(name, lab); got != want {
			t.Fatalf("Allowed(%q, lab=%v) = %v, policy text says %v", name, lab, got, want)
		}
		// One daemon asks the oracle with an SNI. The other daemon asks with a
		// Host. The two arrive with different casing and trailing dots. They must
		// not give different decisions.
		if n := normHost(name); fw.Allowed(n, lab) != got {
			t.Fatalf("Allowed(%q)=%v but Allowed(%q)=%v", name, got, n, fw.Allowed(n, lab))
		}
		if got && normHost(name) != OpenEcho && normHost(name) != CoreEcho {
			// A name must not be allowed because it shares a tail with a listed
			// name across a label boundary. evilgithub.com is not
			// github.com.
			n := normHost(name)
			aligned := false
			for _, base := range append(append(append([]string{}, fuzzAllow...), fuzzExact...), fuzzSuffix...) {
				if n == base || strings.HasSuffix(n, "."+base) {
					aligned = true
				}
			}
			if !aligned {
				t.Fatalf("Allowed(%q) with no label-aligned listed name", name)
			}
		}
	})
}

// FuzzLoadForwardFiles: the two files are root-owned policy. But pf compile
// reads them directly from the disk. It puts each name that Names returns
// into a dnsmasq server=/NAME/# line. A name with a slash, a hash or a
// control byte writes a directive that the operator did not write. Or it
// prevents the start of dnsmasq, and this also stops the agent resolver.
func FuzzLoadForwardFiles(f *testing.F) {
	f.Add(fuzzAllowText, fuzzCoreText)
	f.Add("github.com\n", "api.x.ai K\n")
	f.Add("a/b\n", "*.c K\n")
	f.Add("\x01evil.com\n", "x\x00y K\n")
	f.Add("#only a comment\n", "")
	f.Add("*\n*.*\n", "* K\n")
	f.Fuzz(func(t *testing.T, allow, core string) {
		dir := t.TempDir()
		ap, cp := filepath.Join(dir, "allow.domains"), filepath.Join(dir, "core.hosts")
		if err := os.WriteFile(ap, []byte(allow), 0644); err != nil {
			t.Skip()
		}
		if err := os.WriteFile(cp, []byte(core), 0644); err != nil {
			t.Skip()
		}
		fw, err := LoadForward(ap, cp)
		if err != nil {
			return
		}
		for _, n := range fw.Names() {
			if n == "" {
				t.Fatalf("Names returned an empty name from %q / %q", allow, core)
			}
			if n == OpenEcho || n == CoreEcho {
				t.Fatalf("Names sent the echo fixture %q upstream", n)
			}
			if strings.ContainsAny(n, "/#*") {
				t.Fatalf("name %q breaks a dnsmasq server=/NAME/# directive", n)
			}
			for _, r := range n {
				if r < 0x21 || r == 0x7f {
					t.Fatalf("name %q carries control byte %#x", n, r)
				}
			}
		}
	})
}
