package broker

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
)

func fuzzForward(t *testing.T) *corepolicy.Forward {
	t.Helper()
	dir := t.TempDir()
	ap, cp := filepath.Join(dir, "allow.domains"), filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(ap, []byte("github.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte("api.x.ai K\n*.example.com K\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fw, err := corepolicy.LoadForward(ap, cp)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func fuzzRefListed(n string) bool {
	n = strings.ToLower(strings.TrimRight(strings.TrimSpace(n), "."))
	if n == "" {
		return false
	}
	if n == corepolicy.OpenEcho || n == corepolicy.CoreEcho {
		return true
	}
	return n == "github.com" || strings.HasSuffix(n, ".github.com") ||
		n == "api.x.ai" || strings.HasSuffix(n, ".example.com")
}

// FuzzParanoidHostDecision fuzzes the Host header. After the SNI is on the
// list, the agent can freely set this one field. prettyHost derives the
// name that paranoidRefuse asks the oracle about. Together, the two are the
// full Host-side deny. Whatever the header contains, the derived name must
// be a listed name. It must also be a case/port/dot normalisation of the
// name that the origin server reads in the header that it gets.
func FuzzParanoidHostDecision(f *testing.F) {
	for _, h := range []string{
		"github.com", "GITHUB.COM", "github.com:443", "github.com.", "github.com..",
		"api.github.com", "evil.example", "evilgithub.com", "github.com.evil.example",
		"api.x.ai", "evil.api.x.ai", "example.com", "a.example.com",
		"", " ", "  github.com  ", "[::1]:443", "github.com:443]", "github.com\t",
		"github.com:443@evil.example", "user@github.com",
	} {
		f.Add(h, "github.com")
		f.Add(h, "evil.example")
	}
	f.Fuzz(func(t *testing.T, host, sni string) {
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(
			"GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")))
		if err != nil {
			return
		}
		b := &Broker{Paranoid: true, Forward: fuzzForward(t), LabEcho: true}
		h := prettyHost(req, sni)
		if b.forwardAllowed(h) && !fuzzRefListed(h) {
			t.Fatalf("Host %q derived %q, which is on no list", host, h)
		}
		if h != strings.ToLower(h) {
			t.Fatalf("Host %q derived the uncased %q", host, h)
		}
		// The broker does not change the header that it sends to the origin
		// server. Thus the name that the oracle approved must be the authority of
		// that header, and not a prefix of a longer authority. If a header
		// normalises to nothing, the SNI decides instead. The engine already
		// examined the SNI.
		lit := req.Get("Host")
		want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.Split(lit, ":")[0]), "."))
		if want != "" && !strings.Contains(lit, "]") && h != want {
			t.Fatalf("Host %q: prettyHost gave %q, authority is %q", host, h, want)
		}
	})
}
