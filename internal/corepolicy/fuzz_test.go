package corepolicy

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fuzzPolicy(t *testing.T) *Policy {
	_, file, _, _ := runtime.Caller(0)
	p, err := Load(filepath.Join(filepath.Dir(file), "..", "..", "vm", "policy", "core.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// FuzzAuthority: the code grants substitution authority only for a listed
// SNI. It also requires that the Host header, without port and zone, is
// empty, equals the SNI, or is a subdomain of the SNI.
func FuzzAuthority(f *testing.F) {
	f.Add("api.anthropic.com", "api.anthropic.com:443")
	f.Add("API.Anthropic.COM.", "evil.com")
	f.Add("api.anthropic.com", "x.api.anthropic.com")
	f.Add("x..api.anthropic.com", "")
	f.Add("api.anthropic.com", "x..api.anthropic.com")
	f.Fuzz(func(t *testing.T, sni, host string) {
		p := fuzzPolicy(t)
		ok := p.Authority(sni, host)
		if !ok {
			return
		}
		sniN := normHost(sni)
		if strings.HasPrefix(sniN, ".") || strings.Contains(sniN, "..") {
			t.Fatalf("authority for sni %q with an empty label", sni)
		}
		if !p.listed(sniN) {
			t.Fatalf("authority for unlisted sni %q", sni)
		}
		h := host
		if i := strings.IndexAny(h, "%:"); i >= 0 {
			h = h[:i]
		}
		h = normHost(h)
		if h != "" && h != sniN && !strings.HasSuffix(h, "."+sniN) {
			t.Fatalf("authority with host %q for sni %q", host, sni)
		}
	})
}
