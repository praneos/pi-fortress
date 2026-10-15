package policycompile

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzParseDomain(f *testing.F) {
	f.Add("*.Example.COM.")
	f.Add(strings.Repeat("a", 64) + ".com")
	f.Fuzz(func(t *testing.T, s string) {
		name, ok := ParseDomain(s)
		if !ok {
			return
		}
		if len(name) > 253 || name == "" || strings.ToLower(name) != name || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
			t.Fatalf("accepted %q -> %q", s, name)
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				t.Fatalf("bad label %q in %q", label, name)
			}
		}
		if _, again := ParseDomain(name); !again {
			t.Fatalf("output %q is not itself accepted", name)
		}
	})
}

func FuzzParseIPv4(f *testing.F) {
	f.Add("1.2.3.0/24")
	f.Add("10.0.0.1")
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := ParseIPv4(s)
		if !ok {
			return
		}
		var p netip.Prefix
		if strings.Contains(out, "/") {
			pp, err := netip.ParsePrefix(out)
			if err != nil {
				t.Fatalf("accepted %q -> unparseable %q", s, out)
			}
			p = pp
		} else {
			a, err := netip.ParseAddr(out)
			if err != nil {
				t.Fatalf("accepted %q -> unparseable %q", s, out)
			}
			p = netip.PrefixFrom(a, 32)
		}
		if p.Addr().IsPrivate() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsMulticast() {
			t.Fatalf("reserved address accepted: %q -> %q", s, out)
		}
	})
}
