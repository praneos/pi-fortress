package fetch

import (
	"net/netip"
	"strings"
	"testing"

	"pi-fortress/internal/policycompile"
)

// checkDomain fails when a domains feed gives an entry that is not one
// canonical name of two or more labels. An empty entry, a bare label, a
// wildcard, a root, an address or a local name would block much more
// than one site.
func checkDomain(t *testing.T, feed, d string, numericOK bool) {
	t.Helper()
	if got, ok := policycompile.ParseDomain(d); !ok || got != d {
		t.Fatalf("%s: entry %q is not a canonical domain (%q, %v)", feed, d, got, ok)
	}
	if !strings.Contains(d, ".") || strings.ContainsAny(d, "*/ ") {
		t.Fatalf("%s: entry %q is too wide", feed, d)
	}
	if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".localhost") {
		t.Fatalf("%s: local name %q", feed, d)
	}
	if _, err := netip.ParseAddr(d); err == nil && !numericOK {
		t.Fatalf("%s: address %q read as a name", feed, d)
	}
}

// checkIP fails when an ips feed gives an entry that is not one IPv4
// address or masked prefix, of /8 or narrower, outside the reserved nets.
func checkIP(t *testing.T, feed, s string) {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			t.Fatalf("%s: entry %q is not an address or prefix", feed, s)
		}
		if a.String() != s {
			t.Fatalf("%s: entry %q is not canonical", feed, s)
		}
		p = netip.PrefixFrom(a, 32)
	} else if p.String() != s || p.Masked() != p || p.Bits() == 32 {
		t.Fatalf("%s: prefix %q is not canonical", feed, s)
	}
	if !p.Addr().Is4() || p.Bits() < 8 {
		t.Fatalf("%s: entry %q is too wide or not IPv4", feed, s)
	}
	for _, r := range policycompile.Reserved {
		if p.Overlaps(r) {
			t.Fatalf("%s: entry %q overlaps reserved %s", feed, s, r)
		}
	}
}

// FuzzParseFeeds: a feed body comes from the internet. No body makes a
// parser panic, and each entry that a parser gives is valid for its kind.
// Each format gives at most one entry for each line, except hosts, which
// gives at most one for each name on a line.
func FuzzParseFeeds(f *testing.F) {
	f.Add("0.0.0.0 ads.example.com tracker.example.net\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n# c\n")
	f.Add("example.com\n*.example.org\n.\n*.\n*\ncom\nfoo.local\n1.2.3.4\n")
	f.Add("; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n0.0.0.0/0\n10.0.0.0/8\n8.0.0.0/7\n192.0.2.1\n")
	f.Add(":: a.b\n::1 x.y.\n0.0.0.0 *.c.d ;x\n\x00 a.b\n")
	f.Add("0.0.0.0/0\n::/0\n255.255.255.255\n1.2.3.4/32\n1.2.3.5/31\n")
	f.Fuzz(func(t *testing.T, body string) {
		lines := strings.Count(body, "\n") + 1
		for _, d := range ParseHosts(body) {
			checkDomain(t, "hosts", d, false)
		}
		if n := len(ParseHosts(body)); n > len(strings.Fields(body)) {
			t.Fatalf("hosts: %d entries from %d tokens", n, len(strings.Fields(body)))
		}
		plain := ParsePlain(body, "domains")
		if len(plain) > lines {
			t.Fatalf("plain: %d entries from %d lines", len(plain), lines)
		}
		for _, d := range plain {
			checkDomain(t, "plain", d, true)
		}
		ips := ParsePlain(body, "ips")
		if len(ips) > lines {
			t.Fatalf("plain ips: %d entries from %d lines", len(ips), lines)
		}
		for _, s := range ips {
			checkIP(t, "plain ips", s)
		}
		sh := ParseSpamhaus(body)
		if len(sh) > lines {
			t.Fatalf("spamhaus: %d entries from %d lines", len(sh), lines)
		}
		for _, s := range sh {
			checkIP(t, "spamhaus", s)
		}
		// parseFeed only routes; it must give what the parser gives.
		for _, fd := range []Feed{{Format: "hosts", Kind: "domains"}, {Format: "spamhaus", Kind: "ips"}, {Kind: "ips"}, {Kind: "domains"}} {
			got := parseFeed(fd, body)
			var want []string
			switch {
			case fd.Format == "hosts":
				want = ParseHosts(body)
			case fd.Format == "spamhaus":
				want = sh
			case fd.Kind == "ips":
				want = ips
			default:
				want = plain
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("parseFeed %+v differs from its parser", fd)
			}
		}
	})
}
