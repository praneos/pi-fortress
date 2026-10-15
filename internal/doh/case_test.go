package doh

import "testing"

// cleanPath changes the path to lowercase. An origin server does not do
// this: HTTP paths are case-sensitive, and only the scheme and host are
// not. But it is intentional. This test pins it, so that a person who
// reads the RFC and not the threat model does not "fix" it. The classifier
// asks if an origin server can read the target as DoH. Some origin servers
// ignore case (IIS, a case-insensitive filesystem, a CDN route). The cost of
// one path too many is a 403 that the agent sees and can try again. The
// cost of one path too few is the DNS pin.
func TestCaseVariedPathIsStillDoH(t *testing.T) {
	for _, target := range []string{
		"/dns-query",
		"/DNS-Query",
		"/DNS-QUERY",
		"https://dns.google/DNS-Query",
		"/DNS-Query;jsessionid=1",
		"/a/../DNS-Query/",
		"/dns-quer%59",
	} {
		if !HTTP(target, "", "") {
			t.Errorf("%q not classified as DoH", target)
		}
	}
}

// The lowercase change makes only the path comparison wider. A target that
// is not a resolver call stays not a resolver call, for all cases.
func TestCaseFoldingDoesNotSwallowOrdinaryPaths(t *testing.T) {
	for _, target := range []string{
		"/Upload/dns-queryable.json",
		"/API/Resolve",
		"/v1/RESOLVE?id=7",
		"/DNS-Queries",
	} {
		if HTTP(target, "application/json", "application/json") {
			t.Errorf("%q refused as DoH", target)
		}
	}
}
