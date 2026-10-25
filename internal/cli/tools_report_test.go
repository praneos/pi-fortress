package cli

import (
	"crypto/x509"
	"strings"
	"testing"
)

// The report of pf fetch holds text that a feed server supplies: the
// error of a TLS handshake names the hosts in the certificate. A control
// character in such a name must not get to the terminal of the operator.
func TestFetchReportEscapesControlCharacters(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"a\x1b]0;title\x07b.example", "c\x1b[2Jd.example"}}
	herr := x509.HostnameError{Certificate: cert, Host: "feed.example"}
	report := []string{
		"FAIL f: " + herr.Error(),
		"REDIRECT f: https://feed.example/\u009b31m",
		"OK f: 3 domains",
	}
	var out strings.Builder
	printReport(&out, report)
	got := out.String()
	for _, r := range got {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r > 0x7e {
			t.Fatalf("control or non-ASCII rune %U in report: %q", r, got)
		}
	}
	if !strings.Contains(got, "a?]0;title?b.example") || !strings.Contains(got, "OK f: 3 domains\n") {
		t.Fatalf("report: %q", got)
	}
	if n := strings.Count(got, "\n"); n != len(report) {
		t.Fatalf("lines: %d, want %d: %q", n, len(report), got)
	}
}
