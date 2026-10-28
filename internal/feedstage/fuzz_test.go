package feedstage

import (
	"strings"
	"testing"

	"pi-fortress/internal/policycompile"
)

// FuzzCheckLine: a line that CheckLine accepts uses only the bytes of its
// kind, fits the line cap, is the output of the compile parser, and has
// none of the bytes that nft or dnsmasq give a meaning to.
func FuzzCheckLine(f *testing.F) {
	for _, s := range []string{
		"192.0.2.1", "1.2.3.0/24", "1.2.3.4/24", "10.0.0.1", "::ffff:1.2.3.4",
		"ads.example.com", "*.example.com", "Ads.Example.com.", "x.local",
		"1.2.3.4 }", "x.com\nadd rule", "server=/x/1.1.1.1", "a\x1b]0;t\x07.com",
		"001.002.003.004", "xn--80ak6aa92e.com", "",
	} {
		for k := range uint8(3) {
			f.Add(k, s)
		}
	}
	f.Fuzz(func(t *testing.T, k uint8, line string) {
		kind := Kind(k % 3)
		if CheckLine(kind, line) != "" {
			return
		}
		if len(line) == 0 || len(line) > kind.lineMax() {
			t.Fatalf("accepted %q of length %d", line, len(line))
		}
		for i := 0; i < len(line); i++ {
			if !kind.allowed(line[i]) {
				t.Fatalf("accepted %q with byte 0x%02x", line, line[i])
			}
		}
		if strings.ContainsAny(line, " \t\r\n{};#=\"'*,\\") {
			t.Fatalf("accepted %q with a syntax byte", line)
		}
		if kind != KindIPs && strings.Contains(line, "/") {
			t.Fatalf("accepted %q with a slash in a name list", line)
		}
		var got string
		switch kind {
		case KindIPs:
			got, _ = policycompile.ParseIPv4(line)
		case KindBlockDomains:
			got, _ = policycompile.ParseToken("block_domains", line)
		default:
			got, _ = policycompile.ParseToken("names", line)
		}
		if got != line {
			t.Fatalf("accepted %q, the parser gives %q", line, got)
		}
	})
}

// FuzzFilterReport: each kept line has only printable ASCII, fits 512
// bytes and starts with a report verb.
func FuzzFilterReport(f *testing.F) {
	for _, s := range []string{
		"OK a: 1 ips\n", "FAIL b: \x1b]0;t\x07\r\n", "junk\nWARN c: caf\xc3\xa9\n",
		"STALE " + strings.Repeat("y", 700), "\x00\x00\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got := FilterReport(b)
		if len(got) > reportLines {
			t.Fatalf("kept %d lines", len(got))
		}
		for _, l := range got {
			if len(l) > reportLineMax {
				t.Fatalf("kept a line of %d bytes", len(l))
			}
			for i := 0; i < len(l); i++ {
				if l[i] < 0x20 || l[i] > 0x7e {
					t.Fatalf("kept byte 0x%02x in %q", l[i], l)
				}
			}
			verb, _, _ := strings.Cut(l, " ")
			if !reportVerbs[verb] {
				t.Fatalf("kept %q", l)
			}
		}
	})
}
