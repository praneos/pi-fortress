package leases

import (
	"strings"
	"testing"
)

// FuzzParseLeases: a DHCP client sets the hostname column, so the lease
// file is untrusted text. The parser must not panic. It gives at most one
// lease for each line. Each field is one whitespace-free token of the
// line, the MAC is in lower case, and "*" (no name) is never a name.
func FuzzParseLeases(f *testing.F) {
	f.Add("1700000000 AA:BB:CC:DD:EE:FF 10.78.0.20 laptop 01:aa:bb:cc:dd:ee:ff\n")
	f.Add("0 aa:bb:cc:dd:ee:ff 10.78.0.21 * *\n1 x y z\n")
	f.Add("-9223372036854775808 m i h\n9223372036854775807 m i h c extra\n")
	f.Add("1700000000 aa:bb 10.78.0.22 a\x1b[2Jb\n\n  \n1700000000\x00 a b c\n")
	f.Fuzz(func(t *testing.T, text string) {
		out := ParseLeases(text)
		if lines := strings.Count(text, "\n") + 1; len(out) > lines {
			t.Fatalf("%d leases from %d lines", len(out), lines)
		}
		for _, l := range out {
			for _, s := range []string{l.MAC, l.IP, l.Hostname, l.ClientID} {
				if strings.ContainsAny(s, " \t\n\r\v\f") {
					t.Fatalf("field with whitespace: %q", s)
				}
			}
			if l.MAC == "" || l.IP == "" {
				t.Fatalf("empty MAC or IP: %+v", l)
			}
			if l.MAC != strings.ToLower(l.MAC) {
				t.Fatalf("MAC not lower case: %q", l.MAC)
			}
			if l.Hostname == "*" {
				t.Fatalf("'*' kept as a name")
			}
			if l.Hostname != "" && !strings.Contains(text, l.Hostname) {
				t.Fatalf("name %q not in the input", l.Hostname)
			}
		}
	})
}

// FuzzParseReservations: house.hosts is operator text, but a bad line must
// not panic or stop the read. Comments and blank lines give nothing. Each
// field has no edge space, and the MAC is in lower case.
func FuzzParseReservations(f *testing.F) {
	f.Add("AA:BB:CC:DD:EE:FF,10.78.0.20,printer\n# comment\n\n")
	f.Add(" aa:bb:cc:dd:ee:ff , 10.78.0.21 \n,,\n,\nx")
	f.Add("aa:bb:cc:dd:ee:ff,10.78.0.22,name,extra,fields")
	f.Fuzz(func(t *testing.T, text string) {
		lines := strings.Split(text, "\n")
		out := ParseReservations(lines)
		if len(out) > len(lines) {
			t.Fatalf("%d reservations from %d lines", len(out), len(lines))
		}
		for _, r := range out {
			for _, s := range []string{r.MAC, r.IP, r.Name} {
				if s != strings.TrimSpace(s) {
					t.Fatalf("field with edge space: %q", s)
				}
				if strings.Contains(s, ",") {
					t.Fatalf("field with a comma: %q", s)
				}
			}
			if r.MAC != strings.ToLower(r.MAC) {
				t.Fatalf("MAC not lower case: %q", r.MAC)
			}
			if strings.HasPrefix(r.MAC, "#") {
				t.Fatalf("comment read as a reservation: %+v", r)
			}
		}
	})
}
