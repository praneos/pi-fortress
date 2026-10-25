package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSegmentDNSTypesKey(t *testing.T) {
	load1 := func(body string) (*Config, error) {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		os.Mkdir(segs, 0755)
		write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n"+body)
		return Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env"})
	}
	c, err := load1("DNS_TYPES=\"srv txt  TYPE257\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Segments[0].DNSTypes; got != "SRV TXT TYPE257" {
		t.Fatalf("DNSTypes %q", got)
	}
	if env := c.EnvFile(); !strings.Contains(env, "SEG_DNS_TYPES=('SRV TXT TYPE257')") {
		t.Fatalf("env:\n%s", env)
	}
	for _, bad := range []string{"DNS_TYPES=TEXT", "DNS_TYPES=\"TXT TYPE0\""} {
		if _, err := load1(bad + "\n"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// pf dns answers AAAA, HTTPS and SVCB empty on every segment, before
// DNS_TYPES. A DNS_TYPES entry for one of them stays accepted, so an
// existing segment file still renders, but it gives a warning.
func TestSegmentDNSTypesInertWarns(t *testing.T) {
	load1 := func(body string) (*Config, string) {
		dir := t.TempDir()
		segs := filepath.Join(dir, "segments.d")
		os.Mkdir(segs, 0755)
		write(t, segs, "desk.env", "IF=eth3\nNET=10.79.0.0/30\nIP=10.79.0.1\n"+body)
		var w strings.Builder
		c, err := Load(Options{Net: lab, SegmentsDir: segs, HouseEnv: "/nonexistent/house.env", Stderr: &w})
		if err != nil {
			t.Fatal(err)
		}
		return c, w.String()
	}
	c, out := load1("DNS_TYPES=\"srv aaaa TYPE65 svcb\"\n")
	if got := c.Segments[0].DNSTypes; got != "SRV AAAA TYPE65 SVCB" {
		t.Fatalf("DNSTypes %q", got)
	}
	for _, typ := range []string{"AAAA", "HTTPS", "SVCB"} {
		want := "segment desk DNS_TYPES: " + typ + " is always answered empty"
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "this entry has no effect") != 3 {
		t.Errorf("want 3 warnings:\n%s", out)
	}
	if _, out := load1("DNS_TYPES=\"SRV TXT\"\n"); strings.Contains(out, "DNS_TYPES") {
		t.Errorf("SRV TXT gave a warning:\n%s", out)
	}
}
