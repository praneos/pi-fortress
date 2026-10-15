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
