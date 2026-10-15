package admin

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSegmentEnvDefaultsParanoidOff(t *testing.T) {
	c, _ := segConfig(t)
	env, err := c.SegmentEnv("desk")
	if err != nil {
		t.Fatal(err)
	}
	if env["PARANOID"] != "off" {
		t.Fatalf("PARANOID=%q, want the default off", env["PARANOID"])
	}
}

// PARANOID=on with no allowlist beside segments.d does not render. Thus a
// screen cannot arm a desk that would reach nothing. When the file exists,
// the edit goes in and the warning names the file.
func TestSetSegmentParanoidNeedsItsAllowlist(t *testing.T) {
	c, path := segConfig(t)
	before := read(t, path)
	allow := filepath.Join(filepath.Dir(c.SegmentsDir), "allow.desk.domains")
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"PARANOID": "on"}); err == nil || !strings.Contains(err.Error(), allow) {
		t.Fatalf("PARANOID=on with no allowlist: %v", err)
	}
	if got := read(t, path); got != before {
		t.Fatalf("a refused edit wrote the file:\n%s", got)
	}
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"PARANOID": "maybe"}); err == nil || !strings.Contains(err.Error(), "on or off") {
		t.Fatalf("PARANOID=maybe: %v", err)
	}
	write(t, allow, "github.com\n")
	warn, err := c.SetSegmentEnvKeys("desk", map[string]string{"PARANOID": "on"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn, "desk") || !strings.Contains(warn, allow) {
		t.Fatalf("the warning does not name the segment and its allowlist: %q", warn)
	}
	if env, _ := c.SegmentEnv("desk"); env["PARANOID"] != "on" {
		t.Fatalf("the edit did not go in: %+v", env)
	}
	// A screen then also cannot disable the gate.
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"BLOCK_DIRECT_IP": "off"}); err == nil || !strings.Contains(err.Error(), "PARANOID=on") {
		t.Fatalf("BLOCK_DIRECT_IP=off under PARANOID=on: %v", err)
	}
	if warn, err := c.SetSegmentEnvKeys("desk", map[string]string{"PARANOID": "off"}); err != nil || warn != "" {
		t.Fatalf("PARANOID=off: %v, warn %q", err, warn)
	}
}
