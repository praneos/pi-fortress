package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The paranoid toggle of the desk is a row of its own Settings. It is off
// by default, and one press when its allowlist is in place. When armed, it
// names the file that it reaches by.
func TestSettingsFlipsASegmentsParanoid(t *testing.T) {
	c, path := segSettings(t)
	last := run(t, c, NewFake(120, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	if !strings.Contains(last, "Paranoid (allowlist only)") || !strings.Contains(last, "off (default)") {
		t.Fatalf("no paranoid row on the desk's settings:\n%s", last)
	}
	allow := filepath.Join(filepath.Dir(c.SegmentsDir), "allow.desk.domains")
	if err := os.WriteFile(allow, []byte("github.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("PARANOID")).Press(KeyEnter))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PARANOID=on\n") {
		t.Fatalf("the press did not arm the desk:\n%s", raw)
	}
	last = run(t, c, NewFake(240, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	if !strings.Contains(last, "allowlist: "+allow) {
		t.Fatalf("armed, the row does not name the allowlist:\n%s", last)
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("PARANOID")).Press(KeyEnter))
	if raw, _ = os.ReadFile(path); !strings.Contains(string(raw), "PARANOID=off\n") {
		t.Fatalf("the second press did not disarm it:\n%s", raw)
	}
}
