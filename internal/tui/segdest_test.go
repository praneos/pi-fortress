package tui

import (
	"os"
	"strings"
	"testing"
)

// The Activity of a plain segment has a New destinations view: what the
// desk reached for the first time, named by its own resolver.
func TestDeskActivityHasNewDestinations(t *testing.T) {
	c, _ := testConfig(t)
	deskFixture(t, c)
	body := `{"dns":{},"flows":{},"dests":{"desk":{"api.example.com:443/tcp":{"first_seen":"2026-10-04T10:00:00Z","last_seen":"2026-10-04T10:00:00Z","src":"10.79.0.2","dst":"93.184.216.34","name":"api.example.com","dport":443,"proto":"tcp"}}},"started":"2026-10-04T09:00:00Z"}`
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(140, 24).Type(keys("desk", secActivity, "desk")).Press(KeyTab, KeyTab))
	last := f.Last()
	if !isPicked(f, "New destinations") {
		t.Fatalf("no new destinations tab:\n%s", last)
	}
	if !strings.Contains(last, "api.example.com (93.184.216.34):443/tcp") {
		t.Fatalf("the desk's new destinations are not shown:\n%s", last)
	}
}
