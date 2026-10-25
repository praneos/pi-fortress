package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A feed that is off stops a blocklist for all networks of the box. Thus e
// on a feed that is on asks first, and the question names the feed and
// the effect. e on a feed that is off adds protection, and does not ask.
func TestFeedDisableAsksAndNamesTheFeed(t *testing.T) {
	c, _ := testConfig(t)
	path := filepath.Join(c.PolicyDir, "sources.json")
	off := func() bool {
		got, _ := os.ReadFile(path)
		return strings.Contains(string(got), `"enabled": false`)
	}
	f := run(t, c, NewFake(80, 24).Type(keys(netSystem, secFeeds)+"e"))
	if !strings.Contains(f.Last(), "disable feed f1 for the whole box [y/N]") || off() {
		t.Fatalf("e disabled the feed without a question that names it:\n%s", f.Last())
	}
	f = run(t, c, NewFake(80, 24).Type(keys(netSystem, secFeeds)+"e").Type("n"))
	if off() || !strings.Contains(f.Last(), "cancelled") {
		t.Fatalf("n did not keep the feed on:\n%s", f.Last())
	}
	run(t, c, NewFake(80, 24).Type(keys(netSystem, secFeeds)+"e").Type("y"))
	if !off() {
		t.Fatal("y did not disable the feed")
	}
	f = run(t, c, NewFake(80, 24).Type(keys(netSystem, secFeeds)+"e"))
	if off() || strings.Contains(f.Last(), "[y/N]") {
		t.Fatalf("enable asked a question or did nothing:\n%s", f.Last())
	}
}
