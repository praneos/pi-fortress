package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/secrets"
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

// d removes a slot and its credentials at once, and no apply or restore
// brings them back. Thus it asks for the typed yes that purge asks for,
// and the question names the slot. One y must not delete it.
func TestSlotDeleteAsksForTypedYes(t *testing.T) {
	c, _ := testConfig(t)
	slot, err := secrets.Open(c.SecretsPath).MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "ghp_live"})
	if err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		raw, _ := os.ReadFile(c.SecretsPath)
		return strings.Contains(string(raw), slot)
	}
	// 80 columns: the full question fits, the slot included.
	f := run(t, c, NewFake(80, 24).Type(keys(netAgent, secKeys)+"d"))
	if !strings.Contains(f.Last(), "delete slot "+slot+"; its credentials go away at once (type yes)") {
		t.Fatalf("d does not ask for a typed yes that names the slot:\n%s", f.Last())
	}
	f = run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"d").Type("y").Press(KeyEnter))
	if !has() || !strings.Contains(f.Last(), "cancelled") {
		t.Fatalf("one y deleted the slot:\n%s", f.Last())
	}
	run(t, c, NewFake(130, 24).Type(keys(netAgent, secKeys)+"d").Type("yes").Press(KeyEnter))
	if has() {
		t.Fatal("yes did not delete the slot")
	}
}

// Two networks have a list with the label Blocked sites. Thus the delete
// question names the file, as the list header does. A long item gets the
// cells that are left on the line, so the file name and [y/N] stay
// visible at 80 columns.
func TestListDeleteNamesTheList(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(80, 24).Type(keys(netHouse, secFiltering)+"d"))
	if !strings.Contains(f.Last(), "delete ads.example from house.domains [y/N]") {
		t.Fatalf("the house delete does not name its list:\n%s", f.Last())
	}
	f = run(t, c, NewFake(80, 24).Type(keys(netAgent, secFiltering)+"d"))
	if !strings.Contains(f.Last(), "delete pi-fortress-block.test from blacklist.domains [y/N]") {
		t.Fatalf("the agent delete does not name its list:\n%s", f.Last())
	}
	long := strings.Repeat("a", 60) + ".example"
	path := filepath.Join(c.PolicyDir, "house.domains")
	if err := os.WriteFile(path, []byte(long+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f = run(t, c, NewFake(80, 24).Type(keys(netHouse, secFiltering)+"d"))
	if !strings.Contains(f.Last(), "delete "+long[:30]) || !strings.Contains(f.Last(), "~ from house.domains [y/N]") {
		t.Fatalf("a long item hides the list name or itself:\n%s", f.Last())
	}
	run(t, c, NewFake(80, 24).Type(keys(netHouse, secFiltering)+"d").Type("y"))
	if got, _ := os.ReadFile(path); len(got) != 0 {
		t.Fatalf("y did not delete the full item: %q", got)
	}
}

// A reservation delete that does not reload house dns leaves the live
// resolver on the old name, and nothing shows that gap. Thus one question
// covers the delete and the reload, and y does both. No second question
// follows. n does neither. At 80 columns the full question fits.
func TestReservationDeleteReloadsInOneQuestion(t *testing.T) {
	c, calls := testConfig(t)
	reloads := func() int {
		n := 0
		for _, argv := range *calls {
			if strings.Join(argv, " ") == "systemctl reload "+admin.HouseDNSUnit {
				n++
			}
		}
		return n
	}
	f := run(t, c, NewFake(80, 24).Type(keys(netHouse, secDevices)+"d"))
	if !strings.Contains(f.Last(), "delete reservation mac 10.78.0.20 (aa:bb:cc:dd:ee:01); reload dns [y/N]") {
		t.Fatalf("the question does not cover the delete and the reload:\n%s", f.Last())
	}
	run(t, c, NewFake(80, 24).Type(keys(netHouse, secDevices)+"d").Type("n"))
	if got, _ := os.ReadFile(c.HouseHosts); !strings.Contains(string(got), "ee:01") || reloads() != 0 {
		t.Fatalf("n deleted or reloaded: %q, %d reloads", got, reloads())
	}
	f = run(t, c, NewFake(80, 24).Type(keys(netHouse, secDevices)+"d").Type("y"))
	if got, _ := os.ReadFile(c.HouseHosts); strings.Contains(string(got), "ee:01") {
		t.Fatalf("y did not delete: %q", got)
	}
	if reloads() != 1 {
		t.Fatalf("y did not reload house dns: %v", *calls)
	}
	if strings.Contains(f.Last(), "[y/N]") || !strings.Contains(f.Last(), "deleted aa:bb:cc:dd:ee:01") {
		t.Fatalf("a second question follows the delete, or no message:\n%s", f.Last())
	}
}
