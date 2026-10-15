package tui

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
)

// keys is what an operator types from a fresh seat to reach one view: the
// digit of the network, then l one time for each section before it. plain
// names the segments.d segments of the box. They are between the home
// network and System in the menu.
func keys(net string, sec section, plain ...string) string {
	var segs []admin.Segment
	for _, p := range plain {
		segs = append(segs, admin.Segment{Name: p, Plain: true})
	}
	for i, e := range buildNets(segs) {
		if e.id == net {
			if j := slices.Index(e.secs, sec); j >= 0 {
				return fmt.Sprint(i+1) + strings.Repeat("l", j)
			}
		}
	}
	panic("no view " + net + " " + sectionNames[sec])
}

// settingsDown opens the Settings view that holds key, with the cursor on
// it: the view of the house in group order, else the view of System. The
// code computes the index and does not count it by hand. Thus a new
// grouping cannot make a test edit the row next to the one that it names.
func settingsDown(key string, plain ...string) string {
	n := 0
	for _, g := range houseGroups {
		for _, s := range g.items {
			if s.key == key {
				return keys(netHouse, secSettings, plain...) + strings.Repeat("j", n)
			}
			n++
		}
	}
	for i, s := range netSettings {
		if s.key == key {
			return keys(netSystem, secSettings, plain...) + strings.Repeat("j", i)
		}
	}
	panic("no setting " + key)
}

// Each house.env key that the admin side writes has exactly one row on the
// Settings of the home network. The seat cannot change a key that is not
// listed. A key that is listed twice gives two rows that disagree after an
// edit.
func TestHouseSettingsGroupEveryKeyOnce(t *testing.T) {
	seen := map[string]int{}
	for _, g := range houseGroups {
		for _, s := range g.items {
			seen[s.key]++
			if s.label == "" || s.help == "" {
				t.Errorf("%s has no label or help", s.key)
			}
		}
	}
	for _, k := range admin.HouseKeys {
		if seen[k] != 1 {
			t.Errorf("%s appears %d times", k, seen[k])
		}
		delete(seen, k)
	}
	for k := range seen {
		t.Errorf("%s is not an admin.HouseKeys key", k)
	}
	for _, k := range admin.NetKeys {
		if n := len(slices.DeleteFunc(slices.Clone(netSettings), func(s setting) bool { return s.key != k })); n != 1 {
			t.Errorf("net key %s has %d rows", k, n)
		}
	}
	for _, s := range netSettings {
		if !slices.Contains(admin.NetKeys, s.key) {
			t.Errorf("%s is not an admin.NetKeys key", s.key)
		}
		if s.label == "" || s.help == "" {
			t.Errorf("%s has no label or help", s.key)
		}
		if len(s.label) > 28 {
			t.Errorf("%s's label is wider than the column: %q", s.key, s.label)
		}
	}
}

// The same four sections on all networks. The complaint that started this
// layout was a home network with no Settings, while the others had it.
func TestEveryNetworkHasTheSameSections(t *testing.T) {
	for _, e := range buildNets([]admin.Segment{{Name: "desk", Plain: true}}) {
		if e.id == netOverview || e.id == netSystem {
			continue
		}
		if !slices.Equal(e.secs[:4], networkSections) {
			t.Errorf("%s: %v", e.id, e.secs)
		}
	}
}

// Left from the first section of a network goes back to the menu. The
// network opens again on the section where the operator left it.
func TestSectionsMoveAndAreRemembered(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(120, 30).Type(keys(netHouse, secActivity)).Press(KeyEsc).Type("3"))
	if !strings.Contains(f.Last(), "Home network > Activity") {
		t.Fatalf("the house did not reopen on Activity:\n%s", f.Last())
	}
	f = run(t, c, NewFake(120, 30).Type("3").Press(KeyLeft))
	if !strings.Contains(f.Last(), "1-9 jump") {
		t.Fatalf("Left from Devices did not reach the menu:\n%s", f.Last())
	}
}

// Overview says All good on a healthy box, and names the problem when
// there is one.
func TestOverviewVerdict(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "OK f1: 9 domains\n", time.Hour)
	last := run(t, c, NewFake(120, 30).Type("1")).Last()
	for _, want := range []string{"All good", "Agent network", "Home network", "ports strict", "Pi  cpu"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on Overview:\n%s", want, last)
		}
	}
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nWG_IF=wg-missing\nHOUSE_EGRESS=audit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last = run(t, c, NewFake(140, 30).Type("1")).Last()
	for _, want := range []string{"Needs attention", "home VPN tunnel", "ports audit (logging, not blocking)"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on Overview:\n%s", want, last)
		}
	}
}

// A Settings row is a label. The explanation with the key under the list
// follows the cursor.
func TestSettingsRowsExplainThemselves(t *testing.T) {
	c, _ := testConfig(t)
	last := run(t, c, NewFake(120, 40).Type(settingsDown("HOUSE_EGRESS"))).Last()
	for _, want := range []string{"Apps & ports", "Outbound ports", "strict (default)", "[HOUSE_EGRESS]", "Enter cycles"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q:\n%s", want, last)
		}
	}
}

// HOUSE_EGRESS steps strict, audit, open. It asks before open, which is the
// one step that removes the port filter from the full house.
func TestSettingsCyclesEgressAndAsksBeforeOpen(t *testing.T) {
	c, _ := testConfig(t)
	egress := func() string {
		return settingsDown("HOUSE_EGRESS")
	}
	run(t, c, NewFake(120, 40).Type(egress()).Press(KeyEnter))
	if raw, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "HOUSE_EGRESS=audit\n") {
		t.Fatalf("strict did not step to audit:\n%s", raw)
	}
	run(t, c, NewFake(120, 40).Type(egress()).Press(KeyEnter).Type("n"))
	if raw, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "HOUSE_EGRESS=audit\n") {
		t.Fatalf("open was written without a yes:\n%s", raw)
	}
	run(t, c, NewFake(120, 40).Type(egress()).Press(KeyEnter).Type("y"))
	if raw, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "HOUSE_EGRESS=open\n") {
		t.Fatalf("y did not open it:\n%s", raw)
	}
	run(t, c, NewFake(120, 40).Type(egress()).Press(KeyEnter))
	if raw, _ := os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "HOUSE_EGRESS=strict\n") {
		t.Fatalf("open did not step back to strict:\n%s", raw)
	}
}

// A saved edit says that A applies it, and the footer continues to say so.
// A runs the apply that the edit needs on System > Actions: --local for a
// list.
func TestSavedEditOffersTheApplyItNeeds(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(120, 30).Type(keys(netHouse, secFiltering)+"a").Type("tracker.example").Press(KeyEnter))
	if !strings.Contains(f.Last(), "added tracker.example; A applies") || !strings.Contains(f.Last(), "A applies saved changes") {
		t.Fatalf("no apply offer after a list edit:\n%s", f.Last())
	}
	f = NewFake(120, 30).Type(keys(netHouse, secFiltering) + "a").Type("tracker2.example").Press(KeyEnter).Type("A")
	run(t, c, f)
	if !strings.Contains(f.Last(), "run pf apply --local now") {
		t.Fatalf("A on a list edit does not offer apply --local:\n%s", f.Last())
	}
	f = NewFake(120, 30).Type(settingsDown("HOUSE_BLOCK_HTTP")).Press(KeyEnter).Type("A")
	run(t, c, f)
	if !strings.Contains(f.Last(), "run pf apply now") {
		t.Fatalf("A on a house.env edit does not offer the full apply:\n%s", f.Last())
	}
}

// A plain segment resolves with the lists of the agent network. Its
// Filtering shows them, but does not edit them from there.
func TestPlainSegmentListsAreReadOnly(t *testing.T) {
	c, _ := segSettings(t)
	f := run(t, c, NewFake(120, 30).Type(keys("desk", secFiltering, "desk")+"a"))
	last := f.Last()
	if !strings.Contains(last, "pi-fortress-block.test") || !strings.Contains(last, "shared with the agent network") {
		t.Fatalf("the desk does not show the agent lists:\n%s", last)
	}
	if !strings.Contains(last, "edit it under Agent network > Filtering") {
		t.Fatalf("a on the desk's list was not refused:\n%s", last)
	}
	// dns_types.allow belongs only to the agent resolver. A plain segment is
	// not address-only, so it has no tab there.
	for i := range admin.AgentLists {
		f := NewFake(120, 30).Type(keys("desk", secFiltering, "desk"))
		for range i {
			f = f.Press(KeyTab)
		}
		if last := run(t, c, f).Last(); strings.Contains(last, admin.DNSTypesList) {
			t.Fatalf("the desk shows the agent's record-type overrides:\n%s", last)
		}
	}
}

// Filtering ends with the feeds that reach that network. e toggles them.
func TestFilteringShowsTheNetworksFeeds(t *testing.T) {
	c, _ := testConfig(t)
	f := NewFake(120, 30).Type(keys(netHouse, secFiltering))
	for range admin.HouseLists {
		f.Press(KeyTab)
	}
	last := run(t, c, f.Type("e")).Last()
	if !isPicked(f, "Feeds") || !strings.Contains(last, "f1") {
		t.Fatalf("no feeds tab:\n%s", last)
	}
	if raw, _ := os.ReadFile(c.PolicyDir + "/sources.json"); !strings.Contains(string(raw), `"enabled": false`) {
		t.Fatalf("e did not toggle the feed:\n%s", raw)
	}
}

// isPicked says that name is the highlighted entry on a section or tab
// strip in the last frame of f.
func isPicked(f *Fake, name string) bool {
	if len(f.Frames) == 0 {
		return false
	}
	for _, chunk := range strings.Split(f.Frames[len(f.Frames)-1], attrCodes[picked])[1:] {
		if i := strings.Index(chunk, "\x1b["); i >= 0 {
			chunk = chunk[:i]
		}
		if strings.TrimSpace(chunk) == name {
			return true
		}
	}
	return false
}

// Right from the last section goes to the first.
func TestRightFromTheLastSectionWraps(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(120, 30).Type(keys(netHouse, secSettings)+"l"))
	if !isPicked(f, "Devices") {
		t.Fatalf("Right from Settings did not come round to Devices:\n%s", f.Last())
	}
	f = run(t, c, NewFake(120, 30).Type(keys(netAgent, secKeys)).Press(KeyRight))
	if !isPicked(f, "Devices") {
		t.Fatalf("Right from Keys did not come round to Devices:\n%s", f.Last())
	}
}
