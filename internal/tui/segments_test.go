package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pi-fortress/internal/admin"
)

// deskFixture is the case that the other fixtures of this package never
// had: a segment that is neither agent nor house. observe counted and
// stored its client and its event, and gave them to the screens. Then a
// tab strip with no tab for them dropped them. No test could see this bug
// while all fixtures used the two names that the strip was written with.
func deskFixture(t *testing.T, c *admin.Config) time.Time {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "segments.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "desk.env"),
		[]byte("IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c.SegmentsDir = dir
	now := time.Now().UTC().Truncate(time.Second)
	iso := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02T15:04:05Z") }
	body := fmt.Sprintf(`{"clients":{
"house/10.78.0.101":{"segment":"house","ip":"10.78.0.101","mac":"aa:bb:cc:dd:ee:02","name":"phone","last_seen":%q,"queries":42,"names":{},"dests":{}},
"desk/10.79.0.2":{"segment":"desk","ip":"10.79.0.2","mac":"aa:bb:cc:dd:ee:09","name":"seat","last_seen":%q,"queries":9,"flows":4,"blocked":1,"names":{"ads.example":9},"dests":{}}},
"events":[
{"t":%q,"segment":"house","src":"10.78.0.101","dst":"ads.example","threat":"hagezi-pro","detail":"dns A"},
{"t":%q,"segment":"desk","src":"10.79.0.2","dst":"tracker.example","threat":"phishing-army","detail":"dns A"}
]}`, iso(3*time.Minute), iso(time.Minute), iso(2*time.Hour), iso(time.Minute))
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return now
}

// Enter on a house device opens what observe counted for it. While that
// detail is open, r and d do nothing: the cursor is on a detail row, not on
// a lease.
func TestHouseDeviceDetailAndNoEditsUnderIt(t *testing.T) {
	c, _ := testConfig(t)
	deskFixture(t, c)
	before, _ := os.ReadFile(c.HouseHosts)
	// Reservations sort first: the admin machine, then the lease of the phone.
	f := run(t, c, NewFake(120, 24).Type(keys(netHouse, secDevices, "desk")+"j").Press(KeyEnter).Type("d"))
	last := f.Last()
	if !strings.Contains(last, "queries 42") || !strings.Contains(last, "top names") {
		t.Fatalf("Enter did not open the phone's detail:\n%s", last)
	}
	if strings.Contains(last, "delete reservation") || strings.Contains(last, "not a reservation") {
		t.Fatalf("d acted on a lease from under the detail:\n%s", last)
	}
	if after, _ := os.ReadFile(c.HouseHosts); string(after) != string(before) {
		t.Fatalf("house.hosts changed:\n%s", after)
	}
	// Esc goes back to the table, on the row that it left.
	f = run(t, c, NewFake(120, 24).Type(keys(netHouse, secDevices, "desk")+"j").Press(KeyEnter, KeyEsc))
	if !strings.Contains(f.Last(), "queries  blocked") {
		t.Fatalf("Esc did not return to the table:\n%s", f.Last())
	}
	// A device that observe did not count says so. It does not open an empty view.
	f = run(t, c, NewFake(120, 24).Type(keys(netHouse, secDevices, "desk")).Press(KeyEnter))
	if !strings.Contains(f.Last(), "nothing recorded for 10.78.0.20 yet") {
		t.Fatalf("Enter on an uncounted device:\n%s", f.Last())
	}
}

// The Activity of a plain segment has its own resolver log. Without it,
// the seat could not reach the log that the resolver of a desk writes.
func TestDeskActivityHasItsResolverLog(t *testing.T) {
	c, _ := testConfig(t)
	deskFixture(t, c)
	if err := os.WriteFile(c.HouseDNSLog, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	seg := filepath.Join(filepath.Dir(c.HouseDNSLog), "dns-desk.jsonl")
	row := `{"t":"2026-09-18T10:00:01Z","src":"10.79.0.2","name":"seat.example","qtype":"A","act":"blocked"}`
	if err := os.WriteFile(seg, []byte(row+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(140, 24).Type(keys("desk", secActivity, "desk")).Press(KeyTab))
	last := f.Last()
	if !isPicked(f, "DNS log") {
		t.Fatalf("no desk log tab:\n%s", last)
	}
	if !strings.Contains(last, "seat.example") {
		t.Fatalf("the desk's DNS log does not show the desk's log:\n%s", last)
	}
}

// Before, the code clipped a strip that was wider than the screen from the
// right. This showed an operator all tabs except the selected tab. The
// Filtering of the agent network is the strip that reaches that width:
// seven lists and the feeds.
func TestTabStripKeepsTheSelectionOnScreen(t *testing.T) {
	c, _ := testConfig(t)
	fake := NewFake(80, 24).Type(keys(netAgent, secFiltering))
	for range admin.AgentLists {
		fake = fake.Press(KeyTab)
	}
	last := run(t, c, fake).Last()
	if !isPicked(fake, "Feeds") {
		t.Fatalf("the selected tab is off the strip at 80 columns:\n%s", last)
	}
	if !strings.Contains(last, "<") {
		t.Fatalf("nothing says tabs scrolled off the left:\n%s", last)
	}
	// Tab zero is already at the left edge. Thus the strip stays whole
	// and clips from the right, as all other rows do.
	ff := run(t, c, NewFake(80, 24).Type(keys(netAgent, secFiltering)))
	first := ff.Last()
	if !isPicked(ff, "Blocked sites") || strings.Contains(first, "<") {
		t.Fatalf("the first tab scrolled when it did not need to:\n%s", first)
	}
}

// The strip shows only whole tabs, marks the tabs that are off each side,
// and always has the selected tab.
func TestTabStripShowsWholeTabs(t *testing.T) {
	var parts []string
	for _, n := range []string{"Blocked sites", "Blocked addresses", "Never block", "Never-block addresses", "Direct-IP exceptions", "Feeds"} {
		parts = append(parts, " "+n+" ")
	}
	for sel := range parts {
		s := fitTabs(parts, sel, 62)
		if n := utf8.RuneCountInString(s.text); n > 62 {
			t.Fatalf("sel %d: %d wide: %q", sel, n, s.text)
		}
		if got := string([]rune(s.text)[s.from:s.to]); got != parts[sel] {
			t.Fatalf("sel %d: picked %q in %q", sel, got, s.text)
		}
		body := strings.TrimSuffix(strings.TrimSuffix(s.text, "  (Tab)"), " >")
		body = strings.TrimPrefix(body, "< ")
		for _, name := range strings.Split(body, "   ") {
			if name = strings.TrimSpace(name); !slices.Contains(parts, " "+name+" ") {
				t.Fatalf("sel %d: %q is not a whole tab in %q", sel, name, s.text)
			}
		}
		if strings.HasPrefix(s.text, "<") == strings.Contains(s.text, parts[0]) {
			t.Fatalf("sel %d: left marker wrong: %q", sel, s.text)
		}
	}
	if s := fitTabs(parts, 0, 62); !strings.Contains(s.text, " >") {
		t.Fatalf("no right marker on a clipped strip: %q", s.text)
	}
}
