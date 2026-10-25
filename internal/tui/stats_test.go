package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
)

func statsFixture(t *testing.T, c *admin.Config) time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	iso := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02T15:04:05Z") }
	body := fmt.Sprintf(`{"clients":{
"house/10.78.0.101":{"segment":"house","ip":"10.78.0.101","mac":"aa:bb:cc:dd:ee:02","name":"phone","last_seen":%q,"queries":42,"flows":3,"blocked":2,
  "names":{"ads.example":30,"cdn.example":12},"dests":{"1.2.3.4:443":3}},
"house/10.78.0.102":{"segment":"house","ip":"10.78.0.102","last_seen":%q,"queries":1,"names":{},"dests":{}},
"agent/10.77.0.10":{"segment":"agent","ip":"10.77.0.10","last_seen":%q,"queries":7,"flows":1,"names":{"api.example":7},"dests":{}}},
"events":[
{"t":%q,"segment":"house","src":"10.78.0.101","dst":"ads.example","threat":"hagezi-pro","detail":"dns A"},
{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"api.example","threat":"credential_strip","detail":"r1"},
{"t":%q,"segment":"house","src":"10.78.0.102","dst":"tracker.example","threat":"phishing-army","detail":"dns A"}
]}`, iso(3*time.Minute), iso(50*time.Hour), iso(2*time.Hour), iso(time.Hour), iso(time.Minute), iso(30*time.Second))
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return now
}

func lineWith(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

// The Devices of the house is its leases with the counts of observe beside
// them, plus each device that observe counted whose lease is gone. Enter
// opens one. The Devices of the agent network is the table of observe
// alone. Neither shows the clients of the other.
func TestDevicesTableDetailPerNetwork(t *testing.T) {
	c, _ := testConfig(t)
	now := statsFixture(t, c)
	house := keys(netHouse, secDevices)
	last := run(t, c, NewFake(140, 24).Type(house)).Last()
	phone := lineWith(last, "10.78.0.101")
	for _, want := range []string{"phone", "aa:bb:cc:dd:ee:02", " 42 ", " 2 ", "3m", "until"} {
		if !strings.Contains(phone, want) {
			t.Fatalf("the phone's row lacks %q:\n%s", want, last)
		}
	}
	if !strings.Contains(lineWith(last, "10.78.0.102"), " 2d") {
		t.Fatalf("a device with no lease left dropped off the table:\n%s", last)
	}
	if strings.Contains(last, "10.77.0.10") {
		t.Fatal("agent client on the house's Devices")
	}

	// The reservation sorts first, so the phone is one row down.
	last = run(t, c, NewFake(140, 24).Type(house+"j").Press(KeyEnter)).Last()
	for _, s := range []string{
		"phone  aa:bb:cc:dd:ee:02  10.78.0.101  queries 42  flows 3  blocked 2  last 3m",
		fmt.Sprintf("%-30s %6d  %-30s %6d", "ads.example", 30, "1.2.3.4:443", 3),
		fmt.Sprintf("%-30s %6d", "cdn.example", 12),
		when(now.Add(-time.Hour)) + "  hagezi-pro         ads.example",
	} {
		if !strings.Contains(last, s) {
			t.Fatalf("missing %q:\n%s", s, last)
		}
	}
	if strings.Contains(last, "phishing-army") || strings.Contains(last, "credential_strip") {
		t.Fatal("another client's event in the detail")
	}
	last = run(t, c, NewFake(140, 24).Type(house+"j").Press(KeyEnter, KeyEsc)).Last()
	if !strings.Contains(last, "10.78.0.101") || strings.Contains(last, "top names") {
		t.Fatalf("Esc did not return to the table:\n%s", last)
	}

	last = run(t, c, NewFake(100, 24).Type(keys(netAgent, secDevices))).Last()
	want := clientRow(100-menuWidth, "", "10.77.0.10", "7", "1", "0", "2h", "")
	if !strings.Contains(last, want) || strings.Contains(last, "phone") {
		t.Fatalf("the agent network's Devices:\n%s", last)
	}
}

// The Blocked table of Activity is newest first. It gives the source as
// its address, and the device name beside it when it has one.
func TestActivityNewestFirstNamesTheSource(t *testing.T) {
	c, _ := testConfig(t)
	now := statsFixture(t, c)
	last := run(t, c, NewFake(100, 24).Type(keys(netHouse, secActivity))).Last()
	rows := strings.Split(last, "\n")
	head := fmt.Sprintf(namedFmt, "time", "threat", "source", "name", "destination")
	r1 := fmt.Sprintf(namedFmt, when(now.Add(-30*time.Second)), "phishing-army", "10.78.0.102", "", "tracker.example")
	r2 := fmt.Sprintf(namedFmt, when(now.Add(-time.Hour)), "hagezi-pro", "10.78.0.101", "phone", "ads.example")
	// Rows 1 and 2 are the section and tab strips; the table is under them.
	for i, s := range []string{head, r1, r2} {
		if got := contentOf(rows[3+i]); strings.TrimRight(got, " ") != s {
			t.Fatalf("row %d: %q want %q", i, got, s)
		}
	}
	if !strings.Contains(rows[0], "Pi Fortress  Home network > Activity") {
		t.Fatal(rows[0])
	}
	if strings.Contains(last, "credential_strip") {
		t.Fatalf("the agent network's event on the house's Activity:\n%s", last)
	}
}

func TestStatsViewsSayWhenEmptyAndClip(t *testing.T) {
	c, _ := testConfig(t)
	for _, k := range []string{keys(netAgent, secDevices), keys(netAgent, secActivity)} {
		f := run(t, c, NewFake(100, 12).Type(k))
		if last := f.Last(); strings.Count(last, "no data yet") != 1 || !strings.Contains(last, "PF_OBSERVE_FLUSH_INTERVAL") {
			t.Fatalf("%s", last)
		}
	}
	statsFixture(t, c)
	// Too narrow for the full table: the code leaves off whole columns that
	// do not fit, and never cuts a value.
	f := run(t, c, NewFake(60, 10).Type(keys(netAgent, secDevices)))
	last := f.Last()
	if row := lineWith(last, "10.77."); strings.Contains(last, "no data yet") || strings.Contains(row, "~") || !strings.Contains(row, "10.77.0.10") {
		t.Fatalf("%s", last)
	}
	if head := lineWith(last, "name"); !strings.HasSuffix(strings.TrimRight(head, " "), "queries") {
		t.Fatalf("the header does not end on a whole column:\n%s", last)
	}
}

func TestStatsViewsTickOnlyWhileShown(t *testing.T) {
	c, _ := testConfig(t)
	statsFixture(t, c)
	old := statsTick
	statsTick = 10 * time.Millisecond
	defer func() { statsTick = old }()
	// frames counts the redraws beyond one per key and the first.
	frames := func(k string, more ...KeyKind) int {
		f := NewFake(80, 24).Type(k).Press(more...)
		f.Hold = true
		a := New(c, f)
		a.Idle = 150 * time.Millisecond
		done := make(chan error, 1)
		go func() { done <- a.Run() }()
		waitRun(t, done, 3*time.Second)
		return len(f.Frames) - 1 - len(k) - len(more)
	}
	if n := frames(keys(netAgent, secKeys)); n > 2 {
		t.Fatal("ticks on Keys:", n)
	}
	if n := frames(keys(netHouse, secActivity), KeyTab); n > 2 {
		t.Fatal("ticks on a log:", n)
	}
	if n := frames(keys(netHouse, secDevices)); n < 4 {
		t.Fatal("no ticks on Devices:", n)
	}
	if n := frames(keys(netHouse, secActivity), KeyEsc); n < 4 {
		t.Fatal("no ticks on Activity at the menu:", n)
	}
}

// An address claim goes on the same event ring as a sinkhole drop and
// shows in the same table. The columns of the table read as things that
// the Pi stopped. An arp_flip row even puts the claimed MAC under
// "destination". Without a mark, a neighbour that took an address with no
// consequence reads as one that was refused. That is the opposite of what
// occurred.
func TestAnAlertRowSaysItWasOnlySeenAndNotStopped(t *testing.T) {
	c, _ := testConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	iso := now.Add(-time.Minute).Format("2006-01-02T15:04:05Z")
	body := fmt.Sprintf(`{"clients":{},"events":[
{"t":%q,"segment":"house","src":"10.78.0.2","dst":"02:00:00:de:ad:99","threat":"arp_flip","detail":"was 08:00:27:5a:2c:c0"},
{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"api.example","threat":"credential_strip","detail":"r1"}
]}`, iso, now.Add(-2*time.Minute).Format("2006-01-02T15:04:05Z"))
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	house := keys(netHouse, secActivity)
	last := run(t, c, NewFake(100, 24).Type(house)).Last()
	if !strings.Contains(last, "! arp_flip") {
		t.Errorf("the claim is not marked as seen-only:\n%s", last)
	}
	if !strings.Contains(last, "! = not stopped") {
		t.Errorf("the table never says what the mark means:\n%s", last)
	}
	// The row that the Pi really stopped must not get the mark. If it
	// does, the mark says nothing.
	agent := run(t, c, NewFake(100, 24).Type(keys(netAgent, secActivity))).Last()
	if !strings.Contains(agent, "credential_strip") || strings.Contains(agent, "! credential_strip") {
		t.Errorf("a blocked row was marked as seen-only:\n%s", agent)
	}
	// At 80 columns, the header alone fills the content width. Thus the
	// legend does not show, and does not take the last character of the
	// heading next to it. The mark on the row stays. Help says what it
	// means.
	small := run(t, c, NewFake(80, 24).Type(house)).Last()
	if !strings.Contains(small, "! arp_flip") || !strings.Contains(lineWith(small, "threat"), "destination") {
		t.Errorf("80 columns lost the mark or the heading:\n%s", small)
	}
}
