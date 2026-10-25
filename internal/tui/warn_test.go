package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeReport(t *testing.T, policyDir, body string, age time.Duration) {
	t.Helper()
	gen := filepath.Join(policyDir, "generated")
	if err := os.MkdirAll(gen, 0755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(gen, "fetch.report")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
}

// A blocklist that decays has no other symptom. All screens continue to
// say ok while the lists go out of date. The Feeds screen is the one place
// that an operator has no reason to open. Thus the warning goes on the
// title bar, which all screens draw.
func TestStaleFeedsWarnFromAnyScreen(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "STALE f1: 9 domains (last good 2d1h ago: HTTP 503)\n", time.Hour)
	// Agent network > Filtering is not Feeds; the warning has to be there anyway.
	f := run(t, c, NewFake(100, 24).Type(keys(netAgent, secFiltering)))
	if !strings.Contains(f.Last(), "serving the last good copy") {
		t.Fatalf("no feed warning outside the Feeds screen:\n%s", firstLine(f.Last()))
	}
}

func TestCleanFeedsDoNotWarn(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "OK f1: 9 domains\n", time.Hour)
	f := run(t, c, NewFake(100, 24).Type(keys(netAgent, secFiltering)))
	if strings.Contains(f.Last(), "feeds:") {
		t.Fatalf("warned on a clean recent fetch:\n%s", firstLine(f.Last()))
	}
}

// The operator reads the Status screen first. Thus the fetch state is a
// row there. It is not only a title-bar note.
func TestStatusScreenShowsTheFeedWarning(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "FAIL f1: dial: no route to host\n", time.Hour)
	f := run(t, c, NewFake(100, 40).Type(keys(netSystem, secHealth)))
	if !strings.Contains(f.Last(), "feeds      ! 1 failed with nothing to fall back on") {
		t.Fatalf("no feed warning on the Status screen:\n%s", f.Last())
	}
}

// A healthy report shows, and is not silent. Thus the operator can see the
// difference between "fetched an hour ago" and "never fetched", and does
// not need to open Feeds.
func TestStatusScreenShowsCleanFeedCounts(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "OK f1: 9 domains\nOK f2: 3 ips\n", time.Hour)
	f := run(t, c, NewFake(100, 40).Type(keys(netSystem, secHealth)))
	if !strings.Contains(f.Last(), "feeds      fetched 1h0m ago  2 ok  0 failed  0 stale") {
		t.Fatalf("no counts row on the Status screen:\n%s", f.Last())
	}
}

// msg is the result of the last operator action. The warning is a
// standing condition. Neither one hides the other: the warning stays on the
// title bar, and msg goes in the footer. When they used one slot, one Esc
// on a prompt removed the warning from all screens.
func TestMessageDoesNotHideTheWarning(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c.PolicyDir, "FAIL f1: dial: no route to host\n", time.Hour)
	f := run(t, c, NewFake(100, 24).Type(keys(netHouse, secFiltering)+"a").Press(KeyEsc))
	last := f.Last()
	if !strings.Contains(firstLine(last), "! feeds:") {
		t.Fatalf("Esc on a prompt removed the warning:\n%s", last)
	}
	if foot := lastLine(last); !strings.HasPrefix(foot, "cancelled") || !strings.Contains(foot, "? help") {
		t.Fatalf("footer: %q", foot)
	}

	a := New(c, NewFake(100, 24))
	a.reload()
	a.msg = "error: something the operator just did"
	a.draw()
	last = a.t.(*Fake).Last()
	if !strings.Contains(firstLine(last), "! feeds:") || strings.Contains(firstLine(last), "operator just did") {
		t.Fatalf("title bar: %q", firstLine(last))
	}
	if foot := lastLine(last); !strings.HasPrefix(foot, a.msg) || !strings.Contains(foot, "? help") {
		t.Fatalf("footer: %q", foot)
	}
}

// A long message keeps its whole text. The keys of the screen give way
// first, then the state. "? help" stays.
func TestALongMessageKeepsItsTextAndHelp(t *testing.T) {
	c, _ := testConfig(t)
	a := New(c, NewFake(80, 24))
	a.reload()
	a.cur, a.focus, a.pending = view{netHouse, secFiltering}, true, "local"
	a.msg = "error: " + strings.Repeat("x", 30) + " the part that says what to do"
	a.draw()
	foot := strings.TrimRight(lastLine(a.t.(*Fake).Last()), " ")
	if !strings.HasPrefix(foot, a.msg) || !strings.HasSuffix(foot, "? help") {
		t.Fatalf("footer: %q", foot)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func lastLine(s string) string {
	return s[strings.LastIndex(s, "\n")+1:]
}
