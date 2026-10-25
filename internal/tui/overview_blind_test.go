package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
)

// "All good" is a claim that each check ran and passed. A query that the
// seat could not make, or a systemctl that answered for no unit, is named
// as a thing that the seat cannot check. It is never read as a clean
// answer.
func TestOverviewNeverSaysAllGoodOverAFailedCheck(t *testing.T) {
	c, _ := testConfig(t)
	if last := run(t, c, NewFake(120, 30)).Last(); strings.Contains(last, "cannot check") {
		t.Fatalf("the fixture's checks fail to begin with:\n%s", last)
	}

	c.Exec = func(context.Context, []string) ([]byte, error) { return nil, errors.New("no systemd here") }
	last := run(t, c, NewFake(120, 30)).Last()
	if strings.Contains(last, "All good") || !strings.Contains(last, "cannot check: units") {
		t.Fatalf("a systemctl that answered nothing read as healthy:\n%s", last)
	}

	c, _ = testConfig(t)
	f := NewFake(120, 30)
	a := New(c, f)
	a.role = admin.Role(0)
	if err := a.Run(); err != nil {
		t.Fatal(err)
	}
	last = f.Last()
	if strings.Contains(last, "All good") {
		t.Fatalf("refused queries read as healthy:\n%s", last)
	}
	for _, verb := range []string{"units", "ifaces", "status", "stats"} {
		if !strings.Contains(last, "cannot check: "+verb) {
			t.Fatalf("no 'cannot check: %s':\n%s", verb, last)
		}
	}
}

// A row that the Pi saw and did not stop is the fact that the operator must
// see first. Overview counts these rows from the same events that Activity
// shows, as a problem and in the notes of the network.
func TestOverviewCountsWhatWasSeenAndNotStopped(t *testing.T) {
	c, _ := testConfig(t)
	writeReport(t, c, "OK f1: 9 domains\n", time.Hour)
	statsFixture(t, c)
	if last := run(t, c, NewFake(120, 30)).Last(); !strings.Contains(last, "All good") || strings.Contains(last, "not stopped") {
		t.Fatalf("blocked rows alone are not a problem:\n%s", last)
	}

	iso := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05Z")
	body := fmt.Sprintf(`{"clients":{},"events":[
{"t":%q,"segment":"house","src":"10.78.0.2","dst":"02:00:00:de:ad:99","threat":"arp_flip"},
{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"x.example","threat":"dns_tunnel"},
{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"y.example","threat":"volume"},
{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"api.example","threat":"credential_strip"}
]}`, iso, iso, iso, iso)
	if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(120, 30)).Last()
	for _, want := range []string{
		"Needs attention",
		"^ 2 threats seen and not stopped on Agent network (Activity)",
		"^ 1 threat seen and not stopped on Home network (Activity)",
	} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q:\n%s", want, last)
		}
	}
	if agent := lineWith(last, "Agent network    "); !strings.Contains(agent, "^ 2 not stopped") {
		t.Fatalf("the agent network's notes do not count them: %q", agent)
	}
}

// A verdict with no time can be ten minutes old on a seat that froze. The
// Pi line says when the seat made the checks.
func TestOverviewSaysWhenItChecked(t *testing.T) {
	c, _ := testConfig(t)
	at := time.Date(2026, 1, 2, 14, 2, 31, 0, time.Local)
	c.Now = func() time.Time { return at }
	last := run(t, c, NewFake(80, 24)).Last()
	if pi := lineWith(last, "Pi  "); !strings.Contains(pi, "checked 14:02:31") || !strings.Contains(pi, "cpu ") {
		t.Fatalf("no check time beside the cpu: %q", pi)
	}
}

// Only a threat from the last 24 hours is a problem on the verdict. An
// older one still counts in the notes of its network, as long as Activity
// shows it. If not, one alert holds the verdict at "Needs attention" for
// seven days, and the operator learns to read past it.
func TestOverviewNeedsAttentionOnlyForTheLastDay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent time.Duration // age of the agent alert, 0 for none
		house time.Duration
		good  bool
	}{
		{"recent and old", 2 * time.Hour, 3 * 24 * time.Hour, false},
		{"old only", 0, 3 * 24 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testConfig(t)
			writeReport(t, c, "OK f1: 9 domains\n", time.Hour)
			statsFixture(t, c)
			var evs []string
			if tc.agent > 0 {
				evs = append(evs, fmt.Sprintf(`{"t":%q,"segment":"agent","src":"10.77.0.10","dst":"x.example","threat":"dns_tunnel"}`, c.Now().Add(-tc.agent).UTC().Format(time.RFC3339)))
			}
			evs = append(evs, fmt.Sprintf(`{"t":%q,"segment":"house","src":"10.78.0.2","dst":"02:00:00:de:ad:99","threat":"arp_flip"}`, c.Now().Add(-tc.house).UTC().Format(time.RFC3339)))
			body := `{"clients":{},"events":[` + strings.Join(evs, ",\n") + `]}`
			if err := os.WriteFile(c.ObservePath, []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			last := run(t, c, NewFake(120, 30)).Last()
			if got := strings.Contains(last, "All good"); got != tc.good {
				t.Fatalf("All good = %v, want %v:\n%s", got, tc.good, last)
			}
			if strings.Contains(last, "seen and not stopped on Home network") {
				t.Fatalf("a threat three days old is a problem:\n%s", last)
			}
			if house := lineWith(last, "Home network     "); !strings.Contains(house, "^ 1 not stopped") {
				t.Fatalf("the home network's notes do not count the old threat: %q", house)
			}
			if tc.agent > 0 && !strings.Contains(last, "^ 1 threat seen and not stopped on Agent network") {
				t.Fatalf("a threat two hours old is not a problem:\n%s", last)
			}
		})
	}
}
