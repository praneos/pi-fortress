package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

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
