package tui

import (
	"testing"

	"pi-fortress/internal/admin"
)

// The last-hour cell shows the difference between three things that an
// operator must not confuse: a slot that spent nothing, a slot that spent
// something, and a broker that was not there to answer.
func TestSlotHourCell(t *testing.T) {
	if got := slotHour(admin.SlotInfo{}); got != "?" {
		t.Fatalf("a broker that did not answer rendered %q", got)
	}
	if got := slotHour(admin.SlotInfo{HourKnown: true}); got != "-" {
		t.Fatalf("an idle slot rendered %q", got)
	}
	s := admin.SlotInfo{HourKnown: true, Hour: admin.SlotHour{Requests: 3001, Bytes: 12 << 20}}
	if got := slotHour(s); got != "3001 req 12M" {
		t.Fatalf("a busy slot rendered %q", got)
	}
}
