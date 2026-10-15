package tui

import (
	"os"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
)

// The DHCP rows are under the other settings of the desk. They are off by
// default with no range, and say what they do.
func TestSettingsShowsASegmentsDHCPRows(t *testing.T) {
	c, _ := segSettings(t)
	last := run(t, c, NewFake(120, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	for _, want := range []string{"DHCP server", "off (default)", "DHCP range start", "DHCP range end"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on the desk's settings:\n%s", want, last)
		}
	}
	if strings.Contains(last, "dhcp.desk.hosts") {
		t.Fatalf("the reservations file is named with DHCP off:\n%s", last)
	}
	last = run(t, c, NewFake(120, 48).Type(segmentDown("DHCP"))).Last()
	if !strings.Contains(last, "[DHCP]") || !strings.Contains(last, "range") {
		t.Fatalf("the DHCP row has no help:\n%s", last)
	}
}

// Enter on either end asks for both and sends them as one edit, because
// render refuses one end without the other. Then Enter on DHCP enables it,
// and the row under it names the reservations file.
func TestSettingsSetsASegmentsDHCPRangeAndTurnsItOn(t *testing.T) {
	c, path := segSettings(t)
	f := run(t, c, NewFake(120, 48).Type(segmentDown("DHCP_END")).Press(KeyEnter).Type("10.79.0.2").Press(KeyEnter).Type("10.79.0.2").Press(KeyEnter))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DHCP_START=10.79.0.2\n") || !strings.Contains(string(raw), "DHCP_END=10.79.0.2\n") {
		t.Fatalf("the range was not written as one edit:\n%s\n%s", raw, f.Last())
	}
	if !strings.Contains(f.Last(), "saved") || !strings.Contains(f.Last(), "A applies") {
		t.Fatalf("the seat did not say it saved:\n%s", f.Last())
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("DHCP")).Press(KeyEnter))
	if raw, _ = os.ReadFile(path); !strings.Contains(string(raw), "DHCP=on\n") {
		t.Fatalf("Enter did not turn DHCP on:\n%s", raw)
	}
	last := run(t, c, NewFake(160, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	if !strings.Contains(last, admin.SegmentHostsPath(c.SegmentsDir, "desk")) {
		t.Fatalf("DHCP on does not name the reservations file:\n%s", last)
	}
}

// The seat refuses a range that render refuses. The file does not change,
// and the message says why.
func TestSettingsRefusesABadDHCPRange(t *testing.T) {
	c, path := segSettings(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(160, 48).Type(segmentDown("DHCP_START")).Press(KeyEnter).Type("10.79.0.1").Press(KeyEnter).Type("10.79.0.2").Press(KeyEnter))
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("a range covering the Pi's own address was written:\n%s", after)
	}
	if !strings.Contains(f.Last(), "covers IP=10.79.0.1") {
		t.Fatalf("the refusal does not say why:\n%s", f.Last())
	}
	// DHCP on with no range is also a refusal of render.
	f = run(t, c, NewFake(160, 48).Type(segmentDown("DHCP")).Press(KeyEnter))
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("DHCP=on with no range was written:\n%s", after)
	}
	if !strings.Contains(f.Last(), "needs DHCP_START and DHCP_END") {
		t.Fatalf("the refusal does not say why:\n%s", f.Last())
	}
}
