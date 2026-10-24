package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
)

// segSettings is the box for all tests here: the tui fixture plus the one
// plain segment that the real Pi has, the desk. All three editable keys
// are absent, so the screen shows their defaults.
func segSettings(t *testing.T) (*admin.Config, string) {
	t.Helper()
	c, _ := testConfig(t)
	c.SegmentsDir = filepath.Join(filepath.Dir(c.HouseEnv), "segments.d")
	if err := os.MkdirAll(c.SegmentsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.SegmentsDir, "desk.env")
	if err := os.WriteFile(path, []byte("# the operator's own seat\nIF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return c, path
}

// segmentDown opens the Settings of the desk with the cursor on key. Its
// selectable rows are admin.SegmentKeys, in order.
func segmentDown(key string) string {
	return keys("desk", secSettings, "desk") + strings.Repeat("j", slices.Index(admin.SegmentKeys, key))
}

const deskSettings = "desk"

// The view is the main point. Before, the settings of the desk were the
// one part of the box that an operator could change only with an editor
// and the file name.
func TestSettingsShowsAPlainSegmentsOwnView(t *testing.T) {
	c, path := segSettings(t)
	last := run(t, c, NewFake(120, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	for _, want := range []string{
		"Desk > Settings", path,
		"eth0.79", "10.79.0.0/30", "10.79.0.1", "edit the file and reboot",
		"SSH to the Pi from here", "no (default)", "SSH to agents", "(none)", "Block direct-IP connections", "on (default)",
		"[ADMIN]",
	} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on the desk's settings:\n%s", want, last)
		}
	}
}

// A box with no segments.d has no segment entry at all, not an empty one.
// The menu is Overview, the agent and home networks, and System.
func TestMenuHasNoSegmentEntryOnABoxWithNoSegments(t *testing.T) {
	c, _ := testConfig(t)
	last := run(t, c, NewFake(120, 48)).Last()
	if !strings.Contains(last, "4 System") || strings.Contains(last, "5 ") {
		t.Fatalf("the menu is not the four fixed entries:\n%s", last)
	}
	// And the three settings views it always had are still there.
	for _, v := range []struct{ net, want string }{
		{netHouse, "Block direct-IP connections"},
		{netSystem, "Untrusted uplink"},
		{netAgent, "Fixed by the fence"},
	} {
		if last := run(t, c, NewFake(120, 48).Type(keys(v.net, secSettings))).Last(); !strings.Contains(last, v.want) {
			t.Fatalf("no %q on %s's settings:\n%s", v.want, v.net, last)
		}
	}
}

// The gate is the key that the desk runs with off since the cutover. Thus
// the change back to on is the reason for this screen. Off says so in its
// own row. It is the only setting here that removes something without
// another symptom on a screen.
func TestSettingsFlipsASegmentsDirectIPGate(t *testing.T) {
	c, path := segSettings(t)
	f := run(t, c, NewFake(120, 48).Type(segmentDown("BLOCK_DIRECT_IP")).Press(KeyEnter))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "BLOCK_DIRECT_IP=off\n") {
		t.Fatalf("the first press did not turn the gate off:\n%s", raw)
	}
	if !strings.Contains(string(raw), "# the operator's own seat") {
		t.Fatalf("the edit dropped the file's comment:\n%s", raw)
	}
	for _, want := range []string{"BLOCK_DIRECT_IP=off saved", "A applies"} {
		if !strings.Contains(f.Last(), want) {
			t.Fatalf("the seat did not say %q:\n%s", want, f.Last())
		}
	}
	last := run(t, c, NewFake(120, 48).Type(keys(deskSettings, secSettings, "desk"))).Last()
	if !strings.Contains(last, "the resolved-address gate is off for this network") {
		t.Fatalf("off does not say what it turned off:\n%s", last)
	}
	run(t, c, NewFake(120, 48).Type(segmentDown("BLOCK_DIRECT_IP")).Press(KeyEnter))
	if raw, _ = os.ReadFile(path); !strings.Contains(string(raw), "BLOCK_DIRECT_IP=on\n") {
		t.Fatalf("the second press did not flip it back:\n%s", raw)
	}
}

// ADMIN=no closes ssh to the Pi from this segment at the next apply. The
// session that closes it usually comes from the desk. A press that does
// that must not be one press.
func TestSettingsAsksBeforeClosingSSHFromASegment(t *testing.T) {
	c, path := segSettings(t)
	if _, err := c.SetSegmentEnvKeys("desk", map[string]string{"ADMIN": "yes"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(170, 48).Type(segmentDown("ADMIN")).Press(KeyEnter).Type("n"))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("a declined confirm closed ssh from the desk anyway:\n%s", after)
	}
	if !strings.Contains(f.Last(), "cancelled") {
		t.Fatalf("the seat did not say it cancelled:\n%s", f.Last())
	}
	f = run(t, c, NewFake(170, 48).Type(segmentDown("ADMIN")).Press(KeyEnter).Type("y"))
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "ADMIN=no\n") {
		t.Fatalf("a confirmed flip did not go in:\n%s", raw)
	}
	// The warning that admin answers with goes in the message. Thus the seat
	// asks the operator first, and also tells them what they scheduled.
	if !strings.Contains(f.Last(), "stops at the next apply") {
		t.Fatalf("the seat did not pass on the warning:\n%s", f.Last())
	}

	// To enable it again is not destructive and takes one press.
	run(t, c, NewFake(170, 48).Type(segmentDown("ADMIN")).Press(KeyEnter))
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "ADMIN=yes\n") {
		t.Fatalf("turning ssh back on asked for a confirm or did not write:\n%s", raw)
	}
}

// SSH_TO is an address, not a word. Thus it opens the text prompt that the
// other non-toggle keys open. The check of pf render refuses a value
// outside AGENT_NET.
func TestSettingsEditsASegmentsSSHToThroughThePrompt(t *testing.T) {
	c, path := segSettings(t)
	run(t, c, NewFake(120, 48).Type(segmentDown("SSH_TO")).Press(KeyEnter).Type("10.77.0.10-10.77.0.12").Press(KeyEnter))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "SSH_TO=10.77.0.10-10.77.0.12\n") {
		t.Fatalf("the prompt did not write the range:\n%s", raw)
	}
	before := string(raw)
	f := run(t, c, NewFake(120, 48).Type(segmentDown("SSH_TO")).Press(KeyEnter).Type("10.99.0.5").Press(KeyEnter))
	if raw, _ = os.ReadFile(path); string(raw) != before {
		t.Fatalf("an address outside AGENT_NET was written:\n%s", raw)
	}
	if !strings.Contains(f.Last(), "AGENT_NET") {
		t.Fatalf("the refusal does not say why:\n%s", f.Last())
	}
}

// The budget of one plain segment is on its own screen. An absent key
// shows the value that applies and where it comes from, not a blank. The
// prompt writes the key, and "-" removes the line again, so that the
// segment takes the System value.
func TestSettingsSetsASegmentsOwnConnectionBudget(t *testing.T) {
	c, path := segSettings(t)
	last := run(t, c, NewFake(120, 48).Type(segmentDown("CONN_PER_IP"))).Last()
	for _, want := range []string{"Connection budget", "[CONN_PER_IP]", "Segments value in System > Settings"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on the desk's settings:\n%s", want, last)
		}
	}
	if got := lineWith(last, "Flows per device"); !strings.Contains(got, "128 (default, from System > Settings)") {
		t.Fatalf("an absent CONN_PER_IP does not show the inherited default: %q", got)
	}
	if err := os.WriteFile(c.NetEnvLocal, []byte("SEG_CONN_TOTAL='0'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(120, 48).Type(segmentDown("CONN_PER_IP")).Press(KeyEnter).Type("512").Press(KeyEnter))
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "CONN_PER_IP=512\n") {
		t.Fatalf("the prompt did not write the budget:\n%s", raw)
	}
	if got := lineWith(f.Last(), "Flows per device"); !strings.Contains(got, "512") || strings.Contains(got, "System") {
		t.Fatalf("a set CONN_PER_IP does not show as its own value: %q", got)
	}
	if got := lineWith(f.Last(), "Flows in total"); !strings.Contains(got, "0 (off, from System > Settings)") {
		t.Fatalf("an inherited 0 does not show as off: %q", got)
	}
	// The prompt opens on the current value, "512". Thus clear it first.
	clear3 := func(f *Fake) *Fake { return f.Press(KeyBackspace).Press(KeyBackspace).Press(KeyBackspace) }
	f = run(t, c, clear3(NewFake(120, 48).Type(segmentDown("CONN_PER_IP")).Press(KeyEnter)).Type("8").Press(KeyEnter))
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "CONN_PER_IP=512\n") {
		t.Fatalf("a cap under the floor went in:\n%s", raw)
	}
	if !strings.Contains(f.Last(), "CONN_PER_IP") {
		t.Fatalf("the refusal does not name the key:\n%s", f.Last())
	}
	run(t, c, clear3(NewFake(120, 48).Type(segmentDown("CONN_PER_IP")).Press(KeyEnter)).Type("-").Press(KeyEnter))
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), "CONN_PER_IP") {
		t.Fatalf("- did not remove the line:\n%s", raw)
	}
}

// The agent and the house have their budget on their own screens too. The
// rows edit net.env.local, as the rows in System > Settings do.
func TestSettingsShowsTheAgentAndHouseBudgetOnTheirOwnScreens(t *testing.T) {
	c, _ := testConfig(t)
	run(t, c, NewFake(120, 48).Type(keys(netAgent, secSettings)).Press(KeyEnter).Type("256").Press(KeyEnter))
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil || !strings.Contains(string(raw), "AGENT_CONN_PER_IP='256'") {
		t.Fatalf("the agent screen did not write AGENT_CONN_PER_IP: %v\n%s", err, raw)
	}
	n := 0
	for _, g := range houseGroups {
		n += len(g.items)
	}
	last := run(t, c, NewFake(120, 60).Type(keys(netHouse, secSettings)+strings.Repeat("j", n))).Last()
	for _, want := range []string{"Connection budget", "[HOUSE_CONN_PER_IP]", "New flows in total"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q on the house's settings:\n%s", want, last)
		}
	}
}
