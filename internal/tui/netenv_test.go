package tui

import (
	"os"
	"strings"
	"testing"
)

// The box block shows the overlay, and that is the main point. A ship
// writes net.env and keeps net.env.local, so DoT is enabled in the
// overlay. A seat that read only the shipped file told an operator that
// the provider was off while the box ran it.
func TestSettingsShowsTheOverlayNotTheShippedFile(t *testing.T) {
	c, _ := testConfig(t)
	if err := os.WriteFile(c.NetEnvLocal, []byte("DNS_UPSTREAM=1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(100, 40).Type(keys(netSystem, secSettings))).Last()
	if !strings.Contains(lineWith(last, "Upstream DNS"), "1.1.1.1") {
		t.Fatalf("the overlay value is not shown:\n%s", last)
	}
	if strings.Contains(last, "9.9.9.9") {
		t.Fatalf("the shipped value is shown instead:\n%s", last)
	}
}

// pf render refuses a DoT name without its addresses, and the addresses
// without the name. Thus one ask for each key could never enable the
// provider: render would refuse the first edit each time. Enter on either
// key asks for both and sends one edit.
func TestSettingsEditsTheDoTPairAsOneEdit(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(100, 40).
		Type(settingsDown("DOT_AUTH_NAME")).Press(KeyEnter).
		Type("dns.quad9.net").Press(KeyEnter).
		Type("9.9.9.9 149.112.112.112").Press(KeyEnter))
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatalf("no overlay was written: %v\n%s", err, f.Last())
	}
	// Quoted, because apply.sh sources this file, and the addresses are one
	// value with a space in it.
	for _, want := range []string{"DOT_AUTH_NAME='dns.quad9.net'", "DOT_IPS='9.9.9.9 149.112.112.112'"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("no %q in the overlay:\n%s", want, raw)
		}
	}
	if !strings.Contains(f.Last(), "DoT provider saved") {
		t.Fatalf("the seat did not say it saved:\n%s", f.Last())
	}
	// The code never writes the shipped file.
	if shipped, _ := os.ReadFile(c.NetEnvPath); strings.Contains(string(shipped), "quad9") {
		t.Fatalf("net.env was rewritten:\n%s", shipped)
	}
}

// Half a provider is the combination that render refuses. The seat must
// say so, and not write a file that the next apply fails on.
func TestSettingsRefusesHalfADoTProvider(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(100, 40).
		Type(settingsDown("DOT_IPS")).Press(KeyEnter).
		Type("dns.quad9.net").Press(KeyEnter).
		Press(KeyEnter))
	if _, err := os.Stat(c.NetEnvLocal); err == nil {
		raw, _ := os.ReadFile(c.NetEnvLocal)
		t.Fatalf("a refused edit wrote the overlay:\n%s", raw)
	}
	if !strings.Contains(f.Last(), "DOT_IPS") {
		t.Fatalf("the refusal does not name the missing half:\n%s", f.Last())
	}
}

// UNTRUSTED_UPLINK is the public-wifi posture. One press changes it, as
// for the on/off keys of the house. Its default is 0, and an absent line
// means the same. Thus the first press must write 1, and not read the
// empty value as already off.
//
// It is also the most important case for a pf render check before the
// edit. When armed, it closes SSH on the uplink. Render refuses that on a
// box where no house admin address and no ADMIN=yes segment can still
// reach the Pi. Without the check, the seat would write the line that
// locks out its own operator at the next apply.
//
// To arm it, the operator must first answer y/N, so the presses here are
// Enter then y. Off is still one press. Refer to
// TestSettingsAsksBeforeClosingSSHOnTheUplink.
func TestSettingsFlipsTheUntrustedUplink(t *testing.T) {
	c, _ := testConfig(t)
	f := run(t, c, NewFake(100, 40).Type(settingsDown("UNTRUSTED_UPLINK")).Press(KeyEnter).Type("y"))
	if _, err := os.Stat(c.NetEnvLocal); err == nil {
		t.Fatal("the seat armed an uplink it could not reach the Pi over")
	}
	if !strings.Contains(f.Last(), "UNTRUSTED_UPLINK=1") {
		t.Fatalf("the refusal does not say what it refused:\n%s", f.Last())
	}

	// With an admin address on the house, there is a way back in, and
	// render allows it.
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.20\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, c, NewFake(100, 40).Type(settingsDown("UNTRUSTED_UPLINK")).Press(KeyEnter).Type("y"))
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "UNTRUSTED_UPLINK='1'") {
		t.Fatalf("a confirmed press did not arm it:\n%s", raw)
	}
	run(t, c, NewFake(100, 40).Type(settingsDown("UNTRUSTED_UPLINK")).Press(KeyEnter))
	if raw, _ = os.ReadFile(c.NetEnvLocal); !strings.Contains(string(raw), "UNTRUSTED_UPLINK='0'") {
		t.Fatalf("second press did not flip back:\n%s", raw)
	}
}

// This test exists for a lockout that occurred on the real Pi. A driver
// moved onto this row and pressed Enter. At the next apply, port 22 on the
// uplink closed, on a box whose operator was on the other end of that
// uplink. Enter alone must now write nothing.
//
// The three cancels are the shape of the driver itself: a key that is not
// y, the Esc that all other prompts accept, and a second Enter. A script
// that answers each prompt with Enter sends a second Enter. All three must
// not change the file and must say so. If the seat ignores the press with
// no message, the operator learns that the press did nothing.
func TestSettingsAsksBeforeClosingSSHOnTheUplink(t *testing.T) {
	c, _ := testConfig(t)
	// A way back in, so that only the confirm is between the press and
	// the file.
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_ADMIN_IP=10.78.0.20\n"), 0644); err != nil {
		t.Fatal(err)
	}
	arm := func(f *Fake) *Fake {
		return f.Type(settingsDown("UNTRUSTED_UPLINK")).Press(KeyEnter)
	}
	for _, tc := range []struct {
		name string
		keys func(*Fake) *Fake
	}{
		{"Enter alone leaves the prompt open", func(f *Fake) *Fake { return arm(f) }},
		{"n declines", func(f *Fake) *Fake { return arm(f).Type("n") }},
		{"a key that is not y declines", func(f *Fake) *Fake { return arm(f).Type("x") }},
		{"Esc declines", func(f *Fake) *Fake { return arm(f).Press(KeyEsc) }},
		{"a second Enter declines", func(f *Fake) *Fake { return arm(f).Press(KeyEnter) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := run(t, c, tc.keys(NewFake(100, 40)))
			if _, err := os.Stat(c.NetEnvLocal); err == nil {
				raw, _ := os.ReadFile(c.NetEnvLocal)
				t.Fatalf("a press that was never confirmed closed uplink ssh:\n%s", raw)
			}
			if tc.name == "Enter alone leaves the prompt open" {
				if !strings.Contains(f.Last(), "[y/N]") {
					t.Fatalf("Enter did not open the confirm:\n%s", f.Last())
				}
				return
			}
			if !strings.Contains(f.Last(), "cancelled") {
				t.Fatalf("the seat did not say it cancelled:\n%s", f.Last())
			}
		})
	}

	// The prompt must name what stops, when it stops, and the way back in.
	// An operator who reads only this line must be able to decide.
	f := run(t, c, arm(NewFake(100, 40)))
	for _, want := range []string{"ssh on the uplink", "at the next apply", "ADMIN=yes"} {
		if !strings.Contains(f.Last(), want) {
			t.Fatalf("the confirm does not say %q:\n%s", want, f.Last())
		}
	}
	// And it fits an 80-column terminal, because the footer clips from the
	// right, and the [y/N] is the last item on it. A warning whose answer is
	// clipped away is worse than no warning.
	narrow := run(t, c, arm(NewFake(80, 40))).Last()
	if !strings.Contains(narrow, "[y/N]") {
		t.Fatalf("eighty columns clipped the answer off the prompt:\n%s", narrow)
	}

	// y is the one key that writes.
	run(t, c, arm(NewFake(100, 40)).Type("y"))
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatalf("a confirmed flip wrote nothing: %v", err)
	}
	if !strings.Contains(string(raw), "UNTRUSTED_UPLINK='1'") {
		t.Fatalf("a confirmed flip did not arm it:\n%s", raw)
	}

	// To disable it only gives back a way in that the operator already
	// had. Thus it is one press and must not ask.
	f = run(t, c, arm(NewFake(100, 40)))
	if raw, _ = os.ReadFile(c.NetEnvLocal); !strings.Contains(string(raw), "UNTRUSTED_UPLINK='0'") {
		t.Fatalf("turning the uplink back on asked for a confirm or did not write:\n%s", raw)
	}
	if strings.Contains(f.Last(), "[y/N]") {
		t.Fatalf("1 -> 0 asked for a confirm:\n%s", f.Last())
	}
}

// WG_IF is the other way for the house to go dark at the next apply. When
// it is set, the house WAN path logs and drops, and does not accept.
// Render never checks that the name is a real interface. Thus a typo gives
// a house with no way out, and no row on this screen says why.
func TestSettingsAsksBeforeSendingTheHouseThroughATunnel(t *testing.T) {
	c, _ := testConfig(t)
	set := func(f *Fake, v string) *Fake {
		return f.Type(settingsDown("WG_IF")).Press(KeyEnter).Type(v).Press(KeyEnter)
	}
	before, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		keys func(*Fake) *Fake
	}{
		{"n declines", func(f *Fake) *Fake { return set(f, "wg0").Type("n") }},
		{"a key that is not y declines", func(f *Fake) *Fake { return set(f, "wg0").Type("x") }},
		{"Esc declines", func(f *Fake) *Fake { return set(f, "wg0").Press(KeyEsc) }},
		{"a third Enter declines", func(f *Fake) *Fake { return set(f, "wg0").Press(KeyEnter) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := run(t, c, tc.keys(NewFake(100, 40)))
			after, err := os.ReadFile(c.HouseEnv)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("a declined confirm sent the house through a tunnel anyway:\n%s", after)
			}
			if !strings.Contains(f.Last(), "cancelled") {
				t.Fatalf("the seat did not say it cancelled:\n%s", f.Last())
			}
		})
	}

	f := run(t, c, set(NewFake(100, 40), "wg0"))
	// The prompt names the interface. The operator can see the typo that it
	// must catch only when the screen shows what they typed.
	for _, want := range []string{"wg0", "the next apply", "[y/N]"} {
		if !strings.Contains(f.Last(), want) {
			t.Fatalf("the confirm does not say %q:\n%s", want, f.Last())
		}
	}
	run(t, c, set(NewFake(100, 40), "wg0").Type("y"))
	raw, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "WG_IF=wg0\n") {
		t.Fatalf("a confirmed edit did not name the tunnel:\n%s", raw)
	}

	// The prompt opens on the name of the tunnel, so Enter keeps it. An
	// emptied prompt cancels, and does not clear it. To clear, type "-".
	// The seat then asks, because this removes the kill switch.
	open := func() *Fake { return NewFake(100, 40).Type(settingsDown("WG_IF")).Press(KeyEnter) }
	erase := []KeyKind{KeyBackspace, KeyBackspace, KeyBackspace}
	for _, f := range []*Fake{open().Press(KeyEnter), open().Press(erase...).Press(KeyEnter)} {
		run(t, c, f)
		if raw, _ = os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "WG_IF=wg0\n") {
			t.Fatalf("Enter on the prompt cleared or changed the tunnel:\n%s", raw)
		}
	}
	f = run(t, c, open().Press(erase...).Type("-").Press(KeyEnter))
	if raw, _ = os.ReadFile(c.HouseEnv); !strings.Contains(string(raw), "WG_IF=wg0\n") || !strings.Contains(f.Last(), "[y/N]") {
		t.Fatalf("clearing WG_IF did not ask first:\n%s\n%s", raw, f.Last())
	}
	run(t, c, open().Press(erase...).Type("-").Press(KeyEnter).Type("y"))
	if raw, _ = os.ReadFile(c.HouseEnv); strings.Contains(string(raw), "WG_IF=wg0") {
		t.Fatalf("a confirmed clear left the tunnel:\n%s", raw)
	}
}

// The house has its own provider and its own pair. The code sets and
// checks them the same way. Render refuses HOUSE_DOT_IPS unless the
// DOT_IPS of the box is also set. Thus half a house provider must not
// reach the file either.
func TestSettingsEditsTheHouseDoTPair(t *testing.T) {
	c, _ := testConfig(t)
	before, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	f := run(t, c, NewFake(100, 40).
		Type(settingsDown("HOUSE_DOT_AUTH_NAME")).Press(KeyEnter).
		Type("dns.quad9.net").Press(KeyEnter).
		Type("9.9.9.9").Press(KeyEnter))
	after, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("a house provider went in without the box's own:\n%s", after)
	}
	if !strings.Contains(f.Last(), "DOT_IPS") {
		t.Fatalf("the refusal does not name what is missing:\n%s", f.Last())
	}

	// When the provider of the box is set, the code accepts the provider
	// of the house. The pair is quoted although pf render parses this file,
	// because vm/itest sources it, and an unquoted list runs its second
	// address as a command. Render strips the quotes from these two keys.
	if _, err := c.SetNetEnv(map[string]string{"DOT_AUTH_NAME": "dns.quad9.net", "DOT_IPS": "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	run(t, c, NewFake(100, 40).
		Type(settingsDown("HOUSE_DOT_AUTH_NAME")).Press(KeyEnter).
		Type("dns.quad9.net").Press(KeyEnter).
		Type("149.112.112.112").Press(KeyEnter))
	raw, err := os.ReadFile(c.HouseEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "HOUSE_DOT_IPS='149.112.112.112'\n") {
		t.Fatalf("the house DoT pair is not quoted:\n%s", raw)
	}
	// All other values in the file stay bare. If not, the quotes become
	// part of the value.
	if !strings.Contains(string(raw), "HOUSE_IF=eth1\n") {
		t.Fatalf("a plain house key was quoted:\n%s", raw)
	}
}

// AGENT_DNS is one of two words, and Enter steps between them. The first
// press on an absent line writes forward, not fakeip, because absent
// already means fakeip. The Settings of the Agent network say which mode
// the fence is in.
func TestSettingsFlipsTheAgentDNSMode(t *testing.T) {
	c, _ := testConfig(t)
	last := run(t, c, NewFake(120, 50).Type(settingsDown("AGENT_DNS"))).Last()
	for _, want := range []string{"Agent DNS", "fakeip (default)", "[AGENT_DNS]", "Enter flips", "198.18.0.0/16 (default)"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q:\n%s", want, last)
		}
	}
	agent := run(t, c, NewFake(120, 50).Type(keys(netAgent, secSettings))).Last()
	if !strings.Contains(lineWith(agent, "DNS"), "fake-IP from 198.18.0.0/16") {
		t.Fatalf("the agent view does not say an absent line is fakeip:\n%s", agent)
	}
	f := run(t, c, NewFake(120, 50).Type(settingsDown("AGENT_DNS")).Press(KeyEnter))
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatalf("the flip wrote nothing: %v\n%s", err, f.Last())
	}
	if !strings.Contains(string(raw), "AGENT_DNS='forward'") {
		t.Fatalf("the first press did not write forward:\n%s", raw)
	}
	if strings.Contains(f.Last(), "[y/N]") {
		t.Fatalf("the mode flip asked for a confirm:\n%s", f.Last())
	}
	agent = run(t, c, NewFake(120, 50).Type(keys(netAgent, secSettings))).Last()
	if strings.Contains(lineWith(agent, "DNS"), "fake-IP") {
		t.Fatalf("the agent view still says fakeip after forward was set:\n%s", agent)
	}
	run(t, c, NewFake(120, 50).Type(settingsDown("AGENT_DNS")).Press(KeyEnter))
	if raw, _ = os.ReadFile(c.NetEnvLocal); !strings.Contains(string(raw), "AGENT_DNS='fakeip'") {
		t.Fatalf("the second press did not step back to fakeip:\n%s", raw)
	}
}

// FAKEIP_NET goes through the check of render itself. A public prefix is a
// pool that the broker could really dial. A pool over the agent segment
// answers lookups with the addresses of real machines. The code refuses
// both before the file. A pool in a private range goes in.
func TestSettingsSetsTheFakeIPPool(t *testing.T) {
	c, _ := testConfig(t)
	set := func(v string) *Fake {
		return run(t, c, NewFake(120, 50).Type(settingsDown("FAKEIP_NET")).Press(KeyEnter).Type(v).Press(KeyEnter))
	}
	for _, bad := range []string{"8.8.0.0/16", "10.77.0.0/16", "198.18.0.1/16", "198.18.0.0/12"} {
		f := set(bad)
		if _, err := os.Stat(c.NetEnvLocal); err == nil {
			raw, _ := os.ReadFile(c.NetEnvLocal)
			t.Fatalf("%s went in:\n%s", bad, raw)
		}
		if !strings.Contains(f.Last(), "FAKEIP_NET") {
			t.Fatalf("the refusal of %s does not name the key:\n%s", bad, f.Last())
		}
	}
	set("10.99.0.0/16")
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil || !strings.Contains(string(raw), "FAKEIP_NET='10.99.0.0/16'") {
		t.Fatalf("a private pool was not written: %v\n%s", err, raw)
	}
}

// The nine budgets are also rows. The floor of render refuses a per-device
// cap that would break page loads. 0 is off and shows as off. An absent
// line shows as the default, not as blank.
func TestSettingsSetsTheConnectionBudgets(t *testing.T) {
	c, _ := testConfig(t)
	last := run(t, c, NewFake(120, 60).Type(settingsDown("SEG_CONN_TOTAL"))).Last()
	for _, want := range []string{"Connection budgets", "Agent: flows per device", "House: new flows per device", "[SEG_CONN_TOTAL]"} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q:\n%s", want, last)
		}
	}
	if !strings.Contains(lineWith(last, "Segments: flows in total"), "(default)") {
		t.Fatalf("an absent budget is not named as the default:\n%s", last)
	}
	set := func(key, v string) *Fake {
		return run(t, c, NewFake(120, 60).Type(settingsDown(key)).Press(KeyEnter).Type(v).Press(KeyEnter))
	}
	f := set("AGENT_CONN_PER_IP", "8")
	if _, err := os.Stat(c.NetEnvLocal); err == nil {
		t.Fatal("a per-device cap under the floor went in")
	}
	if !strings.Contains(f.Last(), "AGENT_CONN_PER_IP") {
		t.Fatalf("the refusal does not name the key:\n%s", f.Last())
	}
	set("HOUSE_NEW_PER_IP", "200/800")
	set("SEG_NEW_TOTAL", "400/2000")
	f = set("SEG_CONN_TOTAL", "0")
	raw, err := os.ReadFile(c.NetEnvLocal)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HOUSE_NEW_PER_IP='200/800'", "SEG_NEW_TOTAL='400/2000'", "SEG_CONN_TOTAL='0'"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("no %s in the overlay:\n%s", want, raw)
		}
	}
	if !strings.Contains(lineWith(f.Last(), "Segments: flows in total"), "0 (off)") {
		t.Fatalf("a budget of 0 is not shown as off:\n%s", f.Last())
	}
}

// The Secrets screen has seven keys of its own, 66 characters before the
// common keys start. Thus at 80 columns, the footer clipped to
// "Esc back  ^~". An operator on a stock terminal could not see that ?
// opened help. ? is the one key that would tell them about the six keys
// that were cut off. Now the keys of the screen go first.
func TestFooterKeepsTheCommonKeysAtEightyColumns(t *testing.T) {
	c, _ := testConfig(t)
	for _, tc := range []struct{ w, wantKeys int }{{80, 4}, {120, 7}} {
		last := run(t, c, NewFake(tc.w, 24).Type(keys(netAgent, secKeys))).Last()
		foot := strings.Split(last, "\n")
		line := foot[len(foot)-1]
		for _, want := range []string{"Esc back", "^R refresh", "? help"} {
			if !strings.Contains(line, want) {
				t.Fatalf("%d columns lost %q: %q", tc.w, want, line)
			}
		}
		if n := strings.Count(line, " unlock") + strings.Count(line, " lock") +
			strings.Count(line, " claim") + strings.Count(line, " disable") +
			strings.Count(line, " restore") + strings.Count(line, " purge") +
			strings.Count(line, " delete"); n != tc.wantKeys {
			t.Fatalf("%d columns kept %d screen keys, want %d: %q", tc.w, n, tc.wantKeys, line)
		}
		if tc.w == 80 && !strings.Contains(line, "..") {
			t.Fatalf("nothing says keys were dropped: %q", line)
		}
		if len([]rune(strings.TrimRight(line, " "))) > tc.w {
			t.Fatalf("the footer is wider than the terminal: %q", line)
		}
	}
}
