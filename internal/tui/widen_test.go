package tui

import (
	"os"
	"strings"
	"testing"
)

// A save that opens the fence does not ask: the confirm set is for the
// changes that cost the way in. But its message says the cost at the press,
// at the start of the footer, where an 80-column clip does not reach it.
func TestWideningSaveSaysItsCost(t *testing.T) {
	for _, tc := range []struct {
		name, keys, cost string
		desk             string // extra desk.env lines
	}{
		{"vpn", settingsDown("HOUSE_BLOCK_VPN", "desk"), "devices may route around the filter", ""},
		{"house direct ip", settingsDown("HOUSE_BLOCK_DIRECT_IP", "desk"), "direct-IP web connections will pass", ""},
		{"agent dns", settingsDown("AGENT_DNS", "desk"), "names may carry data out", ""},
		{"desk direct ip", segmentDown("BLOCK_DIRECT_IP"), "only the blocklist will filter", ""},
		{"desk paranoid", segmentDown("PARANOID"), "names outside the allowlist will resolve", "PARANOID=on\n"},
		{"egress audit", settingsDown("HOUSE_EGRESS", "desk"), "what strict would drop will pass, logged", ""},
		{"call udp", settingsDown("HOUSE_ALLOW_CALL_UDP", "desk"), "call apps' UDP media will pass", ""},
		{"private dns", settingsDown("HOUSE_PRIVATE_DNS", "desk"), "the Pi may not filter devices' DNS", ""},
		{"wifi calling", settingsDown("HOUSE_ALLOW_WIFI_CALLING", "desk"), "IPsec opens to anywhere; IKEv2 VPNs get through too", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, path := segSettings(t)
			if tc.desk != "" {
				raw, _ := os.ReadFile(path)
				if err := os.WriteFile(path, append(raw, tc.desk...), 0644); err != nil {
					t.Fatal(err)
				}
			}
			last := run(t, c, NewFake(80, 24).Type(tc.keys).Press(KeyEnter)).Last()
			rows := strings.Split(strings.TrimRight(last, "\n"), "\n")
			footer := rows[len(rows)-1]
			if !strings.Contains(footer, tc.cost) {
				t.Fatalf("the save does not say %q at 80 columns:\n%s", tc.cost, footer)
			}
		})
	}
}

// A save that closes the fence again has no cost to say.
func TestTighteningSaveSaysNoCost(t *testing.T) {
	c, _ := testConfig(t)
	if err := os.WriteFile(c.HouseEnv, []byte("HOUSE_IF=eth1\nHOUSE_BLOCK_VPN=off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(c, NewFake(80, 24).Type(settingsDown("HOUSE_BLOCK_VPN")).Press(KeyEnter))
	if err := a.Run(); err != nil {
		t.Fatal(err)
	}
	if a.msg != "HOUSE_BLOCK_VPN=on saved; A applies" {
		t.Fatalf("msg = %q", a.msg)
	}
}
