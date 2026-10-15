package install

import "testing"

const linkFixture = `[
  {"ifname":"lo","link_type":"loopback","operstate":"UNKNOWN"},
  {"ifname":"eth0","link_type":"ether","operstate":"UP"},
  {"ifname":"eth1","link_type":"ether","operstate":"UP"},
  {"ifname":"wlan0","link_type":"ether","operstate":"DOWN"}
]`

const routeFixtureEth0 = `[{"dst":"default","dev":"eth0","gateway":"192.168.1.1"}]`

const routeFixtureEmpty = `[]`

func TestProposeWithDefaultRoute(t *testing.T) {
	p, err := Propose([]byte(linkFixture), []byte(routeFixtureEth0))
	if err != nil {
		t.Fatal(err)
	}
	if p.WAN != "eth0" {
		t.Fatalf("WAN = %q, want eth0", p.WAN)
	}
	if p.Agent != "eth1" {
		t.Fatalf("Agent = %q, want eth1", p.Agent)
	}
	want := []string{"eth0", "eth1", "wlan0"}
	if len(p.Candidates) != len(want) {
		t.Fatalf("Candidates = %v, want %v", p.Candidates, want)
	}
	for i, c := range want {
		if p.Candidates[i] != c {
			t.Fatalf("Candidates = %v, want %v", p.Candidates, want)
		}
	}
	house := HouseCandidates(p, p.WAN, p.Agent)
	if len(house) != 1 || house[0] != "wlan0" {
		t.Fatalf("HouseCandidates = %v, want [wlan0]", house)
	}
}

func TestProposeNoDefaultRoute(t *testing.T) {
	p, err := Propose([]byte(linkFixture), []byte(routeFixtureEmpty))
	if err != nil {
		t.Fatal(err)
	}
	if p.WAN == "" {
		t.Fatal("WAN should still be guessed with no default route")
	}
	if p.Agent == "" || p.Agent == p.WAN {
		t.Fatalf("Agent = %q, WAN = %q; must differ and be set", p.Agent, p.WAN)
	}
}

func TestProposeNoEthernet(t *testing.T) {
	_, err := Propose([]byte(`[{"ifname":"lo","link_type":"loopback"}]`), []byte(routeFixtureEmpty))
	if err == nil {
		t.Fatal("expected an error with no ethernet interface")
	}
}

func TestProposeBadJSON(t *testing.T) {
	if _, err := Propose([]byte("not json"), []byte(routeFixtureEmpty)); err == nil {
		t.Fatal("expected a parse error")
	}
	if _, err := Propose([]byte(linkFixture), []byte("not json")); err == nil {
		t.Fatal("expected a parse error")
	}
}
