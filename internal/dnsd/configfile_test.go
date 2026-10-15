package dnsd

import (
	"strings"
	"testing"
	"time"
)

// The file is the only way to configure more than one segment. Thus the
// two-segment case is the important one: each segment must keep its own
// upstream, sinkhole, set and log. A field that leaks from one segment to
// the other is the failure that would put house answers in resolved_v4
// and open the agent gate for them.
func TestParseConfigKeepsSegmentsApart(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{
	  "listen": 53,
	  "nft_table": "inet fortress",
	  "max_ttl": "1h",
	  "segments": [
	    {
	      "iface": "eth1.20",
	      "ip": "10.77.0.1",
	      "upstream": "127.0.0.1:5301",
	      "sinkhole": ["/etc/pi-fortress/blocked-domains.conf", "/etc/pi-fortress/doh-domains.conf"],
	      "nft_set": "resolved_v4",
	      "log": "/var/log/pi-fortress/dns.jsonl"
	    },
	    {
	      "name": "house",
	      "iface": "eth1.78",
	      "ip": "10.78.0.1",
	      "upstream": "127.0.0.1:5302",
	      "sinkhole": ["/etc/pi-fortress/house-domains.conf"],
	      "nft_set": "resolved_house_v4",
	      "log": "/var/log/pi-fortress/dns-house.jsonl"
	    }
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != 53 || cfg.NFTTable != "inet fortress" || cfg.MaxTTL != time.Hour {
		t.Fatalf("globals wrong: %+v", cfg)
	}
	if len(cfg.Segments) != 2 {
		t.Fatalf("got %d segments", len(cfg.Segments))
	}
	// Pointers, not copies: a Segment has an atomic pointer to its hosts, and
	// a copy of one trips vet.
	agent, house := &cfg.Segments[0], &cfg.Segments[1]
	if agent.Name != "" || agent.Iface != "eth1.20" || agent.IP.String() != "10.77.0.1" {
		t.Fatalf("agent segment wrong: %+v", agent)
	}
	if len(agent.SinkholeFiles) != 2 || agent.NFTSet != "resolved_v4" {
		t.Fatalf("agent policy wrong: %+v", agent)
	}
	if house.Name != "house" || house.Iface != "eth1.78" || house.IP.String() != "10.78.0.1" {
		t.Fatalf("house segment wrong: %+v", house)
	}
	if len(house.SinkholeFiles) != 1 || house.NFTSet != "resolved_house_v4" {
		t.Fatalf("house policy wrong: %+v", house)
	}
	if house.Upstream == agent.Upstream || house.LogPath == agent.LogPath {
		t.Fatalf("segments share an upstream or a log:\n%+v\n%+v", agent, house)
	}
}

func TestParseConfigRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no segments", `{"segments": []}`, "no segments"},
		{"absent segments", `{"listen": 53}`, "no segments"},
		// A misspelled key gives a segment a default that nobody chose. Thus the
		// parser refuses it and does not ignore it.
		{"unknown key", `{"segments": [{"nft-set": "resolved_v4"}]}`, "nft-set"},
		{"bad ip", `{"segments": [{"name": "house", "ip": "10.78.0"}]}`, `segment "house": ip`},
		{"bad dot ip", `{"segments": [{"ip": "10.77.0.1", "dot_ips": ["9.9.9"]}]}`, "dot_ips"},
		{"bad duration", `{"max_ttl": "1 hour", "segments": [{"ip": "10.77.0.1"}]}`, "max_ttl"},
		{"not json", `nope`, "dns config"},
		// The name of the agent segment is "". Thus an index must replace it. If
		// not, the message gives the wrong field but not the segment.
		{"unnamed segment says its index", `{"segments": [{"ip": "10.77.0.1"}, {"ip": "nope"}]}`, "segment 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(strings.NewReader(tc.in))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q in: %v", tc.want, err)
			}
		})
	}
}

// DOT_IPS is space-separated in net.env. A renderer that copies that value
// into one JSON string should not have to split it first.
func TestParseConfigTakesSpaceSeparatedDoTIPs(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{
	  "segments": [{
	    "iface": "eth1.20", "ip": "10.77.0.1", "nft_set": "resolved_v4",
	    "dot_name": "dns.quad9.net", "dot_ips": ["9.9.9.9 149.112.112.112"]
	  }]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Segments[0].DoTIPs; len(got) != 2 || got[1].String() != "149.112.112.112" {
		t.Fatalf("dot_ips %v", got)
	}
}
