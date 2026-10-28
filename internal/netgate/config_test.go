package netgate

import (
	"slices"
	"strings"
	"testing"
)

// The shape that apply writes: the agent, the house with its SNI queue, a
// plain segment, and a loopback stub with no set. Keys that netgate does
// not read are ignored.
const applyDNSJSON = `{
  "listen": 53,
  "nft_table": "inet fortress",
  "segments": [
    {"iface": "eth1", "ip": "10.77.0.1", "upstream": "1.1.1.1:53", "sinkhole": [], "nft_set": "resolved_v4", "log": "/var/log/pi-fortress/dns.jsonl", "address_only": true},
    {"name": "house", "iface": "eth2", "ip": "10.78.0.1", "upstream": "1.1.1.1:53", "sinkhole": [], "nft_set": "resolved_house_v4", "log": "", "sni_queue": 1, "sni_ech_ips": "/etc/pi-fortress/house-ech.ips"},
    {"name": "desk", "iface": "eth3", "ip": "10.79.0.1", "upstream": "1.1.1.1:53", "sinkhole": [], "nft_set": "resolved_desk_v4", "log": ""},
    {"name": "stub", "iface": "lo", "ip": "127.0.0.1", "upstream": "", "dot_name": "x", "dot_ips": [], "dot_iface": "", "sinkhole": [], "nft_set": "", "log": ""}
  ]
}`

func TestParseDNSConfig(t *testing.T) {
	cfg, skipped, err := ParseDNSConfig(strings.NewReader(applyDNSJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Table != "inet fortress" {
		t.Errorf("table %q", cfg.Table)
	}
	if want := []string{"resolved_v4", "resolved_house_v4", "resolved_desk_v4"}; !slices.Equal(cfg.Sets, want) {
		t.Errorf("sets %v, want %v", cfg.Sets, want)
	}
	if !slices.Equal(cfg.Queues, []uint16{1}) {
		t.Errorf("queues %v, want [1]", cfg.Queues)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped %v", skipped)
	}
}

// A set that is not a resolver set never becomes a target of GATE, also
// when dns.json names it.
func TestParseDNSConfigSkipsOtherSets(t *testing.T) {
	long := "resolved_" + strings.Repeat("a", maxSetName) + "_v4"
	in := `{"nft_table": "inet fortress", "segments": [
	  {"nft_set": "resolved_v4"}, {"nft_set": "blacklist_v4"}, {"nft_set": "direct_ip_v4"},
	  {"nft_set": "` + long + `"}, {"nft_set": "resolved_v4"}]}`
	cfg, skipped, err := ParseDNSConfig(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Sets, []string{"resolved_v4"}) {
		t.Errorf("sets %v", cfg.Sets)
	}
	if !slices.Equal(skipped, []string{"blacklist_v4", "direct_ip_v4", long}) {
		t.Errorf("skipped %v", skipped)
	}
}

func TestParseDNSConfigRefuses(t *testing.T) {
	for _, in := range []string{
		``,
		`{`,
		`{"segments": []}`,
		`{"nft_table": "inet", "segments": []}`,
		`{"nft_table": "inet fortress; flush ruleset", "segments": []}`,
		`{"nft_table": "bridge fortress", "segments": []}`,
		`{"nft_table": "inet fortress", "segments": [{"sni_queue": 70000}]}`,
	} {
		if _, _, err := ParseDNSConfig(strings.NewReader(in)); err == nil {
			t.Errorf("ParseDNSConfig(%q) passed", in)
		}
	}
}
