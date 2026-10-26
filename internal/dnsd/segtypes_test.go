package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/render"
)

// DNS_TYPES makes the address-only answers of a desk wider by type, for
// all names on that segment. The segment forwards TXT. It still does not
// forward all other non-A types.
func TestSegmentExtraTypesForwardOnlyThoseTypes(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil, map[string][4]byte{"desk.example": {1, 2, 3, 4}}, nil, 300)
	h.srv.segs[0].ExtraTypes = []uint16{uint16(dnsmessage.TypeTXT)}
	h.ask(t, "desk.example", dnsmessage.TypeTXT)
	if n := h.up.asked.Load(); n != 1 {
		t.Fatalf("TXT with DNS_TYPES=TXT: upstream asked %d times, want 1", n)
	}
	h.ask(t, "desk.example", dnsmessage.TypeSRV)
	if n := h.up.asked.Load(); n != 1 {
		t.Fatalf("SRV without DNS_TYPES: upstream asked %d times, want still 1", n)
	}
	rows := h.logLines(t)
	if last := rows[len(rows)-1]; last.Act != dnslog.ActFiltered {
		t.Fatalf("SRV row: %+v", last)
	}
}

// DNS_TYPES cannot widen AAAA, HTTPS or SVCB. These are always answered
// empty and never forwarded, also when DNS_TYPES lists them.
func TestSegmentExtraTypesNeverWidenTheAlwaysEmptyTypes(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil, map[string][4]byte{"desk.example": {1, 2, 3, 4}}, nil, 300)
	types := []uint16{uint16(dnsmessage.TypeAAAA), typeHTTPS, typeSVCB}
	h.srv.segs[0].ExtraTypes = types
	for _, qt := range types {
		hdr, answers := h.ask(t, "desk.example", dnsmessage.Type(qt))
		if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 {
			t.Fatalf("type %d with DNS_TYPES: rcode %v answers %d, want an empty answer", qt, hdr.RCode, len(answers))
		}
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("DNS_TYPES widened an always-empty type: upstream asked %d times", n)
	}
}

func TestNewRefusesExtraTypesWithoutAddressOnly(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.conf")
	if err := os.WriteFile(sink, nil, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		NFTTable: "inet fortress", NFT: &fakeNFT{},
		Segments: []Segment{{
			Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: "127.0.0.1:1", SinkholeFiles: []string{sink},
			NFTSet: "resolved_v4", ExtraTypes: []uint16{uint16(dnsmessage.TypeTXT)},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "dns_types without address_only") {
		t.Fatalf("dns_types without address_only: %v", err)
	}
}

func TestParseConfigTakesDNSTypes(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{"nft_table": "inet fortress", "segments": [
	  {"name": "desk", "iface": "eth3", "ip": "10.79.0.1", "upstream": "127.0.0.1:5301", "nft_set": "resolved_desk_v4",
	   "address_only": true, "dns_types": "txt SRV TYPE257"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Segments[0].ExtraTypes; len(got) != 3 || got[0] != uint16(dnsmessage.TypeTXT) || got[1] != uint16(dnsmessage.TypeSRV) || got[2] != 257 {
		t.Fatalf("ExtraTypes %v", got)
	}
	if _, err := ParseConfig(strings.NewReader(`{"nft_table": "inet fortress", "segments": [
	  {"iface": "eth3", "ip": "10.79.0.1", "upstream": "127.0.0.1:5301", "nft_set": "resolved_desk_v4",
	   "address_only": true, "dns_types": "TEXT"}]}`)); err == nil || !strings.Contains(err.Error(), `dns_types "TEXT"`) {
		t.Fatalf("bad type: %v", err)
	}
}

// apply validates DNS_TYPES with the list of render before pf dns ever
// reads it. The two lists must accept exactly the same names.
func TestRenderDNSTypeNamesMatchDnsd(t *testing.T) {
	if len(render.DNSTypeNames) != len(namedTypes) {
		t.Fatalf("render has %d names, dnsd %d", len(render.DNSTypeNames), len(namedTypes))
	}
	for _, n := range render.DNSTypeNames {
		if _, ok := parseQType(n); !ok {
			t.Errorf("render takes %s, pf dns does not", n)
		}
	}
	for _, typ := range namedTypes {
		if !render.ValidDNSType(qtypeName(typ)) {
			t.Errorf("pf dns takes %s, render does not", qtypeName(typ))
		}
	}
	for _, bad := range []string{"TEXT", "TYPE", "TYPE0", "TYPE70000"} {
		if render.ValidDNSType(bad) {
			t.Errorf("render takes %s", bad)
		}
	}
}
