package dnsd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
)

// addrOnlyHarness is newAliasHarness with an address-only segment and with
// allow in dns_types.allow. The Reload loads the file. An edit on the Pi
// uses the same path.
func addrOnlyHarness(t *testing.T, sinkholed, allow []string, table map[string][4]byte, cname map[string]string, ttl uint32) *harness {
	t.Helper()
	h := newAliasHarness(t, sinkholed, table, cname, ttl)
	path := filepath.Join(t.TempDir(), "dns_types.allow")
	if err := os.WriteFile(path, []byte("# header\n"+strings.Join(allow, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	seg := h.srv.segs[0]
	seg.AddressOnly, seg.TypesAllowPath = true, path
	if err := h.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	h.allow = path
	return h
}

// onlyAddrs is the answer in the form that the address-only segment must
// give: A records, each under the queried name, each with the same TTL.
func onlyAddrs(t *testing.T, name string, ans []dnsmessage.Resource, ttl uint32) []string {
	t.Helper()
	var out []string
	for _, r := range ans {
		a, ok := r.Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("%s: a %T record reached the agent", name, r.Body)
		}
		if r.Header.Name.String() != name+"." {
			t.Fatalf("%s: record owned by %s", name, r.Header.Name)
		}
		if r.Header.TTL != ttl {
			t.Fatalf("%s: ttl %d, want %d", name, r.Header.TTL, ttl)
		}
		out = append(out, netip.AddrFrom4(a.A).String())
	}
	return out
}

const (
	typeNULL = dnsmessage.Type(10)
	typeCAA  = dnsmessage.Type(257)
)

// The resolver answers each type except A here, empty and filtered. The
// upstream never receives the query. TXT and NULL are how a client asks an
// LLM over DNS. The other types also bring text back in.
func TestAddressOnlyAnswersOtherTypesLocally(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil, map[string][4]byte{"ch.at": {1, 2, 3, 4}}, nil, 300)
	types := []dnsmessage.Type{
		dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypeSRV, dnsmessage.TypeALL, typeNULL,
		typeCAA, dnsmessage.TypeNS, dnsmessage.TypeSOA, dnsmessage.TypeCNAME,
	}
	for _, qt := range types {
		hdr, ans := h.ask(t, "what-is-the-key.ch.at", qt)
		if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
			t.Fatalf("%v: rcode %v answers %d, want an empty NOERROR", qt, hdr.RCode, len(ans))
		}
	}
	// The PTR of a public address is a name that the upstream would answer.
	// A private address keeps the NXDOMAIN from bogus-priv.
	if hdr, ans := h.ask(t, "8.8.8.8.in-addr.arpa", dnsmessage.TypePTR); hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("public PTR: rcode %v answers %d", hdr.RCode, len(ans))
	}
	if hdr, _ := h.ask(t, "1.0.168.192.in-addr.arpa", dnsmessage.TypePTR); hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("private PTR: rcode %v, want bogus-priv's NXDOMAIN", hdr.RCode)
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
	rows := h.logLines(t)
	if len(rows) != len(types)+2 {
		t.Fatalf("rows %d, want %d", len(rows), len(types)+2)
	}
	for _, r := range rows[:len(types)+1] {
		if r.Act != dnslog.ActFiltered {
			t.Fatalf("row %+v, want %s", r, dnslog.ActFiltered)
		}
	}
	// And an address still resolves.
	if _, ans := h.ask(t, "ch.at", dnsmessage.TypeA); firstA(t, ans) != "1.2.3.4" {
		t.Fatalf("A: %+v", ans)
	}
}

// A listed pair goes to the upstream as before. An exact entry does not
// include its subdomains or its other types. A "*." entry includes its
// subdomains but not itself.
func TestAddressOnlyAllowForwardsAListedPair(t *testing.T) {
	table := map[string][4]byte{
		"exact.example": {1, 1, 1, 1}, "sub.exact.example": {1, 1, 1, 2},
		"wild.example": {2, 2, 2, 2}, "a.wild.example": {2, 2, 2, 3},
	}
	h := addrOnlyHarness(t, nil, []string{"Exact.Example. TXT srv", "*.wild.example TYPE15 # MX, as the log spells an unnamed type"}, table, nil, 300)
	for _, tc := range []struct {
		name    string
		qt      dnsmessage.Type
		forward bool
	}{
		{"exact.example", dnsmessage.TypeTXT, true},
		{"EXACT.example", dnsmessage.TypeSRV, true},
		{"sub.exact.example", dnsmessage.TypeTXT, false},
		{"exact.example", dnsmessage.TypeMX, false},
		{"a.wild.example", dnsmessage.TypeMX, true},
		{"wild.example", dnsmessage.TypeMX, false},
		{"a.wild.example", dnsmessage.TypeTXT, false},
	} {
		before := h.up.asked.Load()
		h.ask(t, tc.name, tc.qt)
		if got := h.up.asked.Load() > before; got != tc.forward {
			t.Errorf("%s %v: forwarded %v, want %v", tc.name, tc.qt, got, tc.forward)
		}
	}
}

// The chain comes back as addresses under the queried name, with the
// smallest TTL of the chain. The resolver still examines the full chain
// first.
func TestAddressOnlyFlattensAChain(t *testing.T) {
	h := addrOnlyHarness(t,
		[]string{"tracker.adtech.net"}, nil,
		map[string][4]byte{"edge.cdn.example": {9, 9, 9, 9}, "tracker.adtech.net": {6, 6, 6, 6}},
		map[string]string{"www.example.com": "edge.cdn.example", "metrics.yourbank.com": "tracker.adtech.net"},
		300)
	h.up.aliasTTL.Store(60)
	_, ans := h.ask(t, "www.example.com", dnsmessage.TypeA)
	if got := onlyAddrs(t, "www.example.com", ans, 60); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("answer %v", got)
	}
	if got := h.nft.flat(); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("gate set %v", got)
	}
	// The flatten step occurs after the resolver reads the chain. Thus an alias
	// to a listed name still gets the sinkhole, and its address still never
	// goes into the gate set.
	_, ans = h.ask(t, "metrics.yourbank.com", dnsmessage.TypeA)
	if got := onlyAddrs(t, "metrics.yourbank.com", ans, 0); len(got) != 1 || got[0] != "0.0.0.0" {
		t.Fatalf("aliased to a listed name: %v", got)
	}
	if got := h.nft.flat(); len(got) != 1 {
		t.Fatalf("gate set %v", got)
	}
}

// Sixteen addresses get to the agent. The gate set gets the same sixteen
// addresses: each address that this resolver gives is in the set, and an
// address that the agent never gets does not use space in the set.
func TestAddressOnlyCapsTheAddresses(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil, map[string][4]byte{"registry.example": {93, 184, 216, 1}}, nil, 300)
	h.up.manyA.Store(20)
	_, ans := h.ask(t, "registry.example", dnsmessage.TypeA)
	got := onlyAddrs(t, "registry.example", ans, 300)
	if len(got) != maxFlatA {
		t.Fatalf("%d addresses, want %d", len(got), maxFlatA)
	}
	if set := h.nft.flat(); !slices.Equal(set, got) {
		t.Fatalf("gate set took %v, want the answer %v", set, got)
	}
}

// The rcode does not change. The cache holds the full message from the
// upstream. The resolver flattens a cache hit on the way out, as it does a
// new answer. It subtracts the time that the answer was in the cache.
func TestAddressOnlyKeepsRcodesAndFlattensACacheHit(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil,
		map[string][4]byte{"edge.cdn.example": {9, 9, 9, 9}},
		map[string]string{"www.example.com": "edge.cdn.example"}, 300)
	h.up.aliasTTL.Store(120)
	if hdr, ans := h.ask(t, "missing.example", dnsmessage.TypeA); hdr.RCode != dnsmessage.RCodeNameError || len(ans) != 0 {
		t.Fatalf("rcode %v answers %d, want NXDOMAIN", hdr.RCode, len(ans))
	}
	h.ask(t, "www.example.com", dnsmessage.TypeA)
	asked := h.up.asked.Load()
	_, ans := h.ask(t, "www.example.com", dnsmessage.TypeA)
	if h.up.asked.Load() != asked {
		t.Fatal("the second ask was not a cache hit")
	}
	if got := onlyAddrs(t, "www.example.com", ans, 120); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("cache hit %v", got)
	}
}

// A segment without the option does not change. All types go to the
// upstream. An alias comes back as the upstream sent it.
func TestWithoutAddressOnlyNothingChanges(t *testing.T) {
	h := newAliasHarness(t, nil,
		map[string][4]byte{"edge.cdn.example": {9, 9, 9, 9}, "ch.at": {1, 2, 3, 4}},
		map[string]string{"www.example.com": "edge.cdn.example"}, 300)
	h.ask(t, "question.ch.at", dnsmessage.TypeTXT)
	h.ask(t, "ch.at", dnsmessage.TypeMX)
	if n := h.up.asked.Load(); n != 2 {
		t.Fatalf("upstream asked %d times, want 2", n)
	}
	_, ans := h.ask(t, "www.example.com", dnsmessage.TypeA)
	if len(ans) != 2 || ans[0].Header.Type != dnsmessage.TypeCNAME {
		t.Fatalf("the alias did not come back as sent: %+v", ans)
	}
	if strings.Contains(strings.Join(h.srv.Segments(), " "), "a_only") {
		t.Fatalf("-check says a_only: %v", h.srv.Segments())
	}
}

// An edit to dns_types.allow takes effect on Reload. An edit that does not
// load changes nothing.
func TestAddressOnlyAllowReloads(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil, map[string][4]byte{"later.example": {1, 2, 3, 4}}, nil, 300)
	h.ask(t, "later.example", dnsmessage.TypeTXT)
	if n := h.up.asked.Load(); n != 0 {
		t.Fatal("TXT forwarded before it was allowed")
	}
	if err := os.WriteFile(h.allow, []byte("later.example TXT\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	h.ask(t, "later.example", dnsmessage.TypeTXT)
	if n := h.up.asked.Load(); n != 1 {
		t.Fatalf("upstream asked %d times after the reload, want 1", n)
	}
	if got := strings.Join(h.srv.Segments(), " "); !strings.Contains(got, "a_only=1") {
		t.Fatalf("-check: %s", got)
	}
	// The parser skips and reports a line that does not parse. It is not
	// fatal: the reload still occurs, with the good line. The bad line only
	// filters what it would have forwarded.
	var said []string
	h.srv.logf = func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
	if err := os.WriteFile(h.allow, []byte("later.example TEXT\nother.example TXT\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err != nil {
		t.Fatalf("reload with a bad line: %v", err)
	}
	if len(said) != 1 || !strings.Contains(said[0], `"TEXT" is not a record type`) || !strings.Contains(said[0], ":1:") {
		t.Fatalf("said %q", said)
	}
	h.ask(t, "later.example", dnsmessage.TypeTXT)
	rows := h.logLines(t)
	if last := rows[len(rows)-1]; last.Act != dnslog.ActFiltered {
		t.Fatalf("the skipped line still forwarded: %+v", last)
	}
	if got := strings.Join(h.srv.Segments(), " "); !strings.Contains(got, "a_only=1") {
		t.Fatalf("-check after the bad line: %s", got)
	}
}

func TestLoadTypeAllow(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "dns_types.allow")
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ta, err := loadTypeAllow(write("# only comments\n\n  # indented\n"))
	if err != nil || ta.Len() != 0 {
		t.Fatalf("comments only: %v %d", err, ta.Len())
	}
	ta, err = loadTypeAllow(write("x.example txt TYPE10 # and a note\n*.y.example MX\n"))
	if err != nil || ta.Len() != 3 {
		t.Fatalf("%v %d", err, ta.Len())
	}
	if !ta.allows("X.example.", typeNULL) || !ta.allows("a.b.y.example", dnsmessage.TypeMX) || ta.allows("y.example", dnsmessage.TypeMX) {
		t.Fatal("matching")
	}
	for _, bad := range []string{"x.example\n", "x.example TXT TEXT\n", "x.example TYPE70000\n", "* TXT\n", "*. TXT\n"} {
		ta, err := loadTypeAllow(write(bad))
		if err != nil || ta.Len() != 0 || len(ta.bad) != 1 {
			t.Errorf("%q: err %v, %d pairs, bad %q", bad, err, ta.Len(), ta.bad)
		}
	}
	// AAAA, HTTPS and SVCB are answered empty before the list. The line
	// stays, but each of these entries gives a warning and adds no pair.
	ta, err = loadTypeAllow(write("# note\nx.example SRV aaaa TYPE65 SVCB\n"))
	if err != nil || ta.Len() != 1 || len(ta.bad) != 3 {
		t.Fatalf("err %v, %d pairs, bad %q", err, ta.Len(), ta.bad)
	}
	for i, typ := range []string{"AAAA", "HTTPS", "SVCB"} {
		if want := ":2: " + typ + " is always answered empty"; !strings.Contains(ta.bad[i], want) || !strings.HasSuffix(ta.bad[i], "this entry has no effect") {
			t.Errorf("bad[%d] %q, want %q", i, ta.bad[i], want)
		}
	}
	var none *typeAllow
	if none.allows("x.example", dnsmessage.TypeTXT) {
		t.Fatal("a nil table allowed a pair")
	}
}

// A file that is named but missing stops the daemon, as for key_rules. An
// override file for a segment that is not address-only is an error in
// dns.json.
func TestNewRefusesABadTypesAllow(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.conf")
	if err := os.WriteFile(sink, nil, 0644); err != nil {
		t.Fatal(err)
	}
	seg := func(aOnly bool, path string) Config {
		return Config{
			NFTTable: "inet fortress", NFT: &fakeNFT{},
			Segments: []Segment{{
				Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: "127.0.0.1:1", SinkholeFiles: []string{sink},
				NFTSet: "resolved_v4", AddressOnly: aOnly, TypesAllowPath: path,
			}},
		}
	}
	if _, err := New(seg(true, filepath.Join(dir, "missing.allow"))); err == nil || !strings.Contains(err.Error(), "dns types allow") {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := New(seg(false, sink)); err == nil || !strings.Contains(err.Error(), "address_only") {
		t.Fatalf("allow without address_only: %v", err)
	}
	if _, err := New(seg(true, "")); err != nil {
		t.Fatalf("address_only with no overrides: %v", err)
	}
}

func TestParseConfigTakesAddressOnly(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`{"nft_table": "inet fortress", "segments": [
	  {"iface": "eth1", "ip": "10.77.0.1", "upstream": "127.0.0.1:5301", "nft_set": "resolved_v4",
	   "address_only": true, "dns_types_allow": "/etc/pi-fortress/dns_types.allow"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := &cfg.Segments[0]
	if !s.AddressOnly || s.TypesAllowPath != "/etc/pi-fortress/dns_types.allow" {
		t.Fatalf("address_only %v dns_types_allow %q", s.AddressOnly, s.TypesAllowPath)
	}
}

// A client that asked in EDNS gets its answer in EDNS. The OPT is the only
// additional record: the same helpers build the flattened message and each
// local answer.
func TestAddressOnlyAnswersEDNSInEDNS(t *testing.T) {
	h := addrOnlyHarness(t, nil, nil,
		map[string][4]byte{"edge.cdn.example": {9, 9, 9, 9}},
		map[string]string{"www.example.com": "edge.cdn.example"}, 300)
	for _, e := range []bool{true, false} {
		req := wire(t, "www.example.com", dnsmessage.TypeA, 0x4321)
		if e {
			req = withOPT(t, req, 1232, 0, false)
		}
		msg := h.srv.answer(context.Background(), h.srv.segs[0], netip.MustParseAddr("10.77.0.10"), req, 0)
		var m dnsmessage.Message
		if err := m.Unpack(msg); err != nil {
			t.Fatal(err)
		}
		if m.Header.ID != 0x4321 || len(m.Answers) != 1 || len(m.Authorities) != 0 {
			t.Fatalf("edns %v: %+v", e, m)
		}
		opts := 0
		for _, a := range m.Additionals {
			if a.Header.Type != dnsmessage.TypeOPT {
				t.Fatalf("edns %v: additional %v", e, a.Header.Type)
			}
			opts++
		}
		if (opts == 1) != e {
			t.Fatalf("edns %v: %d OPT records", e, opts)
		}
	}
}
