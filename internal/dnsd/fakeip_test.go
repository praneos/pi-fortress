package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
)

var testPool = netip.MustParsePrefix("198.18.0.0/16")

// fakeOpts is what a fake-IP test changes. All else is the agent
// segment as apply writes it.
type fakeOpts struct {
	sinkholed  []string
	typesAllow []string
	paranoid   []string // allow.domains; nil is not paranoid
	journal    string   // "" is a fresh one in a temp dir
}

// fakeHarness is the agent segment under AGENT_DNS=fakeip. The harness
// builds it through New, so the tests pass the checks that New makes:
// address-only, the sinkhole with the open echo fixture,
// dns_types.allow, and a pool.
func fakeHarness(t *testing.T, o fakeOpts, table map[string][4]byte) *harness {
	t.Helper()
	dir := t.TempDir()
	lines := []string{"address=/pf-open-echo.test/192.0.2.3"}
	for _, n := range o.sinkholed {
		lines = append(lines, "address=/"+n+"/0.0.0.0")
	}
	write := func(name string, body []string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strings.Join(body, "\n")+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	segs := []Segment{{
		Iface:          "lo",
		IP:             netip.MustParseAddr("127.0.0.1"),
		SinkholeFiles:  []string{write("blocked-domains.conf", lines)},
		NFTSet:         "resolved_v4",
		LogPath:        filepath.Join(dir, "dns.jsonl"),
		AddressOnly:    true,
		TypesAllowPath: write("dns_types.allow", o.typesAllow),
		FakeIPNet:      testPool,
		FakeIPJournal:  o.journal,
	}}
	seg := &segs[0]
	if seg.FakeIPJournal == "" {
		seg.FakeIPJournal = filepath.Join(t.TempDir(), "fakeip.journal")
	}
	if o.paranoid != nil {
		seg.Paranoid = true
		seg.AllowPath = write("allow.domains", o.paranoid)
		seg.CorePath = write("core.hosts", nil)
	}
	up := newUpstream(t, table, nil, 300)
	seg.Upstream = up.addr()
	nft := &fakeNFT{}
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		NFT:      nft,
		Now:      func() time.Time { return now },
		Segments: segs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	t.Cleanup(srv.closeFake)
	return &harness{srv: srv, nft: nft, up: up, log: seg.LogPath, now: func() time.Time { return now }}
}

// fakeA asks name A and returns the one address from the pool. It fails
// unless the answer is exactly one A record in the pool at fakeTTL.
func (h *harness) fakeA(t *testing.T, name string) netip.Addr {
	t.Helper()
	hdr, ans := h.ask(t, name, dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("%s: rcode %v", name, hdr.RCode)
	}
	got := onlyAddrs(t, name, ans, fakeTTL)
	if len(got) != 1 {
		t.Fatalf("%s: %d addresses, want one", name, len(got))
	}
	a := netip.MustParseAddr(got[0])
	if !testPool.Contains(a) {
		t.Fatalf("%s: %s is not a pool address", name, a)
	}
	return a
}

// The pool answers an A query, with the same address each time, and
// nothing leaves: the upstream gets no query, nothing writes the gate
// set, and the row says resolved with the pool address.
func TestFakeIPAnswersFromThePool(t *testing.T) {
	h := fakeHarness(t, fakeOpts{}, map[string][4]byte{"example.com": {93, 184, 216, 34}})
	a := h.fakeA(t, "example.com")
	if b := h.fakeA(t, "Example.COM"); b != a {
		t.Fatalf("same name, two addresses: %s then %s", a, b)
	}
	c := h.fakeA(t, "www.iana.org")
	if c == a {
		t.Fatalf("two names share %s", a)
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
	if n := h.nft.calls.Load(); n != 0 {
		t.Fatalf("resolved_v4 written %d times: %v", n, h.nft.flat())
	}
	rows := h.logLines(t)
	if len(rows) != 3 {
		t.Fatalf("rows %+v", rows)
	}
	if r := rows[0]; r.Act != dnslog.ActResolved || r.Answer != a.String() || r.Name != "example.com" {
		t.Fatalf("row %+v, want resolved %s", r, a)
	}
	raw, err := os.ReadFile(h.srv.segs[0].FakeIPJournal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), a.String()+" example.com\n") {
		t.Fatalf("journal lacks the mapping:\n%s", raw)
	}
}

// The sinkhole and the fixtures answer as before. A listed name gets
// 0.0.0.0 and never takes a pool address. The echo fixture keeps its
// real address and still opens the gate for it.
func TestFakeIPKeepsTheListAndTheFixtures(t *testing.T) {
	h := fakeHarness(t, fakeOpts{sinkholed: []string{"ads.test"}}, nil)
	if _, ans := h.ask(t, "tracker.ads.test", dnsmessage.TypeA); firstA(t, ans) != "0.0.0.0" {
		t.Fatalf("listed: %+v", ans)
	}
	if _, ans := h.ask(t, "pf-open-echo.test", dnsmessage.TypeA); firstA(t, ans) != "192.0.2.3" {
		t.Fatalf("fixture: %+v", ans)
	}
	if got := h.nft.flat(); len(got) != 1 || got[0] != "192.0.2.3" {
		t.Fatalf("set writes %v, want the fixture's alone", got)
	}
	rows := h.logLines(t)
	if len(rows) != 2 || rows[0].Act != dnslog.ActBlocked || rows[1].Act != dnslog.ActResolved {
		t.Fatalf("rows %+v", rows)
	}
	raw, _ := os.ReadFile(h.srv.segs[0].FakeIPJournal)
	if len(raw) != 0 {
		t.Fatalf("a listed or fixture name was journalled:\n%s", raw)
	}
}

// Paranoid still sinkholes the names that it does not forward, before
// the pool. The names that it forwards get a pool address, not a lookup.
func TestFakeIPParanoidStillSinkholes(t *testing.T) {
	h := fakeHarness(t, fakeOpts{paranoid: []string{"allowed.example"}}, map[string][4]byte{"other.example": {1, 2, 3, 4}})
	if _, ans := h.ask(t, "other.example", dnsmessage.TypeA); firstA(t, ans) != "0.0.0.0" {
		t.Fatalf("outside the forward set: %+v", ans)
	}
	h.fakeA(t, "allowed.example")
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
}

// The address-only filter is still before the pool. TXT gets an empty
// answer here, and a dns_types.allow pair still goes upstream.
func TestFakeIPKeepsTheTypeFilter(t *testing.T) {
	h := fakeHarness(t, fakeOpts{typesAllow: []string{"exact.example TXT"}}, map[string][4]byte{"exact.example": {1, 1, 1, 1}})
	hdr, ans := h.ask(t, "what-is-the-key.ch.at", dnsmessage.TypeTXT)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("TXT: rcode %v answers %d", hdr.RCode, len(ans))
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("filtered TXT went upstream")
	}
	h.ask(t, "exact.example", dnsmessage.TypeTXT)
	if n := h.up.asked.Load(); n != 1 {
		t.Fatalf("allowed pair: upstream asked %d times, want 1", n)
	}
	rows := h.logLines(t)
	if rows[0].Act != dnslog.ActFiltered {
		t.Fatalf("row %+v", rows[0])
	}
}

// The key-shape refusal is still the first thing a query meets: a key in
// the name never reaches the journal the broker reads.
func TestFakeIPKeyShapeIsStillFirst(t *testing.T) {
	h := fakeHarness(t, fakeOpts{}, nil)
	h.srv.segs[0].keys.Store(mustKeyShapes(t))
	key := "sk-ant-oat01-" + strings.Repeat("A", 40)
	hdr, ans := h.ask(t, key+".evil.example", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeRefused || len(ans) != 0 {
		t.Fatalf("rcode %v answers %d", hdr.RCode, len(ans))
	}
	raw, _ := os.ReadFile(h.srv.segs[0].FakeIPJournal)
	if len(raw) != 0 {
		t.Fatalf("journalled:\n%s", raw)
	}
	if rows := h.logLines(t); len(rows) != 1 || rows[0].Act != dnslog.ActRefused {
		t.Fatalf("rows %+v", rows)
	}
}

// A restart keeps the mapping. An agent that still has an answer from
// before the restart must find the same name behind the same address.
func TestFakeIPJournalSurvivesARestart(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "fakeip.journal")
	h1 := fakeHarness(t, fakeOpts{journal: journal}, nil)
	a := h1.fakeA(t, "example.com")
	h1.srv.closeFake()
	h2 := fakeHarness(t, fakeOpts{journal: journal}, nil)
	if b := h2.fakeA(t, "example.com"); b != a {
		t.Fatalf("after a restart example.com is %s, was %s", b, a)
	}
	if c := h2.fakeA(t, "www.iana.org"); c == a {
		t.Fatalf("a new name took the old name's %s", a)
	}
	st, err := os.Stat(journal)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("journal mode %v, want 0640 so only the broker's group reads it", st.Mode().Perm())
	}
}

// -check is New plus Segments. Neither may create the journal: apply
// runs the check as root, and pf dns cannot append to a journal that
// root owns.
func TestFakeIPCheckCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"nft_table": "inet fortress", "segments": [{"iface": "lo", "ip": "127.0.0.1", "upstream": "127.0.0.1:53",
		"nft_set": "resolved_v4", "address_only": true, "fakeip_net": "198.18.0.0/16", "fakeip_journal": "` + filepath.Join(dir, "fakeip.journal") + `"}]}`
	c, err := ParseConfig(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if lines := srv.Segments(); len(lines) != 1 || !strings.Contains(lines[0], " fakeip=198.18.0.0/16") {
		t.Fatalf("-check lines %q", lines)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("-check created %v", ents)
	}
	// Run opens it, before the first query.
	if err := srv.openFake(); err != nil {
		t.Fatal(err)
	}
	srv.closeFake()
	if _, err := os.Stat(filepath.Join(dir, "fakeip.journal")); err != nil {
		t.Fatalf("openFake: %v", err)
	}
}

// A pool that cannot assign costs the client its answer: a SERVFAIL and
// a row, never a forward. A name that the journal cannot carry is no
// name.
func TestFakeIPPoolFailureIsServfail(t *testing.T) {
	h := fakeHarness(t, fakeOpts{}, map[string][4]byte{"example.com": {93, 184, 216, 34}})
	var logged []string
	h.srv.logf = func(f string, a ...any) { logged = append(logged, f) }
	if hdr, _ := h.ask(t, "has space.example", dnsmessage.TypeA); hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unjournalable name: rcode %v", hdr.RCode)
	}
	h.srv.closeFake()
	for i := 0; i < 3; i++ {
		if hdr, ans := h.ask(t, "example.com", dnsmessage.TypeA); hdr.RCode != dnsmessage.RCodeServerFailure || len(ans) != 0 {
			t.Fatalf("closed pool: rcode %v answers %d", hdr.RCode, len(ans))
		}
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("a failed pool forwarded: upstream asked %d times", n)
	}
	if len(logged) != 1 {
		t.Fatalf("pool failure logged %d times in a minute, want once: %q", len(logged), logged)
	}
	rows := h.logLines(t)
	if len(rows) != 4 || rows[0].Act != dnslog.ActNXDomain || rows[3].Act != dnslog.ActServfail {
		t.Fatalf("rows %+v", rows)
	}
}

func TestNewRefusesABadFakeIP(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "fakeip.journal")
	base := func() []Segment {
		return []Segment{{
			Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: "127.0.0.1:53",
			NFTSet: "resolved_v4", AddressOnly: true, FakeIPNet: testPool, FakeIPJournal: journal,
		}}
	}
	for _, tc := range []struct {
		what string
		edit func(*Segment)
		want string
	}{
		{"no journal", func(s *Segment) { s.FakeIPJournal = "" }, "go together"},
		{"no net", func(s *Segment) { s.FakeIPNet = netip.Prefix{} }, "go together"},
		{"not address-only", func(s *Segment) { s.AddressOnly = false }, "without address_only"},
		{"a /25", func(s *Segment) { s.FakeIPNet = netip.MustParsePrefix("198.18.0.0/25") }, "fakeip_net"},
		{"v6", func(s *Segment) { s.FakeIPNet = netip.MustParsePrefix("fd00::/64") }, "fakeip_net"},
		{"relative", func(s *Segment) { s.FakeIPJournal = "fakeip.journal" }, "absolute"},
		{"no directory", func(s *Segment) { s.FakeIPJournal = filepath.Join(dir, "gone", "fakeip.journal") }, "directory"},
		{"journal is a directory", func(s *Segment) { s.FakeIPJournal = dir }, "regular file"},
	} {
		segs := base()
		tc.edit(&segs[0])
		_, err := New(Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, Segments: segs})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.what, err, tc.want)
		}
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		segs := base()
		segs[0].FakeIPJournal = filepath.Join(ro, "fakeip.journal")
		if _, err := New(Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, Segments: segs}); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Errorf("read-only directory: err %v", err)
		}
	}
	if _, err := New(Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, Segments: base()}); err != nil {
		t.Fatalf("a good pair: %v", err)
	}
}

func TestParseConfigTakesFakeIP(t *testing.T) {
	wrap := func(extra string) string {
		return `{"nft_table": "inet fortress", "segments": [{"iface": "lo", "ip": "127.0.0.1", "upstream": "127.0.0.1:53", "nft_set": "resolved_v4"` + extra + `}]}`
	}
	c, err := ParseConfig(strings.NewReader(wrap(`, "fakeip_net": "198.18.0.0/16", "fakeip_journal": "/var/lib/pi-fortress/dns/fakeip.journal"`)))
	if err != nil {
		t.Fatal(err)
	}
	if s := &c.Segments[0]; s.FakeIPNet != testPool || s.FakeIPJournal != "/var/lib/pi-fortress/dns/fakeip.journal" {
		t.Fatalf("fakeip_net %s fakeip_journal %q", s.FakeIPNet, s.FakeIPJournal)
	}
	for _, bad := range []string{`, "fakeip_net": "198.18.0.1/16"`, `, "fakeip_net": "nope"`, `, "fakeip-net": "198.18.0.0/16"`} {
		if _, err := ParseConfig(strings.NewReader(wrap(bad))); err == nil {
			t.Errorf("%s: taken", bad)
		}
	}
}

// A name that is an address is not a name that the broker can map back
// to anything but that address. With a pool address for 203.0.114.9,
// the broker dials the literal, and the direct-IP rule never sees it.
// The resolver refuses it before the pool and writes nothing to the
// journal. The row says so.
func TestFakeIPRefusesAnAddressAsAName(t *testing.T) {
	h := fakeHarness(t, fakeOpts{}, nil)
	for _, name := range []string{"203.0.114.9", "10.77.0.1", "127.1", "0x7f.1", "::1"} {
		hdr, ans := h.ask(t, name, dnsmessage.TypeA)
		if hdr.RCode != dnsmessage.RCodeNameError || len(ans) != 0 {
			t.Fatalf("%s: rcode %v answers %v, want NXDOMAIN and nothing", name, hdr.RCode, ans)
		}
	}
	if raw, err := os.ReadFile(h.srv.segs[0].FakeIPJournal); err == nil && strings.TrimSpace(string(raw)) != "" {
		t.Fatalf("journal took an address as a name:\n%s", raw)
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
	rows := h.logLines(t)
	if len(rows) != 5 || rows[0].Name != "203.0.114.9" || rows[0].Act != dnslog.ActNXDomain {
		t.Fatalf("rows %+v", rows)
	}
	if a := h.fakeA(t, "203.0.114.9.nip.example"); !a.IsValid() {
		t.Fatal("a real name with an address in it lost its pool address")
	}
}
