package dnsd

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/dnslog"
)

// paranoidHarness is newAliasHarness with a forward set. Paranoid mode
// decides only by the forward set.
func paranoidHarness(t *testing.T, allow, core []string, table map[string][4]byte) *harness {
	t.Helper()
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sinkPath, []byte("address=/ads.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	allowPath := filepath.Join(dir, "allow.domains")
	if err := os.WriteFile(allowPath, []byte(strings.Join(allow, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	corePath := filepath.Join(dir, "core.hosts")
	if err := os.WriteFile(corePath, []byte(strings.Join(core, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, table, nil, 300)
	nft := &fakeNFT{}
	logPath := filepath.Join(dir, "dns.jsonl")
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   0,
		NFT:      nft,
		Now:      func() time.Time { return now },
		Segments: []Segment{{
			Iface:         "lo",
			IP:            netip.MustParseAddr("127.0.0.1"),
			Upstream:      up.addr(),
			SinkholeFiles: []string{sinkPath},
			NFTSet:        "resolved_v4",
			LogPath:       logPath,
			Paranoid:      true,
			AllowPath:     allowPath,
			CorePath:      corePath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	h := &harness{srv: srv, nft: nft, up: up, log: logPath, now: func() time.Time { return now }}
	h.allow = allowPath
	return h
}

func onlyA(t *testing.T, ans []dnsmessage.Resource) string {
	t.Helper()
	if len(ans) != 1 {
		t.Fatalf("want one answer, got %d", len(ans))
	}
	a, ok := ans[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer is %T, not an A record", ans[0].Body)
	}
	return netip.AddrFrom4(a.A).String()
}

// All of paranoid mode: a name that policy names resolves. A name that
// policy does not name gets the sinkhole address and is not forwarded.
func TestParanoidResolvesOnlyTheForwardSet(t *testing.T) {
	h := paranoidHarness(t,
		[]string{"listed.test"},
		[]string{"core.test"},
		map[string][4]byte{
			"listed.test":     {1, 2, 3, 4},
			"sub.listed.test": {1, 2, 3, 5},
			"core.test":       {5, 6, 7, 8},
			"evil.core.test":  {6, 6, 6, 6},
			"random.test":     {9, 9, 9, 9},
		})

	for _, tc := range []struct {
		name string
		want string
		why  string
	}{
		{"listed.test", "1.2.3.4", "an allow.domains name resolves"},
		{"sub.listed.test", "1.2.3.5", "allow.domains carries its subdomains"},
		{"core.test", "5.6.7.8", "a core.hosts name resolves"},
		{"random.test", "0.0.0.0", "an unlisted name is sinkholed, not forwarded"},
		// K9: the dnsmasq conf spelled each forward name server=/name/#.
		// That also carried the subdomains of exact core.hosts entries. Thus
		// the exact core name opened every name under it. The oracle that the
		// fence uses to decide does not do this. Now the resolver also does not.
		{"evil.core.test", "0.0.0.0", "a core.hosts entry is exact unless written *.name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ans := h.ask(t, tc.name, dnsmessage.TypeA)
			if got := onlyA(t, ans); got != tc.want {
				t.Fatalf("%s = %s, want %s (%s)", tc.name, got, tc.want, tc.why)
			}
		})
	}
}

// A refused name is logged as blocked. It never reaches the upstream or
// the gate set. The log word is the contract. observe uses it to tell
// blocked from resolved. A refusal with a different log word would count
// as traffic that was allowed out. A query upstream before the sinkhole
// would leak the interest of the agent to the resolver operator. An
// address in resolved_v4 is a hole in the 443 gate.
func TestParanoidRefusalIsBlockedUnaskedAndUngated(t *testing.T) {
	h := paranoidHarness(t,
		[]string{"listed.test"},
		[]string{"core.test"},
		map[string][4]byte{"listed.test": {1, 2, 3, 4}, "random.test": {9, 9, 9, 9}})
	before := h.up.asked.Load()
	h.ask(t, "random.test", dnsmessage.TypeA)
	if n := h.up.asked.Load(); n != before {
		t.Fatalf("upstream asked %d times for a refused name, want %d", n, before)
	}
	h.nft.mu.Lock()
	for _, batch := range h.nft.adds {
		for _, a := range batch {
			if a.String() == "9.9.9.9" {
				t.Errorf("a refused name put %s in the gate set", a)
			}
		}
	}
	h.nft.mu.Unlock()

	var saw bool
	for _, r := range h.logLines(t) {
		if r.Name != "random.test" || r.Answer == "" {
			continue
		}
		saw = true
		if r.Act != dnslog.ActBlocked {
			t.Fatalf("random.test logged as %q, not blocked: %+v", r.Act, r)
		}
		if r.Answer != "0.0.0.0" {
			t.Fatalf("random.test answered %q, want 0.0.0.0", r.Answer)
		}
	}
	if !saw {
		t.Fatal("no answer line for random.test in the query log")
	}
}

// Paranoid is a posture that the operator changes while the daemon runs.
// SIGHUP applies the change. A name added to allow.domains must resolve
// after a reload. A name removed from it must stop. This includes the
// cache that answered it a moment before.
func TestParanoidForwardSetReloads(t *testing.T) {
	h := paranoidHarness(t,
		[]string{"listed.test"},
		[]string{"core.test"},
		map[string][4]byte{"listed.test": {1, 2, 3, 4}, "later.test": {7, 7, 7, 7}})

	if _, ans := h.ask(t, "later.test", dnsmessage.TypeA); onlyA(t, ans) != "0.0.0.0" {
		t.Fatal("later.test resolved before it was listed")
	}
	if _, ans := h.ask(t, "listed.test", dnsmessage.TypeA); onlyA(t, ans) != "1.2.3.4" {
		t.Fatal("listed.test did not resolve")
	}

	if err := os.WriteFile(h.allow, []byte("later.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, ans := h.ask(t, "later.test", dnsmessage.TypeA); onlyA(t, ans) != "7.7.7.7" {
		t.Fatal("later.test did not resolve after it was listed and reloaded")
	}
	// The test answered and cached listed.test above. A removal from the
	// list must also remove the cached answer.
	if _, ans := h.ask(t, "listed.test", dnsmessage.TypeA); onlyA(t, ans) != "0.0.0.0" {
		t.Fatal("listed.test still resolved from cache after it left the forward set")
	}
}

// A reload that cannot read the forward set must change nothing. The
// sinkhole list makes the same bargain. If a daemon half-applied a reload,
// it would answer by a policy that the operator was told failed to load.
func TestParanoidReloadFailureChangesNothing(t *testing.T) {
	h := paranoidHarness(t,
		[]string{"listed.test"},
		[]string{"core.test"},
		map[string][4]byte{"listed.test": {1, 2, 3, 4}})
	if err := os.Remove(h.allow); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Reload(); err == nil {
		t.Fatal("reload accepted a missing allow.domains")
	}
	if _, ans := h.ask(t, "listed.test", dnsmessage.TypeA); onlyA(t, ans) != "1.2.3.4" {
		t.Fatal("the failed reload took the forward set away")
	}
}

// Paranoid without a forward set would sinkhole everything. That looks
// like a working segment with an empty internet, not like a mistake.
func TestParanoidWithoutAForwardSetIsRefused(t *testing.T) {
	_, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   0,
		NFT:      &fakeNFT{},
		Segments: []Segment{{
			Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"),
			Upstream: "127.0.0.1:5353", NFTSet: "resolved_v4", Paranoid: true,
		}},
	})
	if err == nil {
		t.Fatal("paranoid with no allow list was accepted")
	}
	if !strings.Contains(err.Error(), "paranoid") {
		t.Fatalf("error does not name the mode: %v", err)
	}
}

// The resolver decides the echo fixtures before any list
// (docs/paranoid_mode.md K11). It resolves pf-core-echo.test only inside
// the lab (LabEcho). Elsewhere it sinkholes that name. A resolver that
// forwarded it on a real Pi would open a
// fixture that the fence refuses.
func TestParanoidEchoFixtures(t *testing.T) {
	table := map[string][4]byte{
		corepolicy.OpenEcho: {1, 1, 1, 1},
		corepolicy.CoreEcho: {2, 2, 2, 2},
	}
	t.Run("open echo resolves anywhere", func(t *testing.T) {
		h := paranoidHarness(t, []string{"listed.test"}, []string{"core.test"}, table)
		if _, ans := h.ask(t, corepolicy.OpenEcho, dnsmessage.TypeA); onlyA(t, ans) != "1.1.1.1" {
			t.Fatal("the open echo fixture was sinkholed")
		}
	})
	t.Run("core echo needs the lab", func(t *testing.T) {
		h := paranoidHarness(t, []string{"listed.test"}, []string{"core.test"}, table)
		if _, ans := h.ask(t, corepolicy.CoreEcho, dnsmessage.TypeA); onlyA(t, ans) != "0.0.0.0" {
			t.Fatal("the core echo fixture resolved without -lab-echo")
		}
		h.srv.segs[0].LabEcho = true
		if _, ans := h.ask(t, corepolicy.CoreEcho, dnsmessage.TypeA); onlyA(t, ans) != "2.2.2.2" {
			t.Fatal("the core echo fixture did not resolve with -lab-echo")
		}
	})
}

// The blocklist still wins. A name on both lists is blocked, not
// forwarded. If not, a name added to allow.domains would quietly undo the
// feeds (corepolicy: "Blocklists run before this and still win").
func TestParanoidDoesNotOverrideTheBlocklist(t *testing.T) {
	h := paranoidHarness(t,
		[]string{"ads.test"},
		[]string{"core.test"},
		map[string][4]byte{"ads.test": {4, 4, 4, 4}})
	_, ans := h.ask(t, "ads.test", dnsmessage.TypeA)
	if got := onlyA(t, ans); got != "0.0.0.0" {
		t.Fatalf("ads.test = %s: the allow list overrode the blocklist", got)
	}
	for _, r := range h.logLines(t) {
		if r.Name == "ads.test" && r.Answer != "" && r.Act != dnslog.ActBlocked {
			t.Fatalf("ads.test logged as %q, not blocked: %+v", r.Act, r)
		}
	}
}
