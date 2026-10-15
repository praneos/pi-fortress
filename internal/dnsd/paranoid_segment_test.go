package dnsd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/dnslog"
)

// segmentParanoidHarness is a paranoid plain segment as apply.sh writes
// one into dns.json: a name, its own set and log, "paranoid", its own
// allow file, and no core_hosts. It goes through ParseConfig. Thus the
// test examines the wire shape, not a hand-built Segment.
func segmentParanoidHarness(t *testing.T, allow string, table map[string][4]byte) *harness {
	t.Helper()
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sinkPath, []byte("address=/ads.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	allowPath := filepath.Join(dir, "allow.desk.domains")
	if err := os.WriteFile(allowPath, []byte(allow), 0644); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, table, nil, 300)
	logPath := filepath.Join(dir, "dns-desk.jsonl")
	raw := fmt.Sprintf(`{"listen": 0, "nft_table": "inet fortress", "segments": [
  {"name": "desk", "iface": "lo", "ip": "127.0.0.1", "upstream": %q, "sinkhole": [%q], "nft_set": "resolved_desk_v4", "log": %q, "paranoid": true, "allow": %q}
]}`, up.addr(), sinkPath, logPath, allowPath)
	cfg, err := ParseConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	nft := &fakeNFT{}
	now := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	cfg.NFT = nft
	cfg.Now = func() time.Time { return now }
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.OpenLogs(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.CloseLogs)
	return &harness{srv: srv, nft: nft, up: up, log: logPath, allow: allowPath, now: func() time.Time { return now }}
}

// A paranoid desk answers the names in its own allow file. It gives every
// other name the blocklist answer. It logs that name as blocked, never
// asks upstream for it, and never puts it in the gate set of the desk.
func TestParanoidSegmentResolvesOnlyItsAllowFile(t *testing.T) {
	h := segmentParanoidHarness(t, "listed.test\n", map[string][4]byte{
		"listed.test":         {1, 2, 3, 4},
		"sub.listed.test":     {1, 2, 3, 5},
		"random.test":         {9, 9, 9, 9},
		corepolicy.OpenEcho:   {7, 7, 7, 7},
		"ads.test":            {4, 4, 4, 4},
		"listed.test.evil.io": {6, 6, 6, 6},
	})
	for _, tc := range []struct{ name, want, why string }{
		{"listed.test", "1.2.3.4", "a listed name resolves"},
		{"sub.listed.test", "1.2.3.5", "a listed name carries its subdomains, as in allow.domains"},
		{"random.test", "0.0.0.0", "an unlisted name gets the blocked answer"},
		{"listed.test.evil.io", "0.0.0.0", "a listed name as a prefix is not a match"},
		{corepolicy.OpenEcho, "0.0.0.0", "the agent's echo fixture is not a segment's"},
		{"ads.test", "0.0.0.0", "the blocklist still answers first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.up.asked.Load()
			_, ans := h.ask(t, tc.name, dnsmessage.TypeA)
			if got := onlyA(t, ans); got != tc.want {
				t.Fatalf("%s = %s, want %s (%s)", tc.name, got, tc.want, tc.why)
			}
			if tc.want == "0.0.0.0" && h.up.asked.Load() != before {
				t.Fatalf("%s was asked upstream", tc.name)
			}
		})
	}
	h.nft.mu.Lock()
	sets := append([]string(nil), h.nft.sets...)
	h.nft.mu.Unlock()
	if len(sets) == 0 {
		t.Error("no allowed answer reached the desk's gate set")
	}
	for _, s := range sets {
		if s != "resolved_desk_v4" {
			t.Errorf("an answer fed %s, not the desk's own set", s)
		}
	}
	for _, a := range h.nft.flat() {
		if a == "9.9.9.9" || a == "7.7.7.7" {
			t.Errorf("a refused name put %s in the gate set", a)
		}
	}
	var saw bool
	for _, r := range h.logLines(t) {
		if r.Name == "random.test" && r.Answer != "" {
			saw = true
			if r.Act != dnslog.ActBlocked {
				t.Fatalf("random.test logged %q, want blocked", r.Act)
			}
		}
	}
	if !saw {
		t.Fatal("no answer line for random.test")
	}
	if line := strings.Join(h.srv.Segments(), "\n"); !strings.Contains(line, "desk ") || !strings.Contains(line, " paranoid=1") {
		t.Fatalf("-check does not show the desk armed: %s", line)
	}
}

// A paranoid desk without its file does not start. This refuses a
// failure: an empty internet that looks like a working segment.
func TestParanoidSegmentWithoutItsFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	raw := fmt.Sprintf(`{"listen": 0, "nft_table": "inet fortress", "segments": [
  {"name": "desk", "iface": "lo", "ip": "127.0.0.1", "upstream": "127.0.0.1:5353", "nft_set": "resolved_desk_v4", "paranoid": true, "allow": %q}
]}`, filepath.Join(dir, "allow.desk.domains"))
	cfg, err := ParseConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	cfg.NFT = &fakeNFT{}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "allow.desk.domains") {
		t.Fatalf("a paranoid desk with no allow file: %v", err)
	}
}

// apply copies a seed for a segment that has no allowlist yet. This seed
// lets Claude Code work on a paranoid desk. The Anthropic API and the
// claude.ai and claude.com hosts answer. All other names are refused.
func TestParanoidSegmentWithTheShippedSeed(t *testing.T) {
	seed, err := os.ReadFile("../../vm/pi/allow.segment.domains.example")
	if err != nil {
		t.Fatal(err)
	}
	h := segmentParanoidHarness(t, string(seed), map[string][4]byte{
		"api.anthropic.com":  {160, 79, 104, 10},
		"claude.ai":          {160, 79, 104, 11},
		"statsig.claude.com": {160, 79, 104, 12},
		"example.com":        {93, 184, 215, 14},
	})
	for _, tc := range []struct{ name, want string }{
		{"api.anthropic.com", "160.79.104.10"},
		{"claude.ai", "160.79.104.11"},
		{"statsig.claude.com", "160.79.104.12"},
		{"example.com", "0.0.0.0"},
	} {
		if _, ans := h.ask(t, tc.name, dnsmessage.TypeA); onlyA(t, ans) != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, onlyA(t, ans), tc.want)
		}
	}
}
