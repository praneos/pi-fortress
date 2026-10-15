//go:build vagrant

package itest

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/dnslog"
)

// fakeIPTests is AGENT_DNS=fakeip end to end: pf dns answers the agent
// from the pool, the broker maps the address back and resolves the name
// itself, and the gate refuses a real address that the agent learned in
// a different way.
//
// fakeip is the default (render AgentDNSFakeIP, since 2026-09-27). A box
// with no AGENT_DNS line runs in it, and the rest of the suite also does.
// A box pinned to AGENT_DNS=forward in net.env.local skips all subtests
// here, and says so. Nothing here changes the mode, for the reason that
// the paranoid arm gives (dns_segments_test.go): a suite that changed it
// and crashed would leave the shared box in it. The forward-mode gate has
// no group of its own.
//
// Hosts: example.com and www.iana.org only (AGENTS.md).
func fakeIPTests(t *testing.T) {
	// The files of the Pi, not of the repo: the mode is the mode that the
	// box was applied with. The overlay wins, as it does for apply.
	last := func(key string) string {
		return strings.TrimSpace(pi(t, "grep -hE '^"+key+"=' /etc/pi-fortress/net.env /etc/pi-fortress/net.env.local 2>/dev/null | tail -1 | cut -d= -f2- | tr -d \"\\\"' \""))
	}
	mode, pool := last("AGENT_DNS"), last("FAKEIP_NET")
	if mode == "" {
		mode = "fakeip"
	}
	if pool == "" {
		pool = "198.18.0.0/16"
	}
	skip := func(t *testing.T) {
		t.Helper()
		if mode != "fakeip" {
			t.Skipf("AGENT_DNS is %q on the Pi, not fakeip; set it in net.env.local and apply to run this", mode)
		}
	}
	prefix, err := netip.ParsePrefix(pool)
	if err != nil {
		t.Fatalf("FAKEIP_NET=%q on the Pi: %v", pool, err)
	}
	piIP := netenv(t)["PI_IP"]
	inPool := func(t *testing.T, name string) string {
		t.Helper()
		ips := digA(t, name, piIP)
		if len(ips) != 1 {
			t.Fatalf("dig %s: %v, want one address", name, ips)
		}
		a, err := netip.ParseAddr(ips[0])
		if err != nil || !prefix.Contains(a) {
			t.Fatalf("dig %s: %s is not in FAKEIP_NET %s", name, ips[0], pool)
		}
		return ips[0]
	}

	t.Run("example.com answers from the pool", func(t *testing.T) {
		skip(t)
		inPool(t, "example.com")
	})
	t.Run("https to example.com through the pool", func(t *testing.T) {
		skip(t)
		inPool(t, "example.com")
		if code := httpCode(t, "https://example.com"); code != "200" {
			t.Fatalf("https://example.com: %q, want 200", code)
		}
	})
	// A name that nobody asked for before also gets an address, without a
	// lookup: that is the purpose. The row says resolved, with the pool
	// address as the answer.
	t.Run("a fresh name answers from the pool and is logged", func(t *testing.T) {
		skip(t)
		name := fmt.Sprintf("pf-fakeip-%d.example.com", time.Now().UnixNano())
		addr := inPool(t, name)
		eventually(t, 10*time.Second, func() string {
			out, _ := ssh(t, 10*time.Second, "pi", "sudo grep -F '\""+name+"\"' /var/log/pi-fortress/dns.jsonl | tail -1")
			ev, ok := dnslog.ParseEvent(strings.TrimSpace(out))
			if !ok {
				return fmt.Sprintf("no dns.jsonl row for %s: %q", name, out)
			}
			if ev.Act != dnslog.ActResolved || ev.Answer != addr {
				return fmt.Sprintf("dns.jsonl row %+v, want resolved %s", ev, addr)
			}
			return ""
		})
	})
	// The broker holds the SNI to the name for which the pool gave the
	// address. It refuses www.iana.org sent to the pool address of example.com.
	t.Run("an SNI that is not the mapped name is refused", func(t *testing.T) {
		skip(t)
		addr := inPool(t, "example.com")
		out, _ := ssh(t, 25*time.Second, "agent", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 --resolve www.iana.org:443:"+addr+" https://www.iana.org/")
		if code := strings.TrimSpace(out); code != "403" {
			t.Fatalf("www.iana.org via example.com's %s: %q, want 403", addr, code)
		}
	})
	// The agent can no longer get a real address in an answer. Thus the
	// gate drops it, whatever resolved_v4 still has from forward mode. The
	// Pi resolves it with its own resolver.
	t.Run("example.com's real address is dropped at the gate", func(t *testing.T) {
		skip(t)
		origin := firstIPv4(pi(t, "dig +short +time=3 +tries=2 A example.com"))
		if origin == "" {
			t.Fatal("no address for example.com from the Pi's resolver")
		}
		since := piClock(t)
		mustFailOn(t, "agent", "curl -sS --noproxy '*' -o /dev/null --max-time 5 --resolve example.com:443:"+origin+" https://example.com/")
		kernLog(t, since, "pi-fortress agent-directip: ", "DST="+origin+" ")
	})
}
