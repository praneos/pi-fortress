//go:build vagrant

package itest

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	eyeTable  = "/etc/pi-fortress/eyeball.table"
	eyeBackup = "/var/lib/pi-fortress/eyeball.table.itest"
	eyeEnv    = "/etc/pi-fortress/net.env.local"
	eyeEnvBak = "/var/lib/pi-fortress/net.env.local.itest"
	// eyeASN is a documentation ASN (RFC 5398). No feed has it, so a row
	// with it comes from the table of this test.
	eyeASN = "64496"
)

// eyeballTests put the /16 of each address of example.com in the eyeball
// table of the gateway, for the length of the group. The broker reloads
// the table each minute when it changes. In audit mode the agent gets
// example.com and the strip log gets an audit row. In refuse mode the
// agent gets no connection and the row says resolve. The cleanup puts the
// table and net.env.local back, and applies. The backups stay under
// /var/lib until the restore is done, as in deskInspectTests.
func eyeballTests(t *testing.T) {
	if strings.TrimSpace(pi(t, "sudo test -s "+eyeTable+" && echo yes || echo no")) != "yes" {
		t.Skip("no eyeball table on this gateway")
	}
	origin := pi(t, "dig +short +time=3 +tries=2 A example.com")
	table := eyeTableFor(t, origin)
	pi(t, "sudo sh -c "+shellQuote("set -e; [ -e "+eyeBackup+" ] || cp -p "+eyeTable+" "+eyeBackup))
	t.Cleanup(func() { eyeRestore(t) })

	write := func(t *testing.T) {
		t.Helper()
		pi(t, "printf %s "+shellQuote(table)+" | sudo tee "+eyeTable+" >/dev/null")
	}
	// rows counts the eyeball rows of this test's ASN with that where.
	// The test wants the count to grow, so a row of an earlier run does
	// not pass it.
	rows := func(t *testing.T, where string) int {
		t.Helper()
		out, _ := ssh(t, 10*time.Second, "pi", "sudo grep -F eyeball_network /var/log/pi-fortress/strip.jsonl | grep -F '\"where\":\""+where+"\"' | grep -F '\"host\":\"example.com\"' | grep -cF AS"+eyeASN)
		n, _ := strconv.Atoi(strings.TrimSpace(out))
		return n
	}

	t.Run("audit mode dials and writes an audit row", func(t *testing.T) {
		before := rows(t, "audit")
		write(t)
		eventuallyEvery(t, 100*time.Second, 5*time.Second, func() string {
			if code := httpCode(t, "https://example.com"); code != "200" {
				return "https://example.com: " + code + ", want 200 in audit mode"
			}
			if rows(t, "audit") == before {
				return "no new audit eyeball_network row for example.com"
			}
			return ""
		})
	})
	t.Run("refuse mode gives the agent no connection", func(t *testing.T) {
		pi(t, "sudo sh -c "+shellQuote("set -e; [ -e "+eyeEnvBak+" ] || { [ -e "+eyeEnv+" ] && cp -p "+eyeEnv+" "+eyeEnvBak+" || : > "+eyeEnvBak+"; }; grep -v '^EYEBALL=' "+eyeEnvBak+" > "+eyeEnv+"; echo EYEBALL=refuse >> "+eyeEnv))
		if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
			t.Fatalf("pf apply --local with EYEBALL=refuse: %v\n%s", err, out)
		}
		before := rows(t, "resolve")
		write(t)
		eventuallyEvery(t, 100*time.Second, 5*time.Second, func() string {
			if code := httpCode(t, "https://example.com"); code == "200" {
				return "https://example.com: 200, want no connection in refuse mode"
			}
			if rows(t, "resolve") == before {
				return "no new resolve eyeball_network row for example.com"
			}
			return ""
		})
	})
}

// eyeTableFor gives a table with the /16 of each address in dig, sorted
// and without repeats.
func eyeTableFor(t *testing.T, dig string) string {
	t.Helper()
	seen := map[netip.Prefix]bool{}
	var nets []netip.Prefix
	for _, f := range strings.Fields(dig) {
		a, err := netip.ParseAddr(f)
		if err != nil || !a.Is4() {
			continue
		}
		p := netip.PrefixFrom(a, 16).Masked()
		if !seen[p] {
			seen[p] = true
			nets = append(nets, p)
		}
	}
	if len(nets) == 0 {
		t.Fatalf("no IPv4 address for example.com from the gateway: %q", dig)
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].Addr().Less(nets[j].Addr()) })
	var b strings.Builder
	fmt.Fprintf(&b, "# pf eyeball v1\n# built %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, p := range nets {
		a := p.Addr().As4()
		fmt.Fprintf(&b, "%s %d.%d.255.255 %s\n", p.Addr(), a[0], a[1], eyeASN)
	}
	return b.String()
}

// eyeRestore puts back net.env.local and the table, and applies. Apply
// installs the table of pf fetch again, so the table goes back last.
func eyeRestore(t *testing.T) {
	steps := "set -e; if [ -e " + eyeEnvBak + " ]; then if [ -s " + eyeEnvBak + " ]; then cp -p " + eyeEnvBak + " " + eyeEnv + "; else rm -f " + eyeEnv + "; fi; rm -f " + eyeEnvBak + "; fi"
	if out, err := ssh(t, 30*time.Second, "pi", "sudo sh -c "+shellQuote(steps)); err != nil {
		t.Errorf("restore net.env.local: %v\n%s", err, out)
	}
	if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
		t.Errorf("pf apply --local after the eyeball restore: %v\n%s", err, out)
	}
	steps = "set -e; if [ -e " + eyeBackup + " ]; then cp -p " + eyeBackup + " " + eyeTable + "; rm -f " + eyeBackup + "; fi"
	if out, err := ssh(t, 30*time.Second, "pi", "sudo sh -c "+shellQuote(steps)); err != nil {
		t.Errorf("restore the eyeball table: %v\n%s", err, out)
	}
	// The apply restarted the fence. The next group sends its first request
	// at once and does not retry, so wait here until the agent gets
	// example.com again.
	eventuallyEvery(t, 90*time.Second, 3*time.Second, func() string {
		if code := httpCode(t, "https://example.com"); code != "200" {
			return "https://example.com after the eyeball restore: " + code + ", want 200"
		}
		return ""
	})
}
