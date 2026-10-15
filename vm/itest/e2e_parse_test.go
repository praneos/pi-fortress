//go:build vagrant

package itest

import (
	"slices"
	"testing"

	"pi-fortress/internal/dnslog"
)

// TestE2EParsers needs no lab: go test -tags=vagrant -run TestE2EParsers ./vm/itest
func TestE2EParsers(t *testing.T) {
	t.Run("hostAliases", func(t *testing.T) {
		got := hostAliases("Host pi\n  HostName 10.79.0.1\nhost agent agent2\nHost *\n  ControlMaster auto\n# Host gone\n")
		for _, h := range []string{"pi", "agent", "agent2"} {
			if !got[h] {
				t.Errorf("missing %s in %v", h, got)
			}
		}
		if len(got) != 3 {
			t.Errorf("%v", got)
		}
	})
	t.Run("floodCounts", func(t *testing.T) {
		// One resolved query and two dropped queries from three clients,
		// then the summaries that the limiter writes. Only the unlisted
		// counts are the flood. Only the rows of 10.77.0.10 are ours.
		var rows string
		for _, ev := range []dnslog.Event{
			{Src: "10.77.0.10", Name: "example.com", QType: "A", Act: dnslog.ActResolved, Answer: "1.2.3.4"},
			{Src: "10.77.0.11", Name: "example.com", QType: "A", Act: dnslog.ActDropped},
			{Src: "10.77.0.100", Name: "example.com", QType: "A", Act: dnslog.ActDropped},
			{Src: "10.77.0.10", Act: dnslog.ActSuppressed, N: 240},
			{Src: "10.77.0.10", Act: dnslog.ActSuppressed, N: 7, Listed: true},
			{Src: "10.77.0.10", Act: dnslog.ActSuppressed, N: 9},
		} {
			rows += dnslog.EventLine(ev) + "\n"
		}
		if logged, suppressed := floodCounts(rows, "10.77.0.10"); logged != 1 || suppressed != 249 {
			t.Errorf("logged=%d suppressed=%d", logged, suppressed)
		}
		// The two lines of dnsmasq are not a transaction here now.
		if logged, suppressed := floodCounts("query[A] example.com from 10.77.0.10\nsuppressed 240 queries from 10.77.0.10\n", "10.77.0.10"); logged != 0 || suppressed != 0 {
			t.Errorf("the retired format still counted: logged=%d suppressed=%d", logged, suppressed)
		}
	})
	t.Run("pfListeners", func(t *testing.T) {
		ss := `LISTEN 0 4096 10.77.0.1:8080 0.0.0.0:* users:(("pf",pid=10,fd=3))
LISTEN 0 4096 10.77.0.1:80 0.0.0.0:* users:(("pf",pid=11,fd=3))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 4096 [::1]:9090 [::]:* users:(("pf",pid=12,fd=4))
LISTEN 0 4096 127.0.0.1:5353 0.0.0.0:* users:(("dnsmasq",pid=13,fd=4))`
		got := pfListeners(ss, "22", "53", "80", "8080")
		if len(got) != 1 || !contains(got[0], "9090") {
			t.Errorf("%q", got)
		}
	})
	t.Run("lineWith", func(t *testing.T) {
		out := "eth1.20@eth1 UP 10.77.0.1/24\neth1.79@eth1 UP 10.79.0.1/30\neth2 UP 10.78.0.1/24"
		if !lineWith(out, ".79@", " 10.79.0.1/30") || lineWith(out, ".20@", " 10.79.0.1/30") {
			t.Error("lineWith")
		}
	})
	t.Run("nextIP and firstIPv4", func(t *testing.T) {
		if got := nextIP("10.77.0.10"); got != "10.77.0.11" {
			t.Error(got)
		}
		if got := firstIPv4("example.com.\n93.184.215.14\n1.2.3.4\n"); got != "93.184.215.14" {
			t.Error(got)
		}
	})
	t.Run("target", func(t *testing.T) {
		for _, c := range []struct{ tgt, cfg, want string }{{"", "", "vagrant"}, {"", "/x", "pi"}, {"cloudlab", "/x", "cloudlab"}} {
			t.Setenv("PF_TARGET", c.tgt)
			t.Setenv("PF_SSH_CONFIG", c.cfg)
			if got := target(); got != c.want {
				t.Errorf("%+v: %s", c, got)
			}
		}
		if !slices.Contains([]string{"vagrant", "cloudlab", "pi"}, target()) {
			t.Error("target")
		}
	})
}
