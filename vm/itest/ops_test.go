//go:build vagrant

package itest

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/dnslog"
)

// opsTests are the operator checks that a real Pi gets manually. The checks that change live state put it back with t.Cleanup:
// the forced log rotation, the retired keys written into the env files,
// the resolver stopped mid-flood, the back-dated monitor day files, and
// with PF_E2E_REBOOT=1 the reboot. On a real Pi, the retired keys (and the
// applies that they need) and the resolver stop run only with
// PF_E2E_DESTRUCTIVE=1 (labOnly). A Pi in use keeps its env files and its
// resolver, and a run killed in between would leave either one behind.
func opsTests(t *testing.T) {
	t.Run("feeds fail safely", feedsFailTests)
	t.Run("a retired flag is refused, not ignored", labOnly(retiredFlagTests))
	t.Run("forced log rotation", logrotateTests)
	t.Run("DNS log flood control", dnsFloodTests)
	t.Run("a burst of long subdomain labels raises a dns_tunnel alert", dnsTunnelTests)
	t.Run("monitor day files are pruned to a week of UTC days", monitorPruneTests)
	t.Run("the stats day boundary follows the box's own zone", dayBoundaryTests)
	t.Run("no pf listener on a management port", func(t *testing.T) {
		if bad := pfListeners(pi(t, "sudo ss -Hltnp"), "22", "53", "80", "8080"); len(bad) > 0 {
			t.Fatal(strings.Join(bad, "\n"))
		}
	})
	t.Run("key file is private", func(t *testing.T) {
		if out := strings.TrimSpace(pi(t, "sudo stat -c '%a %U' /etc/pi-fortress/broker/secrets.env")); out != "600 pf-broker" {
			t.Fatal(out)
		}
	})
	t.Run("setup page commands run clean", func(t *testing.T) {
		for _, c := range []string{"pf observe once", "pf monitor show -n 5", "pf monitor avg -since 24h"} {
			if out, err := ssh(t, 60*time.Second, "pi", "sudo "+c); err != nil {
				t.Errorf("%s: %v\n%s", c, err, out)
			}
		}
	})
	t.Run("reboot", rebootTests)
}

// feedsFailTests run pf fetch with no network on a copy of generated/:
// the lists must not change whether or not saved feed copies exist.
func feedsFailTests(t *testing.T) {
	const gen = "/tmp/pf-gen"
	hash := "sudo find " + gen + " -type f ! -name fetch.report -exec sha256sum {} + | sort"
	fetch := func(t *testing.T) (out string, rc int, same bool) {
		t.Helper()
		before := pi(t, hash)
		out = strings.TrimSpace(pi(t, "sudo unshare -n pf fetch -out "+gen+" 2>&1; echo rc=$?"))
		rc, _ = strconv.Atoi(out[strings.LastIndex(out, "rc=")+3:])
		return out, rc, before == pi(t, hash)
	}
	pi(t, "sudo rm -rf "+gen+" && sudo cp -a /vagrant/vm/policy/generated "+gen)
	defer func() { _, _ = ssh(t, 20*time.Second, "pi", "sudo rm -rf "+gen) }()

	t.Run("saved copies: STALE, rc 0, lists unchanged", func(t *testing.T) {
		if _, err := ssh(t, 10*time.Second, "pi", "sudo test -d "+gen+"/feeds"); err != nil {
			t.Skip("no saved feed copies: no real fetch has run here")
		}
		if out, rc, same := fetch(t); rc != 0 || !same || !contains(out, "STALE ") {
			t.Fatalf("rc=%d same=%v\n%s", rc, same, out)
		}
	})
	t.Run("no copies: FAIL, rc 1, lists unchanged", func(t *testing.T) {
		pi(t, "sudo rm -rf "+gen+"/feeds")
		if out, rc, same := fetch(t); rc != 1 || !same || !contains(out, "FAIL ") || !contains(out, "wrote 0 ips, 0 domains") {
			t.Fatalf("rc=%d same=%v\n%s", rc, same, out)
		}
	})
}

// rulesetState is what the box filters with: the loaded ruleset without
// its live counters and set elements, plus the file that apply installs.
// Counters change with any traffic, and the resolver adds elements when
// names resolve. Thus neither is evidence of a reload, but the rules are.
// Both halves are read. Thus an apply that rewrote /etc/nftables.conf
// without a load is also caught.
func rulesetState(t *testing.T) string {
	t.Helper()
	// nft prints a set body as "elements = { a, b }", and closes it on the
	// line of the last element. Thus a removal from that line to the first
	// } removes the body and keeps the declaration.
	const dropElements = `awk '/elements = \{/{skip=1} skip{if (/\}/) skip=0; next} {print}'`
	return pi(t, "sudo nft -s list ruleset | "+dropElements+" | sha256sum") +
		pi(t, "sudo sha256sum /etc/nftables.conf")
}

// retiredFlagTests put a retired key back in the env file that an
// operator would use. They check that apply stops, names the file that
// has the key, and does not change the ruleset. This prevents a silent
// ignore of the key: an operator who sets GO_DNS=0 to roll back would get
// a clean apply that did nothing that they asked for, and would believe
// that it worked. The static half is internal/render/render_test.go:394
// and vm/pi/apply_test.sh:183,745. This is the live half.
func retiredFlagTests(t *testing.T) {
	// --local is still a real apply: it renders and reloads nft. But it
	// skips the feed fetch. Thus a regression here costs a local reload,
	// not a full fetch from the upstream. The flood tests can cause that
	// upstream to throttle the NAT address of this lab.
	const apply = "sudo pf apply --local 2>&1"

	before := rulesetState(t)
	time.Sleep(3 * time.Second)
	if now := rulesetState(t); now != before {
		t.Skip("the loaded ruleset is not the same twice at rest, so an unchanged-ruleset check cannot speak here")
	}

	for _, c := range []struct {
		key, file, line, want string
	}{
		{"GO_DNS", "/etc/pi-fortress/net.env.local", "GO_DNS=0", "GO_DNS is retired"},
		{"GO_DNS_FORMAT", "/etc/pi-fortress/net.env.local", "GO_DNS_FORMAT=jsonl", "GO_DNS_FORMAT is retired"},
		{"HOUSE_DEV_MODE", "/etc/pi-fortress/house.env", "HOUSE_DEV_MODE=on", "HOUSE_DEV_MODE is now HOUSE_PRIVATE_DNS; rename the line"},
	} {
		t.Run(c.key+" stops the apply, names the file that holds it, and changes nothing", func(t *testing.T) {
			bak := c.file + ".pf-itest.bak"
			_, err := ssh(t, 15*time.Second, "pi", "sudo test -f "+c.file)
			existed := err == nil
			if existed {
				pi(t, "sudo cp -a "+c.file+" "+bak)
			}
			// Registered before the file changes. A failed assertion below
			// must not leave a retired key on the box. If it did, all later
			// applies (of this suite and of the next operator) would refuse
			// because of a line that this test wrote.
			t.Cleanup(func() {
				cmd := "sudo rm -f " + c.file + " " + bak
				if existed {
					cmd = "sudo mv -f " + bak + " " + c.file
				}
				if out, err := ssh(t, 20*time.Second, "pi", cmd); err != nil {
					t.Errorf("%s was not put back: %v\n%s", c.file, err, out)
				}
			})
			// A leading newline of its own: net.env.local is edited manually
			// and possibly does not end in one. A key attached to the end of
			// the last line is not the key that this test wants to set.
			pi(t, "printf '\\n%s\\n' '"+c.line+"' | sudo tee -a "+c.file+" >/dev/null")

			out, err := ssh(t, 4*time.Minute, "pi", apply)
			if err == nil {
				t.Fatalf("%s left in %s and apply still succeeded:\n%s", c.line, c.file, out)
			}
			if !contains(out, c.want) {
				t.Errorf("apply refused %s without saying %q:\n%s", c.key, c.want, out)
			}
			if !contains(out, c.file) {
				t.Errorf("apply refused %s without naming %s, so the operator cannot find the line:\n%s", c.key, c.file, out)
			}
			if after := rulesetState(t); after != before {
				t.Errorf("the refused apply changed the loaded ruleset; a half-applied firewall is the real failure here")
			}
		})
	}
}

// logrotateTests force a rotation and check the DNS daemons reopened
// their logs: no descriptor left on a rotated or deleted file, and a new
// query lands in the new file.
func logrotateTests(t *testing.T) {
	e := netenv(t)
	const log = "/var/log/pi-fortress/dns.jsonl"
	const offsetPath = "/var/lib/pi-fortress/dns.offset"
	// Read before the rotation: the cursor of the reader into the old file
	// is the only reference against which to measure a shrink.
	offsetBefore := logOffset(t, offsetPath)
	pi(t, "sudo logrotate -f --state /var/lib/pi-fortress/logrotate.state /etc/pi-fortress/logrotate.conf")
	name := fmt.Sprintf("pf-rotate-%d.%s", time.Now().Unix(), e["ALLOW_DOMAIN"])
	// The daemons reopen their logs asynchronously after the signal. A
	// query sent before that goes into the rotated file, so it is sent again.
	query := func() { _, _ = ssh(t, 10*time.Second, "agent", "dig +short +time=2 +tries=1 "+name+" @"+e["PI_IP"]) }
	query()

	for _, unit := range []string{"pi-fortress-dns-agent-go", "pi-fortress-dns-agent", "pi-fortress-dns-house"} {
		t.Run(unit+" reopened its log", func(t *testing.T) {
			pid := strings.TrimSpace(pi(t, "systemctl show -p MainPID --value "+unit))
			if pid == "" || pid == "0" {
				t.Skip("not running")
			}
			eventually(t, 15*time.Second, func() string {
				out, _ := ssh(t, 10*time.Second, "pi", "sudo ls -l /proc/"+pid+"/fd | grep -E '/var/log/.*(deleted|\\.log\\.[0-9])' || true")
				if strings.TrimSpace(out) != "" {
					return "still open:\n" + out
				}
				return ""
			})
		})
	}
	t.Run("new log has the query", func(t *testing.T) {
		eventually(t, 15*time.Second, func() string {
			out, _ := ssh(t, 10*time.Second, "pi", "sudo grep -c "+name+" "+log+" || true")
			if n, _ := strconv.Atoi(strings.TrimSpace(out)); n == 0 {
				query()
				return "no " + name + " in " + log
			}
			return ""
		})
	})
	t.Run("the reader's offset shrinks onto the new log", func(t *testing.T) {
		if offsetBefore <= 0 {
			t.Skip("the reader was at the start of the log before the rotation, so a shrink cannot be seen")
		}
		// observe keys the offset to the inode of the file, and restarts at
		// 0 when the inode changes (internal/observe/observe.go:1142).
		// Without that, it would seek past the end of the small new file,
		// and no query after a rotation would be read.
		eventually(t, 60*time.Second, func() string {
			pi(t, "sudo pf observe once")
			if now := logOffset(t, offsetPath); now >= offsetBefore {
				return fmt.Sprintf("%s is %d after the rotation, was %d: the reader did not follow the new file", offsetPath, now, offsetBefore)
			}
			return ""
		})
	})
	// The rotation check ends with the strip test. The alert path reads
	// its own rotated log. Thus a strip after a rotation must still reach
	// pf alert show. labOnly, because stripTests truncates strip.jsonl,
	// and a Pi in use keeps that file.
	t.Run("a strip after the rotation still reaches pf alert show", labOnly(stripTests))
}

// logOffset is the byte offset in one of the checkpoint files of observe.
// The file has the offset and, after it, the inode that it belongs to
// (internal/observe/observe.go:1175). Thus only the first field is a
// number. A missing file reads as -1: nothing was read yet.
func logOffset(t *testing.T, path string) int {
	t.Helper()
	out, err := ssh(t, 15*time.Second, "pi", "sudo cat "+path+" 2>/dev/null || true")
	if err != nil {
		return -1
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return -1
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return -1
	}
	return n
}

// dnsFloodTests send a burst of queries from the agent: each one gets an
// answer, but the Go resolver logs a few, and sums the rest in a
// "suppressed N queries from <ip>" line.
func dnsFloodTests(t *testing.T) {
	e := netenv(t)
	if out, _ := ssh(t, 10*time.Second, "pi", "systemctl is-active pi-fortress-dns-agent-go"); strings.TrimSpace(out) != "active" {
		t.Skip("the resolver is not running")
	}
	const log = "/var/log/pi-fortress/dns.jsonl"
	// Under the nft meter's burst of 400, so nothing is dropped.
	const n = 350
	src := e["AGENT_IP"]
	start, _ := strconv.Atoi(strings.TrimSpace(pi(t, "sudo cat "+log+" | wc -l")))

	answered := strings.TrimSpace(agent(t, fmt.Sprintf(
		"yes %s | head -n %d > /tmp/pf-flood; dig +noall +comments +time=2 +tries=1 @%s -f /tmp/pf-flood | grep -c 'status: NOERROR'; rm -f /tmp/pf-flood",
		e["ALLOW_DOMAIN"], n, e["PI_IP"])))
	if answered != strconv.Itoa(n) {
		t.Errorf("%s of %d queries answered", answered, n)
	}

	var logged, suppressed int
	eventually(t, 40*time.Second, func() string {
		logged, suppressed = floodCounts(pi(t, fmt.Sprintf("sudo tail -n +%d %s", start+1, log)), src)
		if suppressed == 0 || logged+suppressed < n {
			return fmt.Sprintf("from %s: %d logged + %d suppressed, want %d in total with a suppressed line", src, logged, suppressed, n)
		}
		return ""
	})
	if logged >= n {
		t.Errorf("%d query lines for %d queries: logging is not limited", logged, n)
	}

	t.Run("the log takes a burst at once and then only the steady rate", floodShapeTests)
	t.Run("stopping the resolver flushes the queries it had only counted", labOnly(floodStopTests))
	t.Run("a flood of sinkholed names keeps a budget of its own", floodListedTests)
}

// The shape of the limiter, from internal/dnsd/ratelimit.go:13-14. A quiet
// source gets logBurst lines immediately, and logRate a second after
// that. The tests below assert the two halves separately.
const (
	logBurst = 100
	logRate  = 20
	// Long enough for an empty bucket to refill to logBurst.
	floodIdle = 8 * time.Second
)

// floodShapeTests send two floods, one immediately after the other. The
// first comes on a refilled bucket and must be about the burst. The second
// comes on an empty bucket and must be about the rate. A limiter that
// leaked (a burst that never ran out, or a rate that also applied to the
// first flood) gives two numbers of the same size. This test catches that.
func floodShapeTests(t *testing.T) {
	e := netenv(t)
	const log = "/var/log/pi-fortress/dns.jsonl"
	src, server := e["AGENT_IP"], e["PI_IP"]
	const n = 250

	time.Sleep(floodIdle)
	mark := logLines(t, log)
	burstMS := flood(t, e["ALLOW_DOMAIN"], server, n, "a")
	onBurst, _, _, _ := floodActs(logSince(t, log, mark), src)

	mark = logLines(t, log)
	rateMS := flood(t, e["ALLOW_DOMAIN"], server, n, "a")
	onRate, _, _, _ := floodActs(logSince(t, log, mark), src)

	// Both floods must be short compared with the 5 s that the rate needs
	// to refill a full burst. If not, the two numbers measure the same
	// thing, and neither says anything.
	if burstMS > 3000 || rateMS > 3000 {
		t.Skipf("the floods took %d ms and %d ms; too slow to tell the burst from the rate", burstMS, rateMS)
	}
	if want := logBurst + logRate*(burstMS+1000)/1000 + 40; onBurst > want {
		t.Errorf("%d lines for the first %d queries in %d ms, over the %d the burst plus the rate allows", onBurst, n, burstMS, want)
	}
	if onBurst < logBurst/2 {
		t.Errorf("%d lines for the first %d queries: the burst is not being spent, a busy page load would go unlogged", onBurst, n)
	}
	if want := logRate*(rateMS+1000)/1000 + 40; onRate > want {
		t.Errorf("%d lines for the second %d queries in %d ms, over the %d the rate allows: the bucket did not stay empty", onRate, n, rateMS, want)
	}
	if onRate >= onBurst {
		t.Errorf("the second flood logged %d lines against the first flood's %d: there is no burst, only a rate", onRate, onBurst)
	}
}

// floodStopTests check that the resolver empties its counters when it
// stops. Each query is a line or a part of a summary. If the stop
// discarded what the last sweep did not write yet, the two would not add
// up to what was sent. An operator who reads the log after a restart
// would then quietly get a low count.
func floodStopTests(t *testing.T) {
	e := netenv(t)
	const log = "/var/log/pi-fortress/dns.jsonl"
	const unit = "pi-fortress-dns-agent-go"
	src, server := e["AGENT_IP"], e["PI_IP"]
	const n = 300

	// Registered before the stop: the rest of this group, and every
	// group after it, needs a live resolver even if an assertion below
	// fails first.
	t.Cleanup(func() {
		if out, err := ssh(t, 30*time.Second, "pi", "sudo systemctl start "+unit); err != nil {
			t.Errorf("%s was not started again: %v\n%s", unit, err, out)
		}
	})

	time.Sleep(floodIdle)
	mark := logLines(t, log)
	flood(t, e["ALLOW_DOMAIN"], server, n, "a")
	// Immediately after the flood, inside the 10 s sweep of
	// internal/dnsd/ratelimit.go. Thus there is still a pending count for
	// the shutdown to write. If a sweep comes first, the sum adds up in all
	// cases, and the test passes without much of a test. It cannot fail
	// for that reason.
	pi(t, "sudo systemctl stop "+unit)
	logged, _, suppressed, _ := floodActs(logSince(t, log, mark), src)
	pi(t, "sudo systemctl start "+unit)

	if suppressed == 0 {
		t.Errorf("%d queries from %s and no suppressed row after the stop: nothing summarised what was not logged", n, src)
	}
	if logged+suppressed < n {
		t.Errorf("%d logged + %d suppressed for %d queries from %s: the stop dropped what it had only counted", logged, suppressed, n, src)
	}
	eventually(t, 60*time.Second, func() string {
		if out, _ := ssh(t, 15*time.Second, "pi", "systemctl is-active "+unit); strings.TrimSpace(out) != "active" {
			return unit + " after the stop: " + out
		}
		return ""
	})
}

// floodListedTests run an ordinary flood and a sinkholed flood at the
// same time from the same address. The sinkhole rows are the evidence that
// observe changes into blocked events. Thus they get a bucket of their own
// (internal/dnsd/ratelimit.go limitKey.listed): chatter must not be able
// to spend them. The two floods together are almost four bursts, so one
// shared bucket could not give both of them a burst. They must also stay
// under the guard of the kernel (ruleset.go, burst 400 packets a source).
// A Pi answers 250 queries in less than 100 ms. Two overlapping floods of
// that size are 500 packets, and the meter drops the excess before the
// resolver can log or count it. Seen on hardware 2026-09-21 as 249 rows
// for 250 queries, with the counter of the meter up by one.
func floodListedTests(t *testing.T) {
	e := netenv(t)
	const log = "/var/log/pi-fortress/dns.jsonl"
	src, server := e["AGENT_IP"], e["PI_IP"]
	const n = 190

	time.Sleep(floodIdle)
	mark := logLines(t, log)
	// Both in one ssh, so that the two floods really overlap. Neither name
	// leaves the box: the allow name gets answers from cache after the
	// first query, and the block name is sinkholed to 0.0.0.0. Thus this
	// stays off the upstream that throttles the NAT address of this lab
	// after a flood.
	agent(t, fmt.Sprintf(
		"yes %s | head -n %d > /tmp/pf-flood-a; yes %s | head -n %d > /tmp/pf-flood-b; "+
			"dig +short +time=2 +tries=1 @%s -f /tmp/pf-flood-a >/dev/null & "+
			"dig +short +time=2 +tries=1 @%s -f /tmp/pf-flood-b >/dev/null & "+
			"wait; rm -f /tmp/pf-flood-a /tmp/pf-flood-b",
		e["ALLOW_DOMAIN"], n, e["BLOCK_DOMAIN"], n, server, server))

	var logged, blocked, suppressed, listedSuppressed int
	eventually(t, 60*time.Second, func() string {
		logged, blocked, suppressed, listedSuppressed = floodActs(logSince(t, log, mark), src)
		if suppressed == 0 || listedSuppressed == 0 {
			return fmt.Sprintf("from %s: %d logged + %d suppressed, %d blocked + %d suppressed; want a summary for each bucket", src, logged, suppressed, blocked, listedSuppressed)
		}
		return ""
	})
	if blocked < logBurst/2 {
		t.Errorf("only %d sinkhole rows from %s while %d ordinary rows were logged: the flood of ordinary names spent the sinkhole budget", blocked, src, logged)
	}
	if logged < logBurst/2 {
		t.Errorf("only %d ordinary rows from %s while %d sinkhole rows were logged: the two buckets are one", logged, src, blocked)
	}
	if blocked+listedSuppressed < n {
		t.Errorf("%d blocked + %d suppressed for %d sinkholed queries from %s: the sinkhole rows do not add up", blocked, listedSuppressed, n, src)
	}
	if logged+suppressed < n {
		t.Errorf("%d logged + %d suppressed for %d ordinary queries from %s", logged, suppressed, n, src)
	}
}

// flood sends n queries for name from the agent, as fast as one dig can,
// and returns the time in milliseconds. The caller selects a name that
// the box itself answers, so a flood is never n lookups upstream. tag
// gives two concurrent floods different query files.
func flood(t *testing.T, name, server string, n int, tag string) int {
	t.Helper()
	f := "/tmp/pf-flood-" + tag
	out := strings.TrimSpace(agent(t, fmt.Sprintf(
		"yes %s | head -n %d > %s; s=$(date +%%s%%3N); dig +short +time=2 +tries=1 @%s -f %s >/dev/null; e=$(date +%%s%%3N); rm -f %s; echo $((e-s))",
		name, n, f, server, f, f)))
	ms, err := strconv.Atoi(out)
	if err != nil {
		t.Fatalf("flood of %d %s: %q", n, name, out)
	}
	return ms
}

// logLines is the number of lines in the resolver log now: the mark that
// logSince reads from.
func logLines(t *testing.T, log string) int {
	t.Helper()
	n, _ := strconv.Atoi(strings.TrimSpace(pi(t, "sudo cat "+log+" | wc -l")))
	return n
}

func logSince(t *testing.T, log string, mark int) string {
	t.Helper()
	return pi(t, fmt.Sprintf("sudo tail -n +%d %s", mark+1, log))
}

// floodActs reads a resolver log as observe does, and splits the rows of
// one source by bucket: the ordinary rows and their summary, and the
// sinkhole rows and their summary. floodCounts in e2e.go adds sinkhole
// rows to the rest and discards the listed summaries. That is correct for
// its own question, but hides the question here: are the two budgets
// really separate?
func floodActs(log, src string) (logged, blocked, suppressed, listedSuppressed int) {
	var r dnslog.Reader
	fold := func(evs []dnslog.Event) {
		for _, ev := range evs {
			if ev.Src != src {
				continue
			}
			switch {
			case ev.Act == dnslog.ActSuppressed && ev.Listed:
				listedSuppressed += ev.N
			case ev.Act == dnslog.ActSuppressed:
				suppressed += ev.N
			case ev.Act == dnslog.ActBlocked:
				blocked++
			default:
				logged++
			}
		}
	}
	for line := range strings.SplitSeq(log, "\n") {
		fold(r.Feed(strings.TrimSpace(line)))
	}
	fold(r.Flush())
	return logged, blocked, suppressed, listedSuppressed
}

func rebootTests(t *testing.T) {
	needReboot(t)
	e := netenv(t)
	reboot(t, "pi")
	eventually(t, 3*time.Minute, func() string {
		if out, err := ssh(t, 60*time.Second, "pi", "sudo pf doctor"); err != nil {
			return fmt.Sprintf("pf doctor: %v\n%s", err, out)
		}
		return ""
	})
	if out, _ := ssh(t, 20*time.Second, "pi", "systemctl --failed --no-legend --plain"); contains(out, "pi-fortress") {
		t.Error(out)
	}
	// The box ships this at 0. Only a reload of table inet fortress by
	// nftables.service sets it again, through the 10-pi-fortress-forward.conf
	// drop-in. A 0 here means that the last apply did not finish, and no
	// segment routes anything.
	if out := strings.TrimSpace(pi(t, "/sbin/sysctl -n net.ipv4.ip_forward")); out != "1" {
		t.Errorf("net.ipv4.ip_forward is %q after the reboot, not 1: the forward drop-in did not survive", out)
	}
	t.Run("a sealed key store comes back locked and says how to open it", func(t *testing.T) {
		out, err := ssh(t, 20*time.Second, "pi", "sudo pf enroll state")
		if err != nil {
			t.Fatalf("pf enroll state: %v\n%s", err, out)
		}
		switch state := strings.TrimSpace(out); state {
		case "plaintext":
			t.Skip("the key store is not sealed on this box")
		case "sealed, locked: pf unlock":
			// What a reboot must produce: the key is gone with the
			// RAM that held it, and the line names the way back in.
		case "sealed, unlocked":
			t.Errorf("the key store is sealed but already unlocked after a reboot: the passphrase outlived the boot it is meant to be bound to")
		default:
			t.Errorf("pf enroll state after a reboot: %q", state)
		}
		// The lab cannot do the other half, which opens it again: pf unlock
		// reads the passphrase from /dev/tty (internal/secrets/prompt.go),
		// and the ssh of this suite runs with no tty. Checked manually.
		t.Log("pf unlock itself needs a terminal, so only the locked state is checked here")
	})
	eventually(t, 2*time.Minute, func() string {
		if code := httpCode(t, "https://"+e["ALLOW_DOMAIN"]); !curlOK(code) {
			return "agent HTTPS after reboot: " + code
		}
		return ""
	})
	if target() != "cloudlab" || !sshHosts["house"] {
		return
	}
	eventually(t, 2*time.Minute, func() string {
		if out, _ := ssh(t, 20*time.Second, "pi", "systemctl is-active pi-fortress-dns-house"); strings.TrimSpace(out) != "active" {
			return "house DNS after reboot: " + out
		}
		if ips := digOn(t, "house", e["ALLOW_DOMAIN"], "10.78.0.1"); len(ips) == 0 {
			return "house DNS answers nothing after reboot"
		}
		out, _ := ssh(t, 20*time.Second, "house", "sudo ip netns exec phone curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://"+e["ALLOW_DOMAIN"])
		if !curlOK(strings.TrimSpace(out)) {
			return "house pool device HTTPS after reboot: " + out
		}
		return ""
	})
	if out := pi(t, "sudo cat /var/lib/pi-fortress/house.leases"); !contains(strings.ToLower(out), strings.ToLower(e["HOUSE_MAC"])) {
		t.Errorf("house.leases lost the admin lease across the reboot:\n%s", out)
	}
}

// dnsTunnelTests send the shape that the dns_tunnel heuristic of observe
// counts: a hundred and fifty distinct names under one registrable domain
// in one minute, each with a leftmost label long enough to be a payload.
// The name is pf-open-echo.test, which the resolver answers from
// configuration towards TEST-NET. Thus the burst never leaves the box,
// and no upstream sees it. The heuristic itself knows nothing about that
// name: it fires on the numbers alone. That is the purpose of no special
// case for test domains in the product.
//
// `pf observe once`, not a wait for the daemon: the daemon moves the
// dns.offset checkpoint only when it flushes. Thus `once` still reads
// these rows, at any progress of the daemon (refer to the comment in
// dns_segments_test.go). The rate limiter of the resolver will suppress a
// large part of the burst. What it logs is much more than the twenty
// distinct long labels that the label rule needs, so the row fires in
// both cases.
func dnsTunnelTests(t *testing.T) {
	piIP := netenv(t)["PI_IP"]
	if piIP == "" {
		t.Fatal("net.env has no PI_IP")
	}
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	// dig -f reads one name for each line. Thus the full burst is one
	// process, inside the minute that the heuristic counts.
	agent(t, "for i in $(seq 1 150); do printf 'qrstuvwxyz234567qrstuvwxyz234567%03d-"+nonce+
		".pf-open-echo.test\\n' $i; done > /tmp/pf-tunnel; "+
		"dig +noall +time=2 +tries=1 @"+piIP+" -f /tmp/pf-tunnel >/dev/null 2>&1; rm -f /tmp/pf-tunnel")
	out := pi(t, "sudo /usr/local/sbin/pf observe once")
	alerts := strings.Index(out, "ALERTS (")
	if alerts < 0 {
		t.Fatalf("pf observe once printed no ALERTS section:\n%s", out)
	}
	tail := out[alerts:]
	if !contains(tail, "dns_tunnel") || !contains(tail, "pf-open-echo.test") {
		t.Fatalf("no dns_tunnel row for pf-open-echo.test under ALERTS:\n%s", tail)
	}
	// Never under BLOCKED: the signal reports, and does not change the
	// resolver. Each of those names got an answer.
	if head := out[:alerts]; contains(head, "dns_tunnel") {
		t.Fatalf("a dns_tunnel row under BLOCKED:\n%s", head)
	}
}

// monitorPruneTests back-date day files in the monitor directory, and let
// one append run. prune keeps KeepDays UTC days and removes older days
// (internal/monitor/monitor.go:380). Thus a box that runs for a long time
// does not fill /var/log with a year of samples.
//
// The days are UTC on purpose: each sample has the stamp now.UTC(), and
// the file name comes from that stamp. A box in IST that named its files
// in local time would change the day five and a half hours early, and
// the cut would be on the wrong file.
func monitorPruneTests(t *testing.T) {
	const dir = "/var/log/pi-fortress/monitor"
	if _, err := ssh(t, 15*time.Second, "pi", "sudo test -d "+dir); err != nil {
		t.Skip("no monitor directory on this box")
	}
	today := strings.TrimSpace(pi(t, "date -u +%F"))
	// KeepDays is 7 and the cut is today-(KeepDays-1), so today-7 is the
	// first day that must go. ISO dates compare as strings.
	cut := strings.TrimSpace(pi(t, "date -u -d '"+today+" -6 day' +%F"))
	stale := strings.Fields(pi(t, "for d in 7 8 9 10; do date -u -d \""+today+" -$d day\" +%F; done"))
	if len(stale) != 4 {
		t.Fatalf("could not work out the back-dated days: %q", stale)
	}

	var made []string
	for _, day := range stale {
		for _, kind := range []string{"system", "procs"} {
			made = append(made, dir+"/"+kind+"-"+day+".jsonl")
		}
	}
	files := strings.Join(made, " ")
	// touch never truncates. Thus a real day file that a stopped daemon
	// left keeps its samples, and prune must remove it in all cases.
	// The owner is copied from the directory, not named, because the
	// daemon user is different in the lab and on a Pi. Also, the daemon
	// could not append to a root-owned file here after that.
	pi(t, "sudo touch "+files+" && sudo chown --reference="+dir+" "+files)
	// Registered before the prune runs. If prune is broken, these files
	// stay, and a box that quietly collects test files is worse than the
	// bug. Ownership is also repaired, because the run below is root. It
	// would leave the file of today root-owned if it had to create it.
	// The glob runs inside the root shell: the directory belongs to the
	// daemon, and the login account cannot list it to expand a glob.
	repair := "sudo sh -c 'rm -f " + files + "; chown --reference=" + dir + " " + dir + "/*.jsonl'"
	t.Cleanup(func() {
		if out, err := ssh(t, 30*time.Second, "pi", repair); err != nil {
			t.Errorf("the back-dated monitor files were not cleaned up: %v\n%s", err, out)
		}
	})

	// pf monitor once only samples and prints. The prune runs from Append,
	// and only the run loop calls Append. Thus one tick is the shortest
	// way to reach it (internal/cli/monitor.go:35, monitor.go:311). The 124
	// of timeout is the expected end, because the run loop has no other
	// exit. Thus only 124 and a clean 0 pass. A real failure (a bad flag
	// is 2, a missing binary 127) still fails the test, and does not hide
	// behind the kill.
	tick := "timeout 5 /usr/local/sbin/pf monitor -interval 1 -dir " + dir + " run"
	if out, err := ssh(t, 30*time.Second, "pi", "sudo sh -c '"+tick+"; rc=$?; [ \"$rc\" = 124 ] || [ \"$rc\" = 0 ] || exit \"$rc\"'"); err != nil {
		t.Fatalf("pf monitor run: %v\n%s", err, out)
	}

	days := map[string]map[string]bool{"system": {}, "procs": {}}
	for _, name := range strings.Fields(pi(t, "sudo ls -1 "+dir)) {
		for kind := range days {
			day, ok := strings.CutPrefix(name, kind+"-")
			if !ok {
				continue
			}
			if day, ok = strings.CutSuffix(day, ".jsonl"); ok {
				days[kind][day] = true
			}
		}
	}
	for _, day := range stale {
		for kind := range days {
			if days[kind][day] {
				t.Errorf("%s-%s.jsonl is past the %s cut and still there: prune is not running on append", kind, day, cut)
			}
		}
	}
	for kind, set := range days {
		if len(set) > 7 {
			t.Errorf("%d %s day files in %s, over the 7 KeepDays allows", len(set), kind, dir)
		}
		for day := range set {
			if day < cut {
				t.Errorf("%s-%s.jsonl is older than the %s cut and survived", kind, day, cut)
			}
		}
	}
}

// dayBoundaryTests check that the SERIES columns break at the midnight of
// the box, not at UTC midnight. The hours are stored in UTC and rolled up
// in time.Local (internal/observe/observe.go:1788, Days at :803). Thus on
// a Pi in IST, an hour late in the UTC day belongs to the next local day.
// A rollup without the conversion would show the operator a day that
// ended five and a half hours before their day.
//
// It reads its own state file through -state, and changes nothing on the
// box: it never opens the real observe.json.
func dayBoundaryTests(t *testing.T) {
	const state = "/tmp/pf-itest-series.json"
	t.Cleanup(func() {
		if out, err := ssh(t, 20*time.Second, "pi", "rm -f "+state); err != nil {
			t.Errorf("%s was left behind: %v\n%s", state, err, out)
		}
	})
	// 20:00 UTC is 01:30 the next day in IST, so one bucket goes into a
	// different column in each zone. Two days back keeps it inside the
	// seven days that Days shows, and away from both ends.
	utcDay := strings.TrimSpace(pi(t, "date -u -d '-2 day' +%F"))
	utcCol := strings.TrimSpace(pi(t, "date -u -d '-2 day' +%m-%d"))
	istCol := strings.TrimSpace(pi(t, "date -u -d '-1 day' +%m-%d"))
	pi(t, `echo '{"series":{"agent":[{"hour":"`+utcDay+`T20","queries":7,"flows":0,"blocked":0}]}}' > `+state)

	// The row is "  %-5s %-5s q=%d f=%d b=%d" and both fields are five
	// wide already (internal/observe/observe.go:1797).
	row := func(col string) string { return "  " + col + " agent q=7" }
	// env carries the zone in, because sudo resets the environment; the
	// binary is named in full because env resolves it on its own PATH.
	utc := pi(t, "sudo env TZ=UTC /usr/local/sbin/pf observe show -state "+state)
	if !contains(utc, "SERIES") {
		t.Fatalf("pf observe show printed no SERIES section:\n%s", utc)
	}
	if !contains(utc, row(utcCol)) {
		t.Errorf("in UTC the 20:00 hour is not on %s:\n%s", utcCol, utc)
	}
	ist := pi(t, "sudo env TZ=Asia/Kolkata /usr/local/sbin/pf observe show -state "+state)
	if !contains(ist, row(istCol)) {
		t.Errorf("in IST the 20:00 UTC hour is not on %s, so the day does not start at the box's own midnight:\n%s", istCol, ist)
	}
	if contains(ist, row(utcCol)) {
		t.Errorf("in IST the 20:00 UTC hour is still on %s: the rollup is bucketing by UTC and the operator's day ends early:\n%s", utcCol, ist)
	}
}
