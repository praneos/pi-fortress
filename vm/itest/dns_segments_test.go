//go:build vagrant

package itest

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/nftsets"
)

// dnsSegmentTests check the Go resolver on a box that really ran an
// apply. pf dns serves one segment for each interface from
// /etc/pi-fortress/dns.json. Where there is a house, it is a segment of
// that same daemon, and dnsmasq still does DHCP.
//
// apply_test.sh cannot reach any of this: --render-nft exits before the
// resolver half of apply. Thus the segment list has no coverage in any
// other place.
func dnsSegmentTests(t *testing.T) {
	// apply used -check as the gate for the restart. Thus a new run of it
	// asks the daemon to describe the configuration that it serves.
	check := pi(t, "sudo /usr/local/sbin/pf dns -config /etc/pi-fortress/dns.json -check")
	t.Logf("pf dns -check:\n%s", check)

	agent := ""
	house := ""
	for _, ln := range strings.Split(strings.TrimSpace(check), "\n") {
		switch {
		case strings.HasPrefix(ln, "agent "):
			agent = ln
		case strings.HasPrefix(ln, "house "):
			house = ln
		}
	}

	// The log is rows, and only a live box can show that. The writer is
	// the daemon and the reader is observe. A unit test can only agree
	// with itself about what was written.
	t.Run("the live log is rows", func(t *testing.T) {
		last := strings.TrimSpace(pi(t, "sudo tail -n 1 /var/log/pi-fortress/dns.jsonl 2>/dev/null || true"))
		if last == "" {
			t.Skip("the resolver log is empty")
		}
		if !strings.HasPrefix(last, "{") {
			t.Fatalf("the resolver is still writing dnsmasq's two lines: %s", last)
		}
		// The row must carry the asker. That is the full reason for the
		// shape: a reply line could not be told apart from the query of a
		// different client for the same name.
		for _, want := range []string{`"src"`, `"act"`} {
			if !contains(last, want) {
				t.Fatalf("a log row without %s: %s", want, last)
			}
		}
	})

	// The verdict and its attribution, measured around one firing of
	// three queries, not two. The counters must move for the same rows
	// that this then reads. If not, the two halves only agree about
	// different traffic.
	//
	// This is the one place where two past counting bugs show. A blocked
	// name answers 0.0.0.0 if the resolver calls it blocked or resolved.
	// Thus all other DNS tests in the suite pass while the TUI tells the
	// operator that nothing was stopped.
	t.Run("a blocked name logs a blocked row and observe counts it against the client that asked", func(t *testing.T) {
		e := netenv(t)
		piIP, agentIP, block := e["PI_IP"], e["AGENT_IP"], e["BLOCK_DOMAIN"]
		if piIP == "" || agentIP == "" || block == "" {
			t.Fatalf("net.env has no PI_IP/AGENT_IP/BLOCK_DOMAIN: %v", e)
		}

		// The flush is `pf observe once`, not a restart and not a poll.
		// Once() is Snapshot then Flush, and Flush writes observe.json
		// and the dns.offset checkpoint in the same pass
		// (internal/observe/observe.go). Thus a pair of them brackets
		// exactly the rows fired between them. A wait for the daemon
		// would wait for FlushInterval, which is 15 minutes. A restart of
		// pi-fortress-observe would also flush (Run flushes on SIGTERM),
		// but it is heavier and not necessary. `once` renames a new inode
		// into place, and the next pass of the daemon sees stateReplaced
		// and reads it again. Thus it cannot overwrite this baseline.
		// policy_test.go and house_devices_test.go already operate
		// observe this way.
		pi(t, "sudo /usr/local/sbin/pf observe once")
		before := observeCounts(t, agentIP)

		// Local names, never DNS_UPSTREAM. pf-open-echo.test is an
		// address= fixture that the resolver answers from configuration
		// (vm/pi/apply.sh writes dns-agent-go.hosts), and it matches all
		// subdomains. Thus a nonce gives a name that the log never saw,
		// and no packet leaves the box. A query that left would count the
		// same, but it puts the NAT address of the lab in front of an
		// upstream rate limiter. The SERVFAIL that follows looks like a
		// resolver bug.
		nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
		plain := "q1-" + nonce + ".pf-open-echo.test"
		quad := "q2-" + nonce + ".pf-open-echo.test"
		// mustSSH, not the agent() helper: a local named agent holds the
		// segment lines that this function parses.
		mustSSH(t, "agent", "dig +short +time=5 +tries=1 A "+plain+" @"+piIP)
		mustSSH(t, "agent", "dig +short +time=5 +tries=1 AAAA "+quad+" @"+piIP)
		mustSSH(t, "agent", "dig +short +time=5 +tries=1 A "+block+" @"+piIP)

		// A barrier, not a poll for a timer: the resolver writes a row for
		// each query when it answers. Thus this covers only the gap
		// between the return of dig and the write. observe must not count
		// rows that are not on disk yet.
		// `sudo cat | tail`, not `sudo tail -n 200`: the pipe runs in the
		// remote shell outside sudo, and the itest allowlist grants cat of
		// this one log (vm/pi/sudoers.d/pf-itest). The allowlist refuses a
		// bare `tail -n 200`. That would skip this subtest on exactly the
		// boxes that run with an allowlist.
		var tail string
		eventually(t, 20*time.Second, func() string {
			tail = pi(t, "sudo cat /var/log/pi-fortress/dns.jsonl | tail -n 200")
			for _, name := range []string{plain, quad, block} {
				if !lineWith(tail, `"name":"`+name+`"`) {
					return "dns.jsonl has no row for " + name + " yet"
				}
			}
			return ""
		})

		// The verdict is the contract, and the asker is also. A row that
		// said "resolved" here, or carried the address of a different
		// client, would count as allowed traffic in all downstream code.
		if !lineWith(tail, `"src":"`+agentIP+`"`, `"name":"`+block+`"`, `"act":"blocked"`, `"answer":"0.0.0.0"`) {
			t.Fatalf("no blocked row with answer 0.0.0.0 from %s for %s:\n%s", agentIP, block, tail)
		}

		pi(t, "sudo /usr/local/sbin/pf observe once")
		after := observeCounts(t, agentIP)

		// Exactly, not at least. One past bug lost blocks and a different
		// bug doubled names. A ">= before" assertion would pass for both.
		// The AAAA is filtered, not blocked, on purpose: the resolver
		// suppresses it with an empty answer. Thus no contact was stopped,
		// and to add it to Blocked would hide the real blocks.
		for _, c := range []struct {
			what  string
			moved int
			want  int
		}{
			{"queries", after.Queries - before.Queries, 3},
			{"blocked", after.Blocked - before.Blocked, 1},
			{"filtered", after.Filtered - before.Filtered, 1},
		} {
			if c.moved != c.want {
				t.Fatalf("observe moved %s by %d for %s, want %d (before %+v, after %+v)", c.what, c.moved, agentIP, c.want, before, after)
			}
		}
	})

	// A cache miss that the operator would time manually, with the
	// upstream out of the path on purpose. pf-open-echo.test gets its
	// answer from configuration. Thus this measures the per-query work of
	// the daemon (the source table, the row write, the nft add on
	// resolved_v4), not the forward. Fifteen queries to DNS_UPSTREAM cause
	// the upstream to throttle the NAT address of the lab. The SERVFAIL at
	// approximately 5000 ms that comes back looks exactly like a broken
	// resolver. Thus the test would blame the daemon for the refusal of
	// the upstream.
	t.Run("fifteen names the resolver has never seen all answer, and none of them slowly", func(t *testing.T) {
		piIP := netenv(t)["PI_IP"]
		nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
		out := mustSSH(t, "agent", "for i in $(seq 1 15); do dig +noall +comments +stats +time=5 +tries=1 "+
			"m$i-"+nonce+".pf-open-echo.test @"+piIP+" | grep -E 'status:|Query time:' || true; done")

		var codes []string
		var times []int
		for _, ln := range strings.Split(out, "\n") {
			if i := strings.Index(ln, "status: "); i >= 0 {
				code, _, _ := strings.Cut(ln[i+len("status: "):], ",")
				codes = append(codes, strings.TrimSpace(code))
			}
			if i := strings.Index(ln, "Query time: "); i >= 0 {
				f := strings.Fields(ln[i+len("Query time: "):])
				if len(f) == 0 {
					continue
				}
				ms, err := strconv.Atoi(f[0])
				if err != nil {
					continue
				}
				times = append(times, ms)
			}
		}
		// A dig that timed out prints neither line. Thus a short count is
		// the "no servers could be reached" case, and must fail here, not
		// pass on the fourteen that answered.
		if len(codes) != 15 || len(times) != 15 {
			t.Fatalf("15 digs gave %d statuses and %d timings:\n%s", len(codes), len(times), out)
		}
		for i, code := range codes {
			if code != "NOERROR" {
				t.Fatalf("dig %d answered %s, not NOERROR:\n%s", i+1, code, out)
			}
		}
		// The checklist expects single or low double digit msec. The
		// alarm is much higher, so that a loaded VM does not fail the
		// suite. It is still much lower than upstreamTO (5s), which is the
		// number that means "nothing answered".
		const slowMS = 500
		worst := 0
		for _, ms := range times {
			if ms > worst {
				worst = ms
			}
		}
		if worst > slowMS {
			t.Fatalf("slowest of 15 first-time names was %d msec, over the %d msec alarm:\n%s", worst, slowMS, out)
		}
		t.Logf("15 first-time names: slowest %d msec", worst)
	})

	t.Run("the agent segment feeds resolved_v4", func(t *testing.T) {
		if agent == "" {
			t.Fatalf("no agent segment in:\n%s", check)
		}
		if !contains(agent, "set=resolved_v4") {
			t.Fatalf("agent segment does not feed resolved_v4: %s", agent)
		}
	})

	// A reload replaces the full table, and until 2026-09-22 the sets
	// came back empty with it. The agent VM never showed it, because it
	// asks the Pi for each lookup. But a client that answers from its own
	// cache does not ask again. Thus the gate dropped it until that cache
	// expired. The carry must keep the element, and must not give it a
	// longer life than it had: "resolved once" is not "allowed forever".
	//
	// resolved_v4, not the set of a plain segment, so that a box with no
	// plain segment also runs this.
	// labOnly: it runs pf apply, and a test run does not do that on a
	// real Pi in use.
	t.Run("an apply carries the resolved addresses over the reload without lengthening them", labOnly(func(t *testing.T) {
		piIP := netenv(t)["PI_IP"]
		name := "carry-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".pf-open-echo.test"
		ips := digA(t, name, piIP)
		if len(ips) == 0 {
			t.Fatalf("the agent segment stopped resolving: %s gave nothing", name)
		}
		// ssh, not pi: an allowlisted real Pi refuses these two. A
		// refusal there must skip the subtest, not fail the suite.
		set := func(d time.Duration) string {
			out, err := ssh(t, d, "pi", "sudo nft list set inet fortress resolved_v4")
			if err != nil {
				t.Fatalf("nft list set resolved_v4: %v\n%s", err, out)
			}
			return out
		}
		var before time.Duration
		eventually(t, 15*time.Second, func() string {
			if before = expiresIn(set(45*time.Second), ips[0]); before > 0 {
				return ""
			}
			return "resolved_v4 has no " + ips[0] + " after the agent resolved " + name +
				"; the nft the resolver forks never ran"
		})
		if _, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
			t.Fatalf("pf apply --local: %v", err)
		}
		after := expiresIn(set(45*time.Second), ips[0])
		if after == 0 {
			t.Fatalf("the reload emptied resolved_v4: %s is gone, and a client answering from its own DNS "+
				"cache would be dropped by the gate until that cache expired", ips[0])
		}
		if after > before {
			t.Fatalf("%s came back with %v left, more than the %v it had before the reload", ips[0], after, before)
		}
		t.Logf("%s carried across the reload: %v left, was %v", ips[0], after, before)
		// The apply can end before the new pf dns listens. Wait for an
		// answer, so that the next subtest does not ask in that gap. This
		// comes after the checks: the answer renews the element.
		eventually(t, 15*time.Second, func() string {
			back := "back-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".pf-open-echo.test"
			if len(digA(t, back, piIP)) > 0 {
				return ""
			}
			return "the agent segment does not resolve after the apply"
		})
	}))

	// Phase 3. The rest of the suite assumes PARANOID=0 (it resolves
	// example.com freely). Thus this is the one place that says anything
	// about the armed box, and it stays quiet on the ordinary box.
	//
	// TO RUN THIS ARM, the operator or CI must arm the box before the
	// suite: put PARANOID=1 in /etc/pi-fortress/net.env.local (or run
	// apply with PF_PARANOID=1 in its environment, vm/pi/apply.sh) and
	// `sudo pf apply`, then run this group. Nothing in the suite sets the
	// flag. If the tests set the arm on and off, a crash would leave the
	// shared lab in the posture of the run that crashed.
	paranoid := strings.TrimSpace(pi(t, "grep -hE '^PARANOID=' /etc/pi-fortress/net.env /etc/pi-fortress/net.env.local 2>/dev/null | tail -1 | cut -d= -f2- | tr -d \"\\\"' \""))
	t.Run("paranoid is the daemon's own posture", func(t *testing.T) {
		if paranoid != "1" {
			t.Skip("PARANOID is not 1")
		}
		if !contains(agent, "paranoid=") {
			t.Fatalf("PARANOID=1 but the agent segment is not paranoid: %s", agent)
		}
		// The forward set must be the files that the engine and the broker
		// use to decide. A resolver that answers from its own list would
		// give an address that the fence then refuses. The operator would
		// then read two policies to explain one failure.
		conf := pi(t, "sudo cat /etc/pi-fortress/dns.json")
		for _, want := range []string{`"allow": "/etc/pi-fortress/allow.domains"`, `"core_hosts": "/etc/pi-fortress/core.hosts"`} {
			if !contains(conf, want) {
				t.Fatalf("dns.json is missing %s:\n%s", want, conf)
			}
		}
		// The dnsmasq form of the same thing. Nothing reads it now. Thus
		// a copy that stays is a stale forward set that someone can
		// believe.
		if out := pi(t, "ls /etc/pi-fortress/paranoid-dns.conf 2>&1 || true"); !contains(out, "No such file") {
			t.Fatalf("paranoid-dns.conf survived: %s", out)
		}

		// The behaviour of the posture, which the configuration above only
		// promises. K9 (docs/paranoid_mode.md): dnsmasq wrote each
		// forward name as server=/NAME/#, and that included the subdomains
		// of exact core.hosts entries. Thus api.x.ai opened evil.api.x.ai
		// to anything that could get a name under it. corepolicy.Forward
		// does not.
		//
		// console.anthropic.com is the case that shows this on this box:
		// an exact entry in vm/policy/core.hosts, and not in allow.domains
		// on purpose. There, a name includes its subdomains by design, and
		// this test would prove nothing.
		piIP := netenv(t)["PI_IP"]
		exact := mustSSH(t, "agent", "dig +short +time=5 +tries=2 A console.anthropic.com @"+piIP)
		if ip := firstIPv4(exact); ip == "" || ip == "0.0.0.0" {
			t.Fatalf("console.anthropic.com is an exact core.hosts entry and did not resolve under PARANOID=1: %q", exact)
		}
		sub := digA(t, "evil.console.anthropic.com", piIP)
		if len(sub) == 0 || sub[len(sub)-1] != "0.0.0.0" {
			t.Fatalf("evil.console.anthropic.com answered %v, not 0.0.0.0: an exact core.hosts entry is carrying its subdomains again (K9)", sub)
		}
		// Paranoid uses the path of the sinkhole, so the row says blocked
		// directly. A reader who must infer it from an answer of 0.0.0.0
		// would count a refused name as ordinary traffic.
		if tail := pi(t, "sudo cat /var/log/pi-fortress/dns.jsonl | tail -n 50"); !lineWith(tail, `"name":"evil.console.anthropic.com"`, `"act":"blocked"`) {
			t.Fatalf("the refused subdomain has no blocked row:\n%s", tail)
		}
	})

	houseIF := strings.TrimSpace(pi(t, "grep -hE '^HOUSE_IF=' /etc/pi-fortress/house.env 2>/dev/null | cut -d= -f2- | tr -d \"\\\"' \" || true"))
	if houseIF == "" {
		t.Log("no HOUSE_IF on this box: the house half of phase 2 is exercised in the cloud lab")
		return
	}

	t.Run("the house is a segment of the same daemon", func(t *testing.T) {
		if house == "" {
			t.Fatalf("HOUSE_IF=%s but no house segment in:\n%s", houseIF, check)
		}
		if !contains(house, "iface="+houseIF) {
			t.Fatalf("house segment is not on %s: %s", houseIF, house)
		}
	})

	// This pins the failure that is important: a house that feeds
	// resolved_v4 would open the agent gate for an address that only the
	// house asked about.
	t.Run("the house feeds its own set", func(t *testing.T) {
		if !contains(house, "set=resolved_house_v4") {
			t.Fatalf("house segment does not feed resolved_house_v4: %s", house)
		}
		if strings.Count(check, "set=resolved_v4\n")+strings.Count(check, "set=resolved_v4 ") > 1 {
			t.Fatalf("resolved_v4 is fed by more than one segment:\n%s", check)
		}
	})

	t.Run("the segments do not share an upstream or a log", func(t *testing.T) {
		field := func(line, key string) string {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, key+"=") {
					return strings.TrimPrefix(f, key+"=")
				}
			}
			return ""
		}
		// Whether the house has its own provider is the configuration of
		// the box, not a constant. With DoT on and no provider of its own,
		// the house shares the stub of the agents by design (pf render).
		// Then the same upstream is the correct answer, not the bug.
		own := strings.TrimSpace(pi(t, "grep -hE '^(HOUSE_DNS_UPSTREAM|HOUSE_DOT_IPS|WG_IF)=.' /etc/pi-fortress/house.env 2>/dev/null || true"))
		dot := strings.TrimSpace(pi(t, "grep -hE '^DOT_IPS=.' /etc/pi-fortress/net.env /etc/pi-fortress/net.env.local 2>/dev/null | tail -1 || true"))
		au, hu := field(agent, "upstream"), field(house, "upstream")
		switch {
		case own != "":
			if au != "" && au == hu {
				t.Fatalf("both segments forward to %s; the house has its own provider (%s)", au, own)
			}
		case dot != "":
			if au != "127.0.0.1:53" || hu != au {
				t.Fatalf("DoT is on and the house has no provider of its own, so both should forward to the stub at 127.0.0.1:53; agent=%s house=%s", au, hu)
			}
		}
	})

	// dnsmasq keeps DHCP by decision. port=0 makes that true, not only
	// intended: without it, dnsmasq and pf dns both want 53 on the house
	// address.
	t.Run("the house dnsmasq is DHCP only", func(t *testing.T) {
		conf := pi(t, "sudo cat /etc/pi-fortress/dns-house.conf")
		if !contains(conf, "port=0") {
			t.Fatalf("dns-house.conf has no port=0:\n%s", conf)
		}
		for _, dns := range []string{"nftset=", "server=", "conf-file=", "log-queries"} {
			if contains(conf, dns) {
				t.Fatalf("dns-house.conf still carries %q, so dnsmasq is still doing DNS:\n%s", dns, conf)
			}
		}
		// The DHCP half must stay intact: this is the full reason that
		// dnsmasq stays on the box.
		for _, want := range []string{"dhcp-range=", "dhcp-authoritative", "dhcp-leasefile="} {
			if !contains(conf, want) {
				t.Fatalf("dns-house.conf lost %q:\n%s", want, conf)
			}
		}
		if out := pi(t, "sudo dnsmasq --test --conf-file=/etc/pi-fortress/dns-house.conf 2>&1"); !contains(out, "syntax check OK") {
			t.Fatalf("dnsmasq --test on the DHCP-only conf: %s", out)
		}
	})

	// The resolver parses DNS from the wire from all segments, and is the
	// only thing that answers 53 on this box. Thus it gets the same
	// seccomp box that pf-broker and pf-engine (the same binary) already
	// run under. A resolve is also the nft set write: pf dns forks nft to
	// add the answer to resolved_v4, and that child is under this same
	// filter. If it dies, the 443 gate closes on a name that just
	// resolved. That is why the fetch below is part of this subtest, not
	// a separate one.
	t.Run("the resolver runs boxed in", func(t *testing.T) {
		since := piClock(t)
		pid, filter := unitSandbox(t, "pi-fortress-dns-agent-go", "pf-dns",
			capNetBindService|capNetAdmin|capNetRaw)
		// No @chown re-add, unlike the DHCP daemon: no code that pf dns
		// reaches chowns a file. It reopens its log with O_APPEND and
		// keeps the owner that apply.sh gave it.
		if slices.Contains(filter, "fchown") {
			t.Error("the resolver may fchown; pf dns chowns nothing, so @chown was re-added for no caller")
		}
		e := netenv(t)
		allow, piIP := e["ALLOW_DOMAIN"], e["PI_IP"]
		// A name that the resolver never saw, answered from
		// configuration, so that no packet leaves the box (the same
		// pf-open-echo.test fixture that the blocked-row subtest uses).
		// The set write occurs on a miss, not on a cache hit. Thus a name
		// already in the cache proves nothing, and an element left by an
		// earlier group lives two hours.
		fresh := "gate-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".pf-open-echo.test"
		ips := digA(t, fresh, piIP)
		if len(ips) == 0 {
			t.Fatalf("the agent segment stopped resolving: %s gave nothing", fresh)
		}
		eventually(t, 15*time.Second, func() string {
			if contains(pi(t, "sudo nft list set inet fortress resolved_v4"), ips[0]) {
				return ""
			}
			return "resolved_v4 has no " + ips[0] + " after the agent resolved " + fresh + "; the nft the resolver forks never ran"
		})
		// And the gate that set feeds, end to end.
		if a := digA(t, allow, piIP); len(a) == 0 || a[len(a)-1] == "0.0.0.0" {
			t.Fatalf("the agent segment stopped resolving %s: %v", allow, a)
		}
		if code := httpCode(t, "https://"+allow); !curlOK(code) {
			t.Fatalf("HTTPS to a name that just resolved gave %q; the 443 gate is that same set write", code)
		}
		pi(t, "sudo systemctl reload pi-fortress-dns-agent-go.service")
		if now := mainPID(t, "pi-fortress-dns-agent-go"); now != pid {
			t.Errorf("the resolver was pid %s and is now pid %s; it died and restarted during the resolve and reload", pid, now)
		}
		noSeccompKill(t, since, "pf", "nft")
	})

	// The loopback DoT stub: same binary and same account, one capability
	// fewer. It feeds no nft set, so it forks no nft. It is present only
	// when the box has DOT_IPS. The default lab does not.
	t.Run("the DoT stub runs boxed in", func(t *testing.T) {
		if mainPID(t, "pi-fortress-dns-stub@main") == "0" {
			t.Skip("no DoT stub on this box (no DOT_IPS)")
		}
		since := piClock(t)
		pid, _ := unitSandbox(t, "pi-fortress-dns-stub@main", "pf-dns",
			capNetBindService|capNetRaw)
		// Through the stub and out over TLS. On the Pi, not on the agent:
		// the lookups of the box go to 127.0.0.1, and the stub binds
		// nothing else.
		if ips := digOn(t, "pi", "one.one.one.one", "127.0.0.1"); len(ips) == 0 {
			t.Fatal("the stub answered nothing; the TLS dial is the first thing a filter breaks")
		}
		pi(t, "sudo systemctl reload pi-fortress-dns-stub@main.service")
		if now := mainPID(t, "pi-fortress-dns-stub@main"); now != pid {
			t.Errorf("the stub was pid %s and is now pid %s", pid, now)
		}
		noSeccompKill(t, since, "pf")
	})

	// a query to the Pi and its answer leave no conntrack
	// entry (render dnsNoTrack). Thus a flood under the meter cannot put
	// thousands of them in the table that the dials of the Pi also use.
	// The control is a lookup over lo, which stays tracked. It proves that
	// the listing can see an entry, so the zero is not a failed listing.
	t.Run("UDP DNS to the Pi takes no conntrack entry", func(t *testing.T) {
		e := netenv(t)
		count := func(port, dst string) string {
			out, err := ssh(t, 10*time.Second, "pi", "sudo conntrack -L -p udp --orig-port-src "+port+" --orig-dst "+dst+" 2>/dev/null | wc -l")
			if err != nil {
				t.Skipf("conntrack -L refused: %v %s", err, out)
			}
			return strings.TrimSpace(out)
		}
		pi(t, "dig +short +time=2 +tries=1 -b 127.0.0.1#53536 @127.0.0.1 example.com >/dev/null || true")
		if n := count("53536", "127.0.0.1"); n != "1" {
			t.Skipf("the tracked control over lo lists %s entries, so a zero below would prove nothing", n)
		}
		out, _ := ssh(t, 20*time.Second, "agent", "dig +short +time=2 +tries=1 -b "+e["AGENT_IP"]+"#53535 @"+e["PI_IP"]+" example.com")
		if strings.TrimSpace(out) == "" {
			t.Fatal("the agent's query went unanswered: the untracked answer is not getting out")
		}
		if n := count("53535", e["PI_IP"]); n != "0" {
			t.Fatalf("the agent's query to %s left %s conntrack entries, want 0", e["PI_IP"], n)
		}
	})

	t.Run("doctor reports DHCP and DNS separately", func(t *testing.T) {
		out := pi(t, "sudo /usr/local/sbin/pf doctor 2>&1 || true")
		if !contains(out, "dhcp") {
			t.Fatalf("no dhcp rung in doctor:\n%s", out)
		}
	})
}

// clientCounts is the slice of observe.Client the checklist measures.
// The three counters are omitempty in the state file, so a client that
// has nothing yet is a missing field and not a parse failure.
type clientCounts struct {
	IP       string `json:"ip"`
	Segment  string `json:"segment"`
	Queries  int    `json:"queries"`
	Blocked  int    `json:"blocked"`
	Filtered int    `json:"filtered"`
}

// observeCounts reads the counters of one client from the state file that
// pf tui renders. It finds the client by address, not by map key: the
// key is "<segment>/<ip>" today (internal/observe/observe.go). To write
// that out here would make this fail on a rename, not on a counter that
// stopped. Addresses do not repeat across the segments of the lab, so the
// address alone names one client.
//
// A client that observe did not see yet reads as three zeroes. That is
// the correct baseline: the delta that the caller asserts is exact in
// both cases.
//
// The state file, not the report of `pf observe once`, because the
// report prints q=, f= and b= and has no column for filtered at all
// (internal/observe/observe.go Show). A box that runs the itest sudo
// allowlist has no rule for this path (vm/pi/sudoers.d/pf-itest). Thus
// the read is refused there, and the caller skips, not fails. Add
// `/usr/bin/cat /var/lib/pi-fortress/observe/observe.json` to run it there.
// expiresIn is what nft says is left on addr in a `nft list set` listing,
// or zero when the set does not have it. The listing is read with the
// same parser that the carry of the apply uses. Thus a spelling that this
// box prints and that the carry would misread also fails here.
func expiresIn(listing, addr string) time.Duration {
	s, err := nftsets.ParseSet(listing)
	if err != nil {
		return 0
	}
	for _, e := range s.Elements {
		if e.Addr == addr {
			return e.Remaining
		}
	}
	return 0
}

func observeCounts(t *testing.T, ip string) clientCounts {
	t.Helper()
	var st struct {
		Clients map[string]clientCounts `json:"clients"`
	}
	raw := pi(t, "sudo cat /var/lib/pi-fortress/observe/observe.json")
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("observe.json is not the state pf tui reads: %v\n%s", err, raw)
	}
	for _, c := range st.Clients {
		if c.IP == ip {
			return c
		}
	}
	return clientCounts{IP: ip}
}
