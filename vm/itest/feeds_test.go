//go:build vagrant

package itest

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// feedsTests check the feed download on the live box. pf fetch runs in
// pi-fortress-feeds.service as pf-feeds with no capability. Root (pf feeds
// run, from apply or the TUI) starts it, and imports only the lists that
// pass the check of internal/feedstage. The subtests that change state
// (a held unit, a crafted stage, an apply) are lab only.
func feedsTests(t *testing.T) {
	t.Run("the unit has its sandbox", feedsUnitTests)
	t.Run("the running unit has no capability", labOnly(feedsLiveTests))
	t.Run("a refresh downloads as pf-feeds and keeps the canaries", feedsRefreshTests)
	t.Run("a bad staged line refuses the whole set", labOnly(feedsRefuseTests))
	t.Run("the unit reaches no segment", labOnly(feedsFenceTests))
	t.Run("two applies in 30 minutes reuse the copies", labOnly(feedsReuseTests))
}

const (
	feedsUnit  = "pi-fortress-feeds.service"
	feedsState = "/var/lib/pi-fortress-feeds"
	feedsDrop  = "/etc/systemd/system/pi-fortress-feeds.service.d/uplink.conf"
)

// feedsPolicyDir is base.PolicyDir on the box: the lab tree, the tree of
// a pf install box, or /etc/pi-fortress.
func feedsPolicyDir(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(pi(t, `d=/vagrant/vm/policy; [ -d "$d" ] || d=/opt/pi-fortress/vm/policy; [ -d "$d" ] || d=/etc/pi-fortress; echo "$d"`))
}

// showProps reads properties of a unit from systemd: the merged view, with
// the drop-ins.
func showProps(t *testing.T, unit string, props ...string) map[string]string {
	t.Helper()
	out := pi(t, "systemctl show "+unit+" -p "+strings.Join(props, " -p "))
	m := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// feedsFence is the RestrictNetworkInterfaces value of the uplink drop-in.
func feedsFence(t *testing.T) string {
	t.Helper()
	for line := range strings.SplitSeq(pi(t, "cat "+feedsDrop), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "RestrictNetworkInterfaces="); ok {
			return v
		}
	}
	t.Fatalf("%s has no RestrictNetworkInterfaces line", feedsDrop)
	return ""
}

// L1, static half: what systemd merged from the unit and its drop-in.
func feedsUnitTests(t *testing.T) {
	p := showProps(t, feedsUnit, "User", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges",
		"ProtectProc", "ProcSubset", "RestrictAddressFamilies", "ProtectSystem", "PrivateTmp",
		"StateDirectory", "RestrictNetworkInterfaces", "IPAddressDeny", "LoadState")
	for k, want := range map[string]string{
		"LoadState":               "loaded",
		"User":                    "pf-feeds",
		"CapabilityBoundingSet":   "",
		"AmbientCapabilities":     "",
		"NoNewPrivileges":         "yes",
		"ProtectProc":             "invisible",
		"ProcSubset":              "pid",
		"RestrictAddressFamilies": "AF_INET AF_INET6",
		"ProtectSystem":           "strict",
		"PrivateTmp":              "yes",
		"StateDirectory":          "pi-fortress-feeds",
	} {
		if got := p[k]; got != want {
			t.Errorf("%s %s=%q, want %q", feedsUnit, k, got, want)
		}
	}
	fence := strings.Fields(feedsFence(t))
	got := strings.Fields(p["RestrictNetworkInterfaces"])
	if len(got) == 0 || !strings.Contains(" "+strings.Join(got, " ")+" ", " lo ") {
		t.Errorf("%s RestrictNetworkInterfaces=%q: the drop-in %v did not reach systemd", feedsUnit, p["RestrictNetworkInterfaces"], fence)
	}
	for _, i := range fence {
		if !strings.Contains(" "+p["RestrictNetworkInterfaces"]+" ", " "+i+" ") {
			t.Errorf("%s RestrictNetworkInterfaces=%q lacks %s of the drop-in", feedsUnit, p["RestrictNetworkInterfaces"], i)
		}
	}
	if p["IPAddressDeny"] == "" {
		t.Errorf("%s has no IPAddressDeny", feedsUnit)
	}
	if mode := strings.TrimSpace(pi(t, "sudo stat -c %a "+feedsState)); mode != "700" {
		t.Errorf("%s has mode %s, want 700", feedsState, mode)
	}
	t.Logf("systemd-analyze security: %s",
		strings.TrimSpace(pi(t, "systemd-analyze security "+feedsUnit+" --no-pager 2>/dev/null | tail -1 || true")))
}

// L1, live half: a process of the unit, as the kernel sees it. A runtime
// drop-in holds the unit in ExecStartPre (same user and sandbox) for a few
// seconds. The cleanup stops the unit before its download.
func feedsLiveTests(t *testing.T) {
	const hold = "/run/systemd/system/pi-fortress-feeds.service.d/zz-itest-hold.conf"
	pi(t, `sudo sh -c 'mkdir -p `+hold[:strings.LastIndex(hold, "/")]+` && printf "[Service]\nExecStartPre=/bin/sleep 20\n" > `+hold+` && systemctl daemon-reload'`)
	t.Cleanup(func() {
		_, _ = ssh(t, 30*time.Second, "pi", "sudo sh -c 'systemctl stop "+feedsUnit+"; rm -f "+hold+"; systemctl daemon-reload'")
	})
	pi(t, "sudo systemctl start --no-block "+feedsUnit)
	pid := ""
	for range 20 {
		pid = strings.TrimSpace(pi(t, "systemctl show -p ControlPID --value "+feedsUnit))
		if pid != "" && pid != "0" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if pid == "" || pid == "0" {
		t.Fatalf("%s did not start", feedsUnit)
	}
	status := pi(t, "sudo cat /proc/"+pid+"/status")
	if got, want := procStatus(status, "Uid"), strings.TrimSpace(pi(t, "id -u pf-feeds")); got != want {
		t.Errorf("%s runs as uid %q, want %q (pf-feeds)", feedsUnit, got, want)
	}
	boxedStatus(t, feedsUnit, status, 0)
	if got := procStatus(status, "CapBnd"); strings.Trim(got, "0") != "" {
		t.Errorf("%s bounding set is %s, want 0", feedsUnit, got)
	}
}

// L3: the timer path. The download runs in the unit, root imports, and
// the canaries are still blocked. It downloads the feeds of sources.json,
// the same hosts as each apply before.
func feedsRefreshTests(t *testing.T) {
	since := strings.TrimSpace(pi(t, "date +%s"))
	if out, err := ssh(t, 16*time.Minute, "pi", "sudo systemctl start pi-fortress-fetch.service"); err != nil {
		t.Fatalf("refresh: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(pi(t, "systemctl show -p Result --value pi-fortress-fetch.service")); got != "success" {
		t.Fatalf("refresh result %q", got)
	}
	j := pi(t, "sudo journalctl -u "+feedsUnit+" --since @"+since+" -o cat --no-pager | tail -40")
	if !contains(j, "OK ") && !contains(j, "STALE ") {
		t.Errorf("the journal of %s has no feed line since the refresh began:\n%s", feedsUnit, j)
	}
	p := feedsPolicyDir(t)
	if got := strings.Fields(pi(t, "sudo stat -c %U "+p+"/generated/blacklist.ips "+p+"/generated/blacklist.domains")); strings.Join(got, " ") != "root root" {
		t.Errorf("generated lists are owned by %v, want root", got)
	}
	if got := strings.TrimSpace(pi(t, "sudo stat -c %U "+feedsState+"/stage/run")); got != "pf-feeds" {
		t.Errorf("the stage is owned by %q, want pf-feeds", got)
	}
	if head := pi(t, "sudo head -1 "+p+"/generated/fetch.report"); strings.HasPrefix(head, "FAIL stage") || strings.HasPrefix(head, "FAIL download") {
		t.Errorf("the refresh did not import its set: %s", head)
	}
	if out, err := ssh(t, 15*time.Second, "pi", "sudo nft get element inet fortress blacklist_v4 '{ 192.0.2.1 }'"); err != nil {
		t.Errorf("the canary 192.0.2.1 is not in blacklist_v4 after the refresh: %v\n%s", err, out)
	}
	if out := agent(t, "dig +short +time=3 +tries=2 pi-fortress-block.test"); strings.TrimSpace(out) != "0.0.0.0" {
		t.Errorf("pi-fortress-block.test resolves to %q after the refresh, want 0.0.0.0", strings.TrimSpace(out))
	}
}

// feedsScratch copies the policy files that the download and the import
// read into a scratch policy directory on the box, and gives its path.
// The cleanup removes it.
func feedsScratch(t *testing.T) string {
	t.Helper()
	const s = "/var/lib/pi-fortress/itest-feeds-policy"
	p := feedsPolicyDir(t)
	pi(t, "sudo sh -c 'rm -rf "+s+" && mkdir -p "+s+"/generated && cp "+p+"/sources.json "+s+"/ && "+
		"for f in never_block.ips never_block.domains house_never_block.domains; do [ ! -f "+p+"/$f ] || cp "+p+"/$f "+s+"/; done && "+
		"for f in blacklist.ips blacklist.domains house.domains house_vpn.domains feeds.map sample.domain eyeball.table; do [ ! -f "+p+"/generated/$f ] || cp "+p+"/generated/$f "+s+"/generated/; done'")
	t.Cleanup(func() { _, _ = ssh(t, 20*time.Second, "pi", "sudo rm -rf "+s) })
	return s
}

func listsHash(t *testing.T, dir string) string {
	t.Helper()
	return pi(t, "sudo find "+dir+"/generated -type f ! -name fetch.report -exec sha256sum {} + | sort")
}

// L4: a stage with rule text in one line. pf feeds import refuses the
// whole set; the lists of the scratch policy and the loaded ruleset stay
// byte for byte. The next download clears the stage.
func feedsRefuseTests(t *testing.T) {
	s := feedsScratch(t)
	before, rules := listsHash(t, s), rulesetState(t)
	const run = "0123456789abcdef0123456789abcdef"
	stage := feedsState + "/stage"
	pi(t, "sudo setpriv --reuid=pf-feeds --regid=pf-feeds --clear-groups sh -c "+shellQuote(
		"mkdir -p "+stage+" && printf '192.0.2.1\\n192.0.2.2 } ; flush ruleset\\n' > "+stage+"/blacklist.ips && printf '"+run+"\\n' > "+stage+"/run"))
	out, err := ssh(t, 60*time.Second, "pi", "sudo pf feeds import -run "+run+" -policy "+s)
	if err == nil {
		t.Fatalf("pf feeds import took a stage with rule text:\n%s", out)
	}
	if !contains(out, "FAIL stage: blacklist.ips: line 2") || contains(out, "flush") {
		t.Errorf("the refusal does not name the line, or it quotes it:\n%s", out)
	}
	if after := listsHash(t, s); after != before {
		t.Errorf("a refused set changed the lists:\nbefore %s\nafter  %s", before, after)
	}
	if rulesetState(t) != rules {
		t.Error("a refused set changed the loaded ruleset")
	}
	if head := pi(t, "sudo head -1 "+s+"/generated/fetch.report"); !strings.HasPrefix(head, "FAIL stage") {
		t.Errorf("report starts with %q", head)
	}
}

// L6: the unit may use lo and the uplink only. A dial from pf-feeds with
// the fence of the unit to the agent VM on port 22 gets no answer (the
// fence drops it with no error); the same dial with no fence connects.
// systemd-run takes the fence of the drop-in, not the unit itself: the
// unit runs pf fetch only.
func feedsFenceTests(t *testing.T) {
	needHost(t, "agent")
	agentIP := netenv(t)["AGENT_IP"]
	dial := "/usr/bin/timeout 8 /bin/bash -c " + shellQuote("</dev/tcp/"+agentIP+"/22 && echo REACHED")
	base := "sudo systemd-run --wait --pipe --quiet -p User=pf-feeds -p 'RestrictAddressFamilies=AF_INET AF_INET6' "
	fenced, _ := ssh(t, 30*time.Second, "pi", base+"-p "+shellQuote("RestrictNetworkInterfaces="+feedsFence(t))+" "+dial)
	if contains(fenced, "REACHED") {
		t.Errorf("pf-feeds with the fence of the unit reached the agent %s:22", agentIP)
	}
	open, _ := ssh(t, 30*time.Second, "pi", base+dial)
	if !contains(open, "REACHED") {
		t.Errorf("control: pf-feeds with no fence did not reach the agent %s:22, so the check above proves nothing:\n%s", agentIP, open)
	}
}

// L7: a full apply reuses a last-good copy that is less than 30 minutes
// old, and the copies belong to pf-feeds.
func feedsReuseTests(t *testing.T) {
	piApply(t, "sudo pf apply")
	piApply(t, "sudo pf apply")
	p := feedsPolicyDir(t)
	if n, _ := strconv.Atoi(strings.TrimSpace(pi(t, "sudo grep -c 'not downloaded again' "+p+"/generated/fetch.report || true"))); n == 0 {
		t.Errorf("the second apply in 30 minutes downloaded again:\n%s", pi(t, "sudo cat "+p+"/generated/fetch.report"))
	}
	if got := strings.Fields(pi(t, "sudo sh -c 'stat -c %U "+feedsState+"/cache/*.list | sort -u'")); strings.Join(got, " ") != "pf-feeds" {
		t.Errorf("the last-good copies are owned by %v, want pf-feeds", got)
	}
}
