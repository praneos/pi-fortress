//go:build vagrant

package itest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ntpProbePath is where ntpProbe puts the client on a lab VM.
const ntpProbePath = "/tmp/pf-ntpprobe"

// ntpProbe builds vm/itest/ntpprobe for the architecture of each VM that
// asks, and copies it there one time. The lab clients have no NTP tool,
// and the tests must not install one from the internet.
func ntpProbe(t *testing.T) func(vm string) string {
	t.Helper()
	dir := t.TempDir()
	var mu sync.Mutex
	built := map[string]string{}
	copied := map[string]bool{}
	return func(vm string) string {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if copied[vm] {
			return ntpProbePath
		}
		arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(mustSSH(t, vm, "uname -m"))]
		if arch == "" {
			t.Fatalf("%s: no Go architecture for its uname -m", vm)
		}
		bin, ok := built[arch]
		if !ok {
			bin = filepath.Join(dir, "ntpprobe-"+arch)
			if out, err := run(t, 3*time.Minute, "env", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0",
				"go", "build", "-trimpath", "-o", bin, "./vm/itest/ntpprobe"); err != nil {
				t.Fatalf("build ntpprobe for %s: %v\n%s", arch, err, out)
			}
			built[arch] = bin
		}
		f, err := os.Open(bin)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ssh", "-F", sshCfg, "-o", "BatchMode=yes", vm,
			"cat > "+ntpProbePath+".new && chmod 0755 "+ntpProbePath+".new && mv "+ntpProbePath+".new "+ntpProbePath)
		cmd.Stdin = f
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("copy ntpprobe to %s: %v\n%s", vm, err, out)
		}
		copied[vm] = true
		return ntpProbePath
	}
}

var reNTPReply = regexp.MustCompile(`^reply from=(\S+) leap=(\d) version=\d mode=4 stratum=(\d+) refid=(\S+) size=\d+ offset=(\S+)$`)

// ntpQuery asks addr from vm and gives the reply line, or "" with no reply.
func ntpQuery(t *testing.T, probe func(string) string, vm, addr string) string {
	t.Helper()
	out, err := ssh(t, 30*time.Second, vm, probe(vm)+" query -timeout 3s -tries 2 "+addr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// gwRefID is the reference ID of the clock of the gateway, as the address
// that chronyc tracking shows in brackets.
func gwRefID(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`Reference ID\s*:\s*[0-9A-F]{8} \(([^)]*)\)`).FindStringSubmatch(pi(t, "sudo chronyc -n tracking"))
	if m == nil {
		return ""
	}
	return m[1]
}

// ntpRedirects is the packet counter of the NTP redirect to gw in nat
// prerouting. Under NTP=pass, the rule also keeps ntp_pass_v4 out.
func ntpRedirects(t *testing.T, gw string) int {
	t.Helper()
	m := regexp.MustCompile(`udp dport 123 ip daddr != ` + regexp.QuoteMeta(gw) + ` (?:ip daddr != @ntp_pass_v4 )?counter packets (\d+) `).FindStringSubmatch(pi(t, "sudo nft list chain inet fortress prerouting"))
	if m == nil {
		t.Fatalf("no NTP redirect to %s in nat prerouting", gw)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// ntpTests: the gateway is the only NTP server of the house and of the
// desk. A query to any address gets the answer of chrony on the gateway,
// and the uplink never carries it. 216.239.35.4 is time.google.com, which
// the gateway itself never asks. 192.0.2.1 is on the lab blacklist, and is
// TEST-NET: the blacklist drops a query to it before the redirect, so it
// gets no answer at all. The agent network gets no NTP at all.
func ntpTests(t *testing.T) {
	needHost(t, "house", "desk")
	e := netenv(t)
	houseGW, houseNet := e["LAB_HOUSE_IP"], e["LAB_HOUSE_NET"]
	deskGW, deskNet := e["DESK_IP"], e["DESK_NET"]
	piIP, agentNet := e["PI_IP"], e["AGENT_NET"]
	probe := ntpProbe(t)
	// An apply that changed chrony.conf restarted chrony. Its replies say
	// "unsynced" until it has a clock again.
	eventuallyEvery(t, 3*time.Minute, 5*time.Second, func() string {
		if out, _ := ssh(t, 15*time.Second, "pi", "sudo chronyc -n tracking"); !lineWith(out, "Leap status", "Normal") {
			return "chrony on the gateway is not synced:\n" + out
		}
		return ""
	})

	t.Run("chrony serves the house and the desk only", func(t *testing.T) {
		conf := pi(t, "sudo grep -E '^(allow|deny|local|ratelimit|cmdport|bindcmdaddress)' /etc/chrony/chrony.conf")
		for _, want := range []string{"allow " + houseNet, "allow " + deskNet, "ratelimit interval 1 burst 8", "cmdport 0", "bindcmdaddress 127.0.0.1"} {
			if !lineWith(conf, want) {
				t.Errorf("chrony.conf lacks %q:\n%s", want, conf)
			}
		}
		if strings.Contains(conf, agentNet) || regexp.MustCompile(`(?m)^(local|allow all|allow$)`).MatchString(conf) {
			t.Errorf("chrony.conf serves the agents, all, or an unsynced clock:\n%s", conf)
		}
		if ss := pi(t, "sudo ss -H -ulpn 'sport = :123'"); !strings.Contains(ss, "chronyd") {
			t.Errorf("chronyd does not hold UDP 123:\n%s", ss)
		}
	})

	for _, c := range []struct{ vm, gw string }{{"house", houseGW}, {"desk", deskGW}} {
		t.Run(c.vm+" gets NTP from the gateway for any address", func(t *testing.T) {
			wan := ""
			if f := strings.Fields(pi(t, "ip -4 route show default")); len(f) > 4 && f[3] == "dev" {
				wan = f[4]
			}
			if wan == "" {
				t.Fatal("no default route on the gateway")
			}
			before := ntpRedirects(t, c.gw)
			// The capture runs while the client asks. It counts NTP to the two
			// outside addresses on the uplink.
			var seen string
			var capErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				seen, capErr = sshNoSkip(t, 40*time.Second, "pi", "sudo timeout 25 tcpdump -i "+wan+" -n -l 'udp port 123 and (host 192.0.2.1 or host 216.239.35.4)' 2>/dev/null | grep -c ' IP ' || true")
			})
			time.Sleep(3 * time.Second)
			eventuallyEvery(t, 2*time.Minute, 5*time.Second, func() string {
				ref := gwRefID(t)
				for _, dst := range []string{"216.239.35.4", c.gw} {
					line := ntpQuery(t, probe, c.vm, dst)
					m := reNTPReply.FindStringSubmatch(line)
					if m == nil {
						return fmt.Sprintf("%s: no NTP reply for %s: %q", c.vm, dst, line)
					}
					if m[1] != dst+":123" {
						return fmt.Sprintf("%s: the reply for %s came from %s", c.vm, dst, m[1])
					}
					if m[2] == "3" || m[3] == "0" || m[3] == "16" {
						return fmt.Sprintf("%s: the reply for %s is from an unsynced server (is chrony on the gateway synced?): %s", c.vm, dst, line)
					}
					if ref == "" || m[4] != ref {
						return fmt.Sprintf("%s: the reply for %s has refid %s, the gateway tracks %q: %s", c.vm, dst, m[4], ref, line)
					}
				}
				return ""
			})
			wg.Wait()
			sudoSkip(t, "pi", "tcpdump", capErr)
			if capErr != nil {
				t.Fatalf("the uplink capture failed: %v", capErr)
			}
			if n := strings.TrimSpace(seen); n != "0" {
				t.Errorf("the uplink %s carried %s NTP packets of the %s", wan, n, c.vm)
			}
			if after := ntpRedirects(t, c.gw); after < before+1 {
				t.Errorf("the NTP redirect to %s counted %d to %d packets, want 1 more at least", c.gw, before, after)
			}
		})
		t.Run(c.vm+" NTP to a blacklisted address is dropped, not answered", func(t *testing.T) {
			since := piClock(t)
			if line := ntpQuery(t, probe, c.vm, "192.0.2.1"); reNTPReply.MatchString(line) {
				t.Fatalf("%s: NTP to 192.0.2.1 got a reply: %q", c.vm, line)
			}
			kernLog(t, since, "pi-fortress "+c.vm+"-blacklist: ", "DST=192.0.2.1 ", "DPT=123 ")
		})
	}

	t.Run("NTS key exchange does not leave the house or the desk", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "house", "nc -z -w3 162.159.200.1 4460")
		mustFailOn(t, "desk", "nc -z -w3 162.159.200.1 4460")
		if strings.Contains(pi(t, "sudo nft list chain inet fortress house_egress 2>/dev/null || true"), "house-port") {
			kernLog(t, since, "pi-fortress house-port: ", "DST=162.159.200.1 ", "DPT=4460 ")
		}
	})

	// The lock of the agent VM drops these before they leave it. Thus the
	// probe lifts the lock, and the gateway must drop and log them.
	t.Run("the agent gets no NTP", func(t *testing.T) {
		liftAgentLock(t)
		since := piClock(t)
		for _, dst := range []string{"192.0.2.1", piIP} {
			if line := ntpQuery(t, probe, "agent", dst); line != "" && line != "no reply" {
				t.Errorf("agent: NTP to %s got %q", dst, line)
			}
		}
		mustFailOn(t, "agent", "nc -z -w3 192.0.2.1 4460")
		kernLog(t, since, "pi-fortress agent-blacklist: ", "DST=192.0.2.1 ", "DPT=123 ")
		kernLog(t, since, "pi-fortress agent-blacklist: ", "DST=192.0.2.1 ", "DPT=4460 ")
		kernLog(t, since, "pi-fortress agent-drop: ", "DST="+piIP+" ", "DPT=123 ")
		// Each NTP rule of nat prerouting and input is for the house or the
		// desk address. A rule that drops (the meter for each source) gives
		// NTP to nobody, so it can be on any interface.
		for _, ch := range []string{"prerouting", "input"} {
			for l := range strings.SplitSeq(pi(t, "sudo nft list chain inet fortress "+ch), "\n") {
				if strings.HasSuffix(strings.TrimSpace(l), " drop") {
					continue
				}
				if strings.Contains(l, "dport 123") && !strings.Contains(l, " "+houseGW+" ") && !strings.Contains(l, " "+deskGW+" ") &&
					!strings.HasSuffix(l, " "+houseGW) && !strings.HasSuffix(l, " "+deskGW) {
					t.Errorf("%s: an NTP rule that is not for the house or the desk: %s", ch, strings.TrimSpace(l))
				}
			}
		}
	})

	t.Run("NTP=pass on the desk reaches ntp_pass.ips only", func(t *testing.T) {
		ntpPassTests(t, probe, deskGW)
	})
}

// deskNTPBackup is the desk segment file while ntpPassTests runs. It is
// not the backup of deskInspectTests, so the two groups never restore the
// file of the other.
const deskNTPBackup = "/var/lib/pi-fortress/itest-desk-ntp.env"

// ntpPassTests sets NTP=pass on the desk for its run. NTP to
// 216.239.35.4 (time.google.com, in the shipped ntp_pass.ips) then leaves
// the uplink and gets an answer that is not the clock of the gateway. NTS
// key exchange to 162.159.200.1 (time.cloudflare.com, in the list) leaves
// the uplink. 216.239.32.10 is a Google address that is not a time server
// and not in the list (nor in doh.ips, whose raw drop would hide the
// redirect): NTP to it still gets the answer of the gateway, and NTS key
// exchange to it does not leave. NTS key exchange to example.com, which
// the desk resolves, meets the strict egress drop. 192.0.2.1 is still
// dropped by the blacklist. The cleanup puts the file back, applies, and
// waits until the gateway answers the NTP of the desk to 216.239.35.4
// again.
func ntpPassTests(t *testing.T, probe func(string) string, gw string) {
	arm := strings.Join([]string{
		"set -e",
		"[ -e " + deskNTPBackup + " ] || cp -p " + deskSegFile + " " + deskNTPBackup,
		"grep -v '^NTP=' " + deskNTPBackup + " > " + deskSegFile,
		"echo NTP=pass >> " + deskSegFile,
	}, "; ")
	pi(t, "sudo sh -c "+shellQuote(arm))
	t.Cleanup(func() { restoreDeskNTP(t, probe) })
	if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
		t.Fatalf("pf apply --local with NTP=pass: %v\n%s", err, out)
	}
	if set := pi(t, "sudo nft list set inet fortress ntp_pass_v4"); !strings.Contains(set, "216.239.35.4") || !strings.Contains(set, "162.159.200.1") || strings.Contains(set, "216.239.32.10") {
		t.Fatalf("ntp_pass_v4 must hold 216.239.35.4 and 162.159.200.1, and not 216.239.32.10:\n%s", set)
	}
	if pre := pi(t, "sudo nft list chain inet fortress prerouting"); !strings.Contains(pre, "udp dport 123 ip daddr != "+gw+" ip daddr != @ntp_pass_v4 ") {
		t.Fatalf("no NTP redirect of the desk that keeps ntp_pass_v4 out:\n%s", pre)
	}
	wan := ""
	if f := strings.Fields(pi(t, "ip -4 route show default")); len(f) > 4 && f[3] == "dev" {
		wan = f[4]
	}
	if wan == "" {
		t.Fatal("no default route on the gateway")
	}

	t.Run("NTP to a listed server leaves and gets its answer", func(t *testing.T) {
		var seen string
		var capErr error
		var wg sync.WaitGroup
		wg.Go(func() {
			seen, capErr = sshNoSkip(t, 50*time.Second, "pi", "sudo timeout 35 tcpdump -i "+wan+" -n -l 'udp port 123 and host 216.239.35.4' 2>/dev/null | grep -c ' IP ' || true")
		})
		time.Sleep(3 * time.Second)
		eventuallyEvery(t, 30*time.Second, 5*time.Second, func() string {
			ref := gwRefID(t)
			line := ntpQuery(t, probe, "desk", "216.239.35.4")
			m := reNTPReply.FindStringSubmatch(line)
			if m == nil {
				return fmt.Sprintf("desk: no NTP reply for 216.239.35.4: %q", line)
			}
			if m[1] != "216.239.35.4:123" || m[2] == "3" || m[3] == "0" || m[3] == "16" {
				return "desk: not a synced reply of 216.239.35.4: " + line
			}
			if m[3] != "1" && ref != "" && m[4] == ref {
				return fmt.Sprintf("desk: the reply for 216.239.35.4 has the refid of the gateway (%s): %s", ref, line)
			}
			return ""
		})
		wg.Wait()
		sudoSkip(t, "pi", "tcpdump", capErr)
		if capErr != nil {
			t.Fatalf("the uplink capture failed: %v", capErr)
		}
		if n, _ := strconv.Atoi(strings.TrimSpace(seen)); n < 2 {
			t.Errorf("the uplink %s carried %q NTP packets to or from 216.239.35.4, want a query and its reply", wan, strings.TrimSpace(seen))
		}
	})

	t.Run("NTP to an address not on the list still goes to the gateway", func(t *testing.T) {
		before := ntpRedirects(t, gw)
		eventuallyEvery(t, time.Minute, 5*time.Second, func() string {
			ref := gwRefID(t)
			line := ntpQuery(t, probe, "desk", "216.239.32.10")
			m := reNTPReply.FindStringSubmatch(line)
			if m == nil {
				return fmt.Sprintf("desk: no NTP reply for 216.239.32.10: %q", line)
			}
			if m[1] != "216.239.32.10:123" || ref == "" || m[4] != ref {
				return fmt.Sprintf("desk: the reply for 216.239.32.10 is not the gateway (refid %q): %s", ref, line)
			}
			return ""
		})
		if after := ntpRedirects(t, gw); after < before+1 {
			t.Errorf("the NTP redirect to %s counted %d to %d packets, want 1 more at least", gw, before, after)
		}
	})

	t.Run("NTP to a blacklisted address is still dropped", func(t *testing.T) {
		since := piClock(t)
		if line := ntpQuery(t, probe, "desk", "192.0.2.1"); reNTPReply.MatchString(line) {
			t.Fatalf("desk: NTP to 192.0.2.1 got a reply: %q", line)
		}
		kernLog(t, since, "pi-fortress desk-blacklist: ", "DST=192.0.2.1 ", "DPT=123 ")
	})

	t.Run("NTS key exchange to a listed server leaves the gateway", func(t *testing.T) {
		// Only the uplink of the gateway is checked: a network behind it can
		// still drop TCP 4460.
		var seen string
		var capErr error
		var wg sync.WaitGroup
		wg.Go(func() {
			seen, capErr = sshNoSkip(t, 30*time.Second, "pi", "sudo timeout 15 tcpdump -i "+wan+" -n -l 'tcp dst port 4460 and dst host 162.159.200.1' 2>/dev/null | grep -c ' IP ' || true")
		})
		time.Sleep(3 * time.Second)
		_, _ = ssh(t, 20*time.Second, "desk", "nc -z -w5 162.159.200.1 4460")
		wg.Wait()
		sudoSkip(t, "pi", "tcpdump", capErr)
		if capErr != nil {
			t.Fatalf("the uplink capture failed: %v", capErr)
		}
		if n, _ := strconv.Atoi(strings.TrimSpace(seen)); n < 1 {
			t.Errorf("the uplink %s carried no TCP 4460 to 162.159.200.1", wan)
		}
	})

	t.Run("NTS key exchange to an address not on the list does not leave", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "desk", "nc -z -w3 216.239.32.10 4460")
		kernLog(t, since, "pi-fortress desk-directip: ", "DST=216.239.32.10 ", "DPT=4460 ")
		// example.com resolves on the desk, so the gate lets it pass. The
		// strict egress of the desk drops it.
		since = piClock(t)
		mustFailOn(t, "desk", "nc -z -w3 example.com 4460")
		kernLog(t, since, "pi-fortress desk-port: ", "DPT=4460 ")
	})
}

// restoreDeskNTP puts the desk segment file back from deskNTPBackup and
// applies. Then it waits until the gateway answers the NTP of the desk to
// 216.239.35.4 again: the apply ends the NTP flows of the desk (its egress
// fingerprint changed), and the next group must start with the redirect.
func restoreDeskNTP(t *testing.T, probe func(string) string) {
	t.Helper()
	out, err := ssh(t, 15*time.Second, "pi", "sudo sh -c "+shellQuote("set -e; [ -e "+deskNTPBackup+" ] || exit 0; cat "+deskNTPBackup+" > "+deskSegFile+"; cmp -s "+deskNTPBackup+" "+deskSegFile+"; rm -f "+deskNTPBackup+"; echo restored"))
	if err != nil {
		t.Errorf("the desk segment file was not restored from %s: %v\n%s", deskNTPBackup, err, out)
		return
	}
	if !contains(out, "restored") {
		return
	}
	if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
		t.Errorf("pf apply --local after the desk restore: %v\n%s", err, out)
		return
	}
	eventuallyEvery(t, 2*time.Minute, 5*time.Second, func() string {
		ref := gwRefID(t)
		line := ntpQuery(t, probe, "desk", "216.239.35.4")
		m := reNTPReply.FindStringSubmatch(line)
		if m == nil || ref == "" || m[4] != ref {
			return fmt.Sprintf("after the restore, the gateway does not answer the desk for 216.239.35.4 (refid %q): %q", ref, line)
		}
		return ""
	})
}

// ntpFuzzOptIn runs the NTP fuzz only with PF_E2E_FUZZ_NTP=1, and only on
// a lab gateway: it sends some hundred thousand malformed packets.
func ntpFuzzOptIn(fn func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		if os.Getenv("PF_E2E_FUZZ_NTP") != "1" {
			t.Skip("fuzzes chrony on the gateway for 5 minutes: PF_E2E_FUZZ_NTP=1 to run it")
		}
		if target() == "pi" {
			t.Skip("lab gateway only")
		}
		fn(t)
	}
}

// ntpFuzzStats is the JSON line of ntpprobe fuzz.
type ntpFuzzStats struct {
	Seconds       float64          `json:"seconds"`
	Sent          int64            `json:"sent"`
	SentBytes     int64            `json:"sent_bytes"`
	SendErrors    int64            `json:"send_errors"`
	ByKind        map[string]int64 `json:"sent_by_kind"`
	Replies       int64            `json:"replies"`
	Matched       int64            `json:"matched"`
	MaxRatio      float64          `json:"max_ratio"`
	MaxReply      int              `json:"max_reply"`
	MaxUnmatched  int              `json:"max_unmatched"`
	Mode67Replies int64            `json:"mode67_replies"`
	KoD           int64            `json:"kod"`
}

// ntpFuzzTests is a black-box fuzz of chrony on the house address of the
// gateway, from the house VM: random datagrams of 0 to 1500 bytes, each
// version and mode, truncated headers, bad and NTS-shaped extension fields,
// MAC tails, mutations of a valid request, and mode 6 and mode 7 queries.
// PF_NTP_FUZZ_DURATION (default 5m) and PF_NTP_FUZZ_RATE (default 2000
// packets a second) set the run. chronyd must stay the same process, log
// no error, answer no mode 6 or mode 7 packet, send no reply larger than
// its request, keep its memory, and answer a valid query after.
func ntpFuzzTests(t *testing.T) {
	needHost(t, "house")
	e := netenv(t)
	gw := e["LAB_HOUSE_IP"]
	dur, rate := os.Getenv("PF_NTP_FUZZ_DURATION"), os.Getenv("PF_NTP_FUZZ_RATE")
	if dur == "" {
		dur = "5m"
	}
	if rate == "" {
		rate = "2000"
	}
	d, err := time.ParseDuration(dur)
	if err != nil {
		t.Fatal("PF_NTP_FUZZ_DURATION: ", err)
	}
	r, err := strconv.Atoi(rate)
	if err != nil || r < 1 || r > 2000 {
		t.Fatal("PF_NTP_FUZZ_RATE must be 1 to 2000")
	}
	probe := ntpProbe(t)
	bin := probe("house")
	rss := func(pid string) int {
		n, _ := strconv.Atoi(procStatus(pi(t, "cat /proc/"+pid+"/status"), "VmRSS"))
		return n
	}
	restarts := func() string { return strings.TrimSpace(pi(t, "systemctl show -p NRestarts --value chrony.service")) }
	pid, nr := mainPID(t, "chrony"), restarts()
	if pid == "0" || pid == "" {
		t.Fatal("chrony is not running on the gateway")
	}
	rssBefore := rss(pid)
	since := piClock(t)

	var out string
	var fuzzErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		out, fuzzErr = sshNoSkip(t, d+3*time.Minute, "house", bin+" fuzz -target "+gw+" -rate "+strconv.Itoa(r)+" -duration "+d.String())
	})
	// Memory of chronyd during the run, each 30 s.
	samples := []int{rssBefore}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	tick := time.NewTicker(30 * time.Second)
wait:
	for {
		select {
		case <-done:
			break wait
		case <-tick.C:
			samples = append(samples, rss(pid))
		}
	}
	tick.Stop()
	if fuzzErr != nil {
		t.Fatalf("ntpprobe fuzz: %v\n%s", fuzzErr, out)
	}
	var s ntpFuzzStats
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		t.Fatalf("ntpprobe fuzz output: %v\n%s", err, out)
	}
	rssAfter := rss(pid)
	samples = append(samples, rssAfter)
	t.Logf("fuzz: %d packets (%d bytes, %d send errors) in %.0f s; by kind %v", s.Sent, s.SentBytes, s.SendErrors, s.Seconds, s.ByKind)
	t.Logf("fuzz: %d replies (%d matched), max reply %d bytes, max reply/request %.3f, max unmatched %d bytes, %d mode 6/7 replies, %d KoD",
		s.Replies, s.Matched, s.MaxReply, s.MaxRatio, s.MaxUnmatched, s.Mode67Replies, s.KoD)
	t.Logf("chronyd pid %s; VmRSS kB during the run: %v", pid, samples)

	if want := int64(float64(r) * d.Seconds() * 0.9); s.Sent < want {
		t.Errorf("sent %d packets, want %d at least", s.Sent, want)
	}
	if s.Mode67Replies != 0 {
		t.Errorf("chrony answered %d mode 6 or mode 7 packets", s.Mode67Replies)
	}
	if s.MaxRatio > 1 {
		t.Errorf("a reply was %.3f times the size of its request", s.MaxRatio)
	}
	// A reply that matches no request: chrony answers no request under 48
	// bytes, so a larger reply could amplify.
	if s.MaxUnmatched > 48 {
		t.Errorf("an unmatched reply of %d bytes", s.MaxUnmatched)
	}
	if now := mainPID(t, "chrony"); now != pid {
		t.Errorf("chronyd was pid %s, now %s", pid, now)
	}
	if now := restarts(); now != nr {
		t.Errorf("chrony.service NRestarts %s, now %s", nr, now)
	}
	if j, _ := ssh(t, 20*time.Second, "pi", "sudo journalctl -u chrony.service --since '"+since+"' -p warning --no-pager -o cat"); strings.TrimSpace(j) != "" && !strings.Contains(j, "-- No entries --") {
		t.Errorf("chrony logged warnings during the fuzz:\n%s", j)
	}
	if k, _ := ssh(t, 20*time.Second, "pi", "sudo journalctl -k --since '"+since+"' --no-pager -o cat -g 'chronyd'"); strings.Contains(k, "segfault") || strings.Contains(k, "traps:") {
		t.Errorf("the kernel logged a chronyd fault:\n%s", k)
	}
	if c, _ := ssh(t, 20*time.Second, "pi", "sudo ls /var/lib/systemd/coredump 2>/dev/null | grep -c chronyd || true"); strings.TrimSpace(c) != "0" && strings.TrimSpace(c) != "" {
		t.Errorf("a chronyd core dump on the gateway: %s", c)
	}
	// clientloglimit gives the client log a fixed size. 8 MiB is far above
	// what that log can use.
	if rssAfter-rssBefore > 8192 {
		t.Errorf("chronyd VmRSS grew from %d to %d kB", rssBefore, rssAfter)
	}
	// The rate limit of the house address refills (burst 8, one each 2 s).
	eventuallyEvery(t, time.Minute, 5*time.Second, func() string {
		line := ntpQuery(t, probe, "house", gw)
		if m := reNTPReply.FindStringSubmatch(line); m == nil || m[2] == "3" || m[3] == "0" {
			return "no valid NTP reply from " + gw + " after the fuzz: " + line
		}
		return ""
	})
}
