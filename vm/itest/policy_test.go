//go:build vagrant

package itest

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func policyTests(t *testing.T) {
	// The seccomp check at the end covers all the traffic of this group.
	since := piClock(t)
	t.Run("parallel", func(t *testing.T) {
		runGroup(t, "blacklist", blacklistTests)
		runGroup(t, "dns", dnsTests)
		runGroup(t, "egress", egressTests)
	})
	t.Run("nft canary in set", func(t *testing.T) {
		out := pi(t, "sudo /usr/sbin/nft list set inet fortress blacklist_v4")
		if !contains(out, "192.0.2.1") {
			t.Fatal(out)
		}
	})
	t.Run("observe saw example.com", func(t *testing.T) {
		// The listing is the 40 newest first-seen names. On a box with a
		// real house behind it, example.com became old some hours ago. The
		// ledger shows that it was seen.
		out := pi(t, "sudo /usr/local/sbin/pf observe once >/dev/null; sudo grep -c '\"example.com\":' /var/lib/pi-fortress/observe/observe.json")
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err != nil || n == 0 {
			t.Fatal(out)
		}
	})
	// The fence daemons and the sidecars, as the kernel sees them: each one
	// runs under its seccomp filter, with no_new_privs, and with only its
	// own capabilities. The policy traffic above went through the engine,
	// the broker, pf dns and observe. A filtered call kills a daemon (the
	// default action), and the kernel logs it.
	t.Run("the daemons run boxed in", func(t *testing.T) {
		for _, u := range []struct {
			unit string
			caps uint64
		}{
			{"pi-fortress-broker", 0},
			{"pi-fortress-engine", 0},
			{"pi-fortress-www", capNetBindService},
			{"pi-fortress-observe", capNetAdmin},
			{"pi-fortress-alert", 0},
			{"pi-fortress-monitor", 0},
		} {
			procBoxed(t, u.unit, u.caps)
		}
		// The engine and www read no log, no observe state, no webhook URL
		// and no house reservation. systemd hides each of them.
		hidden := []string{"/var/log/pi-fortress", "/var/lib/pi-fortress/observe", "/etc/pi-fortress/alert.url", "/etc/pi-fortress/house.hosts"}
		for _, unit := range []string{"pi-fortress-engine", "pi-fortress-www"} {
			paths := unitPaths(t, unit, "InaccessiblePaths")
			for _, p := range hidden {
				if !slices.Contains(paths, p) {
					t.Errorf("%s does not hide %s: InaccessiblePaths=%v", unit, p, paths)
				}
			}
			// The two directories always exist. Thus in the mount
			// namespace of the daemon, each one is the empty node of
			// systemd, mode 0.
			pid := mainPID(t, unit)
			if pid == "" || pid == "0" {
				continue
			}
			for _, d := range hidden[:2] {
				out, _ := ssh(t, 20*time.Second, "pi", "sudo stat -c %a /proc/"+pid+"/root"+d)
				if m := strings.TrimSpace(out); m != "0" {
					t.Errorf("%s sees %s as %q, want the empty node of systemd (mode 0)", unit, d, m)
				}
			}
		}
		noSeccompKill(t, since, "pf", "nft", "journalctl", "conntrack", "ip")
	})
}

func blacklistTests(t *testing.T) {
	t.Parallel()
	e := netenv(t)
	piIP := e["PI_IP"]
	allow := e["ALLOW_DOMAIN"]
	block := e["BLOCK_DOMAIN"]
	blockIP := e["BLOCK_IP"]
	nat := e["VBOX_NAT_GW"]

	t.Run("agent reaches pi", func(t *testing.T) {
		agent(t, "ping -c 1 -W 2 "+piIP)
	})
	t.Run("allowed domain DNS is real", func(t *testing.T) {
		ips := digA(t, allow, piIP)
		if len(ips) == 0 || ips[0] == "0.0.0.0" {
			t.Fatalf("%v", ips)
		}
	})
	t.Run("allowed HTTPS", func(t *testing.T) {
		if !curlOK(httpCode(t, "https://"+allow)) {
			t.Fatal("https failed")
		}
	})
	t.Run("canary domain DNS is 0.0.0.0", func(t *testing.T) {
		ips := digA(t, block, piIP)
		if len(ips) == 0 || ips[len(ips)-1] != "0.0.0.0" {
			t.Fatalf("%v", ips)
		}
	})
	mustFail(t, "canary domain HTTPS fails", "curl -sS -o /dev/null --max-time 5 https://"+block)
	// The client gives its own address for the listed name, so the
	// sinkhole never fires. The engine itself must refuse the SNI.
	t.Run("canary domain via --resolve fails", func(t *testing.T) {
		ips := digA(t, allow, piIP)
		if len(ips) == 0 || ips[0] == "0.0.0.0" {
			t.Fatalf("no real address for %s: %v", allow, ips)
		}
		mustFailOn(t, "agent", "curl -sS -o /dev/null --max-time 5 --resolve "+block+":443:"+ips[0]+" https://"+block)
	})
	mustFail(t, "canary TEST-NET fails", "curl -sS -o /dev/null --max-time 5 https://"+blockIP)
	mustFail(t, "host NAT fails via pi", "curl -sS -o /dev/null --max-time 5 http://"+nat)
	t.Run("feed sample sinkholed", func(t *testing.T) {
		sample, _ := ssh(t, 10*time.Second, "pi", "tr -d '[:space:]' < /vagrant/vm/policy/generated/sample.domain")
		sample = strings.TrimSpace(sample)
		if sample == "" {
			t.Skip("no sample.domain")
		}
		ips := digA(t, sample, piIP)
		if len(ips) == 0 || ips[len(ips)-1] != "0.0.0.0" {
			t.Fatalf("%s -> %v", sample, ips)
		}
	})
}

func dnsTests(t *testing.T) {
	t.Parallel()
	e := netenv(t)
	piIP := e["PI_IP"]

	t.Run("resolv.conf nameserver is Pi", func(t *testing.T) {
		out := agent(t, "cat /etc/resolv.conf")
		if !contains(out, "nameserver "+piIP) {
			t.Fatal(out)
		}
	})
	t.Run("stub DNS via Pi works", func(t *testing.T) {
		ips := digA(t, "example.com", piIP)
		if len(ips) == 0 || ips[0] == "0.0.0.0" {
			t.Fatalf("%v", ips)
		}
	})
	// The lock of the agent drops DNS to all servers except the Pi before
	// it leaves the VM. Thus it is lifted for these two, and the Pi must log
	// the drop (both addresses are in the DoH set, whose drop comes first).
	for _, stub := range []string{"8.8.8.8", "1.1.1.1"} {
		t.Run("public stub "+stub+" blocked", func(t *testing.T) {
			liftAgentLock(t)
			since := piClock(t)
			if ips := digA(t, "example.com", stub); len(ips) != 0 {
				t.Fatal(ips)
			}
			kernLog(t, since, "pi-fortress agent-doh: ", "DST="+stub+" ", "DPT=53 ")
		})
	}
	t.Run("cloudflare-dns.com sinkholed", func(t *testing.T) {
		ips := digA(t, "cloudflare-dns.com", piIP)
		if len(ips) == 0 || ips[len(ips)-1] != "0.0.0.0" {
			t.Fatalf("%v", ips)
		}
	})
	mustFail(t, "DoH to 1.1.1.1 fails", "curl -sk --max-time 4 -o /dev/null https://1.1.1.1/dns-query")
	// 853 never leaves the VM with its lock on.
	t.Run("DoT to 1.1.1.1:853 fails", func(t *testing.T) {
		liftAgentLock(t)
		since := piClock(t)
		mustFailOn(t, "agent", "timeout 3 bash -c 'echo >/dev/tcp/1.1.1.1/853'")
		kernLog(t, since, "pi-fortress agent-doh: ", "DST=1.1.1.1 ", "DPT=853 ")
	})
}

// mustFail runs cmd on the agent as a subtest and fails unless cmd itself
// failed. An ssh error or a timeout does not show that the command was blocked.
func mustFail(t *testing.T, name, cmd string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		mustFailOn(t, "agent", cmd)
	})
}

func egressTests(t *testing.T) {
	t.Parallel()
	e := netenv(t)
	piIP := e["PI_IP"]

	t.Run("HTTPS 443 still works", func(t *testing.T) {
		if !curlOK(httpCode(t, "https://example.com")) {
			t.Fatal("https failed")
		}
	})
	// The lock of the agent also drops 80 to all hosts except the Pi. With
	// the lock lifted, the raw-priority drop of the Pi must count it.
	t.Run("TCP 80 blocked", func(t *testing.T) {
		liftAgentLock(t)
		piDropsGrow(t, "filter_prerouting", `iifname "`+piAgentIF(t)+`" tcp dport 80 ip daddr != `+piIP, func() {
			mustFailOn(t, "agent", "curl -4 -sS --connect-timeout 3 --max-time 4 -o /dev/null http://example.com/")
		})
	})
	mustFail(t, "TCP 22 to github.com blocked", "timeout 3 bash -c 'echo >/dev/tcp/github.com/22'")
	// A one-byte datagram gets no answer from anyone, so "no reply" proved
	// nothing. With the lock lifted, the probe goes to the address of an
	// allowed site (not 1.1.1.1, whose DoH-set drop comes first). The
	// udp/443 drop of the Pi must count it.
	t.Run("UDP 443 QUIC blocked", func(t *testing.T) {
		ip := firstIPv4(pi(t, "dig +short +time=3 +tries=2 "+e["ALLOW_DOMAIN"]))
		if ip == "" {
			t.Fatalf("no address for %s from the Pi's resolver", e["ALLOW_DOMAIN"])
		}
		liftAgentLock(t)
		piDropsGrow(t, "filter_prerouting", `iifname "`+piAgentIF(t)+`" udp dport 443`, func() {
			_, _ = ssh(t, 15*time.Second, "agent", "timeout 3 bash -c 'exec 3<>/dev/udp/"+ip+"/443; printf quic >&3; printf quic >&3'")
		})
	})
	t.Run("IPv6 disabled", func(t *testing.T) {
		out := agent(t, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6 || true")
		if strings.TrimSpace(out) == "1" {
			return
		}
		addrs, _ := ssh(t, 5*time.Second, "agent", "ip -6 addr show scope global")
		if contains(addrs, "inet6") {
			t.Fatal(addrs)
		}
	})
	t.Run("no IPv6 default route", func(t *testing.T) {
		out, _ := ssh(t, 5*time.Second, "agent", "ip -6 route show default")
		if strings.TrimSpace(out) != "" {
			t.Fatal(out)
		}
	})
	mustFail(t, "curl -6 fails", "curl -6 -sk --connect-timeout 3 --max-time 4 -o /dev/null https://example.com")
	// curl -6 fails on the agent itself (IPv6 is off there, and its lock
	// drops it). To check if the Pi drops IPv6, an IPv6 packet must be on
	// the wire: lift the lock, enable IPv6 on the cable for a short time,
	// link-local only, ping all-nodes, then put both back.
	t.Run("IPv6 from the agent is dropped at the Pi", func(t *testing.T) {
		liftAgentLock(t)
		script := strings.Join([]string{
			"dev=$(ip -4 route get " + piIP + " | awk '{for(i=1;i<NF;i++) if($i==\"dev\"){print $(i+1); exit}}')",
			"was=$(cat /proc/sys/net/ipv6/conf/$dev/disable_ipv6)",
			"trap 'echo $was > /proc/sys/net/ipv6/conf/$dev/disable_ipv6' EXIT",
			"echo 0 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6",
			"sleep 3",
			"ping -6 -c 3 -i 0.3 -W 1 -I $dev ff02::1 >/dev/null 2>&1; echo done",
		}, "; ")
		piV6DropsGrow(t, piAgentIF(t), func() {
			if out, err := ssh(t, 40*time.Second, "agent", "sudo bash -c "+shellQuote(script)); !strings.Contains(out, "done") {
				t.Fatalf("the IPv6 probe did not run: %v\n%s", err, out)
			}
		})
		if out := strings.TrimSpace(agent(t, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6")); out != "1" {
			t.Errorf("IPv6 is not off on the agent after the probe: all.disable_ipv6=%s", out)
		}
	})
	t.Run("dnsmasq filter-AAAA", func(t *testing.T) {
		out, _ := ssh(t, 8*time.Second, "agent", "dig +short +time=2 +tries=1 AAAA example.com @"+piIP)
		if strings.Contains(out, ":") && !strings.Contains(out, ".") {
			t.Fatal(out)
		}
	})
}
