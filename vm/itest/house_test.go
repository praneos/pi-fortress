//go:build vagrant

package itest

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// houseTests run on a Linux house client with the reserved admin address:
// the house VM of the local lab or of the cloud lab. Nothing here is about
// a tag or a cable. It is the one segment that DHCP serves. Thus it is
// also the only thing in any lab that reaches the DHCP half of dnsmasq.
// Only the cloud lab has the second, non-admin address. That subtest
// skips without it.
func houseTests(t *testing.T) {
	needHost(t, "house")
	e := netenv(t)
	agentIP, allow, blockIP := e["AGENT_IP"], e["ALLOW_DOMAIN"], e["BLOCK_IP"]
	gw, admin := e["LAB_HOUSE_IP"], e["LAB_HOUSE_ADMIN_IP"]
	const other = "10.78.0.250"

	t.Run("DHCP gives the reserved address, route and DNS", func(t *testing.T) {
		if out := mustSSH(t, "house", "ip -4 -o addr show"); !contains(out, " "+admin+"/24") {
			t.Fatal(out)
		}
		if out := mustSSH(t, "house", "ip route show default"); !contains(out, "via "+gw) {
			t.Fatal(out)
		}
		if out := mustSSH(t, "house", "cat /etc/resolv.conf"); !contains(out, "nameserver "+gw) {
			t.Fatal(out)
		}
	})
	t.Run("allowed name resolves", func(t *testing.T) {
		if ips := digOn(t, "house", allow, gw); len(ips) == 0 || ips[0] == "0.0.0.0" {
			t.Fatalf("%v", ips)
		}
	})
	// A feed name: dig only, never connect to it.
	t.Run("ad name sinkholed", func(t *testing.T) {
		if ips := digOn(t, "house", "ib.adnxs.com", gw); len(ips) == 0 || ips[len(ips)-1] != "0.0.0.0" {
			t.Fatalf("%v (did the feeds fetch? sudo pf status)", ips)
		}
	})
	// house_never_block frees doubleclick.net although hagezi lists it.
	t.Run("never-block ad name resolves", func(t *testing.T) {
		if ips := digOn(t, "house", "static.doubleclick.net", gw); len(ips) == 0 || ips[len(ips)-1] == "0.0.0.0" {
			// A filtering resolver upstream of the lab blocks it too. Then
			// the Pi cannot free it, and the answer says nothing of pf.
			// net.env.local on the Pi can set its own DNS_UPSTREAM.
			out, _ := ssh(t, 10*time.Second, "pi", "sudo -n sh -c '. /etc/pi-fortress/net.env; . /etc/pi-fortress/net.env.local 2>/dev/null; echo $DNS_UPSTREAM'")
			if up := strings.TrimSpace(out); ipv4(up) {
				if a := digOn(t, "pi", "static.doubleclick.net", up); len(a) > 0 && a[len(a)-1] == "0.0.0.0" {
					t.Skipf("the upstream %s itself answers 0.0.0.0 for doubleclick.net", up)
				}
			}
			t.Fatalf("%v (house_never_block.domains should free doubleclick.net)", ips)
		}
	})
	t.Run("public resolver refused", func(t *testing.T) {
		if ips := digOn(t, "house", allow, "9.9.9.9"); len(ips) != 0 {
			t.Fatal(ips)
		}
	})
	t.Run("HTTPS works", func(t *testing.T) {
		out, _ := ssh(t, 20*time.Second, "house", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://"+allow)
		if !curlOK(strings.TrimSpace(out)) {
			t.Fatal(out)
		}
	})
	t.Run("blocked address dropped and logged", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "house", "curl -sS --noproxy '*' -o /dev/null --max-time 5 http://"+blockIP)
		kernLog(t, since, "pi-fortress house-blacklist: ", "DST="+blockIP+" ")
	})
	t.Run("admin address reaches Pi and agent ssh", func(t *testing.T) {
		mustSSH(t, "house", "nc -z -w3 "+gw+" 22")
		mustSSH(t, "house", "nc -z -w3 "+agentIP+" 22")
	})
	t.Run("admin address has no ssh to other agents", func(t *testing.T) {
		needHost(t, "agent2")
		mustFailOn(t, "house", "nc -z -w3 "+nextIP(agentIP)+" 22")
	})
	t.Run("non-admin address has no ssh", func(t *testing.T) {
		if out := mustSSH(t, "house", "ip -4 -o addr show"); !contains(out, " "+other+"/") {
			t.Skip("no second address " + other)
		}
		mustFailAllOn(t, "house",
			"nc -s "+other+" -z -w3 "+agentIP+" 22",
			"nc -s "+other+" -z -w3 "+gw+" 22")
	})
	t.Run("DoT dropped and logged", func(t *testing.T) {
		since := piClock(t)
		mustFailOn(t, "house", "nc -z -w3 1.1.1.1 853")
		kernLog(t, since, "pi-fortress house-doh: ", "DST=1.1.1.1 ", "DPT=853 ")
	})
	// HOUSE_BLOCK_DIRECT_IP and HOUSE_BLOCK_HTTP are read from the live
	// ruleset, so the group checks them in the state that the TUI left.
	fwd := pi(t, "sudo nft list chain inet fortress forward")
	sniCheck, httpBlocked := contains(fwd, "house-sni"), contains(fwd, "house-http")
	// A 443 flow to an address that the house did not give is checked by
	// the name that it sends (pf dns, sni.go), not dropped. The name that
	// owns the address passes, and puts it back in the resolved set. A
	// different name sent to that address gets a reset and is logged house-sni.
	t.Run("direct IP checked by its TLS name", func(t *testing.T) {
		if !sniCheck {
			t.Skip("HOUSE_BLOCK_DIRECT_IP=off")
		}
		ip := unresolved(t, "resolved_house_v4", allow)
		// pf dns writes the set from an upstream answer, not a cache hit.
		// The subtests above left allow in the cache. Thus the name check
		// would pass from the cache and never put ip back. The reload resets
		// the cache, but from SIGHUP, after systemctl returns. Thus the test
		// retries the dial until one dial comes after the reset.
		pi(t, "sudo systemctl reload pi-fortress-dns-agent-go.service")
		eventuallyEvery(t, 20*time.Second, 2*time.Second, func() string {
			mustSSH(t, "house", "curl -sS --noproxy '*' -o /dev/null --max-time 10 --resolve "+allow+":443:"+ip+" https://"+allow+"/")
			if contains(pi(t, "sudo nft list set inet fortress resolved_house_v4"), ip) {
				return ""
			}
			return ip + " passed the name check but is not back in resolved_house_v4"
		})
		ip = unresolved(t, "resolved_house_v4", allow)
		// A different name. Before, this sent example.com, which is allow,
		// so the owner passed. Also not a Cloudflare-hosted name, because
		// example.com is on Cloudflare and a shared /24 also passes.
		const stranger = "www.google.com"
		since := piClock(t)
		mustFailOn(t, "house", "curl -sS --noproxy '*' -o /dev/null --max-time 5 --resolve "+stranger+":443:"+ip+" https://"+stranger+"/")
		kernLog(t, since, "pi-fortress house-sni: ", "DST="+ip+" ")
	})
	// pf dns has no CAP_NET_ADMIN. pf netgate binds the SNI queue of the
	// house and relays it to pf dns, so the queue belongs to the netgate
	// process (render.SNIQueue is 1). The subtest above used that relay.
	t.Run("netgate binds the SNI queue", func(t *testing.T) {
		if !sniCheck {
			t.Skip("HOUSE_BLOCK_DIRECT_IP=off")
		}
		pid := mainPID(t, "pi-fortress-netgate")
		eventually(t, 15*time.Second, func() string {
			out := pi(t, "sudo cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true")
			for line := range strings.SplitSeq(out, "\n") {
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "1" {
					if f[1] == pid {
						return ""
					}
					return "queue 1 is bound by portid " + f[1] + ", not by netgate (pid " + pid + ")"
				}
			}
			return "nothing binds the SNI queue 1:\n" + out
		})
	})
	t.Run("plain HTTP follows HOUSE_BLOCK_HTTP", func(t *testing.T) {
		url := "http://" + allow + "/"
		if !httpBlocked {
			out, _ := ssh(t, 20*time.Second, "house", "curl -4 -sS --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 "+url)
			if code := strings.TrimSpace(out); code == "" || code == "000" {
				t.Fatalf("HTTP by name failed with HOUSE_BLOCK_HTTP=off: %s", out)
			}
			return
		}
		ips := digOn(t, "house", allow, gw)
		if len(ips) == 0 {
			t.Fatalf("no address for %s from the house resolver", allow)
		}
		since := piClock(t)
		mustFailOn(t, "house", "curl -4 -sS --noproxy '*' -o /dev/null --max-time 5 --resolve "+allow+":80:"+ips[0]+" "+url)
		kernLog(t, since, "pi-fortress house-http: ", "DST="+ips[0]+" ", "DPT=80 ")
	})

	// The DHCP daemon is the one thing on the box that parses packets
	// from any device that the house connects. It was the last
	// long-running daemon with no seccomp filter. It also no longer drops
	// its own privilege: systemd starts it as its own account,
	// pf-dhcp-house. That lets the unit deny @privileged and give it one
	// capability, not seven. dhcp-broadcast removes the ARP write that
	// needed CAP_NET_ADMIN. A dnsmasq older than 2.91 does not start its
	// DHCP server without it, so there a drop-in gives it back (dhcpCaps).
	// No other DHCP instance runs as that account. Thus no other instance
	// can write its lease file or its log.
	t.Run("the DHCP daemon runs boxed in", func(t *testing.T) {
		since := piClock(t)
		pid, filter := unitSandbox(t, "pi-fortress-dns-house", "pf-dhcp-house", dhcpCaps(t))
		// The one @privileged call that is added again: dnsmasq fchowns its
		// log to the --user account at each start, root or not. If the
		// filter denies it, the daemon dies before it reads a packet.
		if !slices.Contains(filter, "fchown") {
			t.Error("the DHCP daemon may not fchown; it does that to its log at every start and a filtered call kills it")
		}
		// The lease file belongs to the daemon now. systemd starts the
		// daemon without privilege. Thus the daemon cannot open a
		// root-owned lease file as root and give it to itself when it
		// drops privilege.
		if out := pi(t, "sudo stat -c '%U %a' /var/lib/pi-fortress/house.leases"); strings.TrimSpace(out) != "pf-dhcp-house 640" {
			t.Errorf("house.leases is %s, want pf-dhcp-house 640; an unprivileged dnsmasq cannot write it", strings.TrimSpace(out))
		}

		// What follows renews a lease, reloads the daemon and forces a log
		// rotation: state that a Pi in use keeps (the rule of labOnly).
		if !destructiveOK() {
			t.Log("real Pi without PF_E2E_DESTRUCTIVE=1: the sandbox is checked, the lease, reload and rotation are not exercised")
			return
		}
		// The three things that reach this daemon in normal use, in the
		// order that a box sees them. A lease is the packet path (a
		// broadcast reply, with no ARP write and no ping before the
		// offer). HUP is
		// pf apply and systemctl reload. USR2 is the hourly rotation.
		// Through sudo: dhclient is in /sbin, which is on the secure_path
		// of root, not of the client account.
		if out, err := ssh(t, 15*time.Second, "house", "sudo sh -c 'command -v dhclient'"); err != nil || strings.TrimSpace(out) == "" {
			t.Log("no dhclient on the house client; this subtest does not exercise a fresh lease")
		} else {
			dev := strings.TrimSpace(mustSSH(t, "house", "ip -4 -o addr show to "+admin+"/32 | awk '{print $2}' | head -1"))
			if dev == "" {
				t.Fatalf("no interface on the house holds %s", admin)
			}
			// A no-op script and its own pidfile. At each run, a dhclient -1
			// stays as a daemon, and those daemons flush the second address
			// of the client (other) when they renew. Only the DHCPACK of the
			// Pi is under test here.
			const pidf = "/run/pf-itest-dhclient.pid"
			out, err := ssh(t, 60*time.Second, "house", "sudo dhclient -1 -sf /bin/true -pf "+pidf+" -lf /run/pf-itest-dhclient.leases "+dev+" 2>&1")
			ssh(t, 15*time.Second, "house", "sudo pkill -f -- '-pf "+pidf+"'; sudo rm -f "+pidf+" /run/pf-itest-dhclient.leases")
			if err != nil {
				t.Fatalf("dhclient on %s: %v\n%s", dev, err, out)
			}
			eventually(t, 20*time.Second, func() string {
				out := pi(t, "sudo tail -40 /var/log/pi-fortress/dnsmasq-house-dhcp.log")
				if lineWith(out, "DHCPACK", admin) {
					return ""
				}
				return "no DHCPACK for " + admin + " at the end of the DHCP log after the renew:\n" + out
			})
			// dhcp-broadcast: the reply went as broadcast, with no ARP
			// write. Without NET_ADMIN, a unicast reply logs this line.
			if n := strings.TrimSpace(pi(t, "sudo grep -c 'ARP-cache injection failed' /var/log/pi-fortress/dnsmasq-house-dhcp.log || true")); n != "0" {
				t.Errorf("the DHCP log has %s failed ARP writes; dnsmasq replied as unicast, not as broadcast", n)
			}
		}
		pi(t, "sudo systemctl reload pi-fortress-dns-house.service")
		pi(t, "sudo logrotate -f --state /var/lib/pi-fortress/logrotate.state /etc/pi-fortress/logrotate.conf")
		// create has no owner in this stanza. The new log keeps the owner
		// of the old one, so the daemon can append to it after USR2.
		if out := pi(t, "sudo stat -c '%U %a' /var/log/pi-fortress/dnsmasq-house-dhcp.log"); strings.TrimSpace(out) != "pf-dhcp-house 640" {
			t.Errorf("after rotation the DHCP log is %s, want pf-dhcp-house 640", strings.TrimSpace(out))
		}

		// Restart=always would hide a kill behind a healthy unit two
		// seconds later. Thus the PID shows the kill, and the journal
		// shows which call it was.
		if now := mainPID(t, "pi-fortress-dns-house"); now != pid {
			t.Errorf("the DHCP daemon was pid %s and is now pid %s; it died and restarted during the lease, reload and rotation", pid, now)
		}
		noSeccompKill(t, since, "dnsmasq")
	})
}
