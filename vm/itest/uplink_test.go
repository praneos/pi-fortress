//go:build vagrant

package itest

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// uplinkTests examine the Pi as a stranger on its uplink would
// (docs/user_guide/public_wifi.md). Read-only on the Pi.
func uplinkTests(t *testing.T) {
	in := pi(t, "sudo nft list chain inet fortress input")
	out := pi(t, "sudo nft list chain inet fortress output")
	wan := uplinkIF(in)
	if wan == "" {
		t.Fatalf("no uplink DHCP rule in the input chain:\n%s", in)
	}
	closed := !lineWith(in, `iifname "`+wan+`" tcp dport 22`)

	t.Run("IPv6 dropped both ways", func(t *testing.T) {
		if !lineWith(in, `iifname "`+wan+`" meta nfproto ipv6`, " drop") {
			t.Fatalf("input:\n%s", in)
		}
		if !lineWith(out, `oifname "`+wan+`" meta nfproto ipv6`, " drop") {
			t.Fatalf("output:\n%s", out)
		}
	})
	t.Run("ARP answered only on the asked interface", func(t *testing.T) {
		got := strings.Join(strings.Fields(pi(t, "/sbin/sysctl -n net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce")), " ")
		if got != "1 2" {
			t.Fatalf("arp_ignore arp_announce = %q, want \"1 2\"", got)
		}
	})
	t.Run("no mDNS out of an untrusted uplink", func(t *testing.T) {
		if !closed {
			t.Skip("UNTRUSTED_UPLINK is off; the last subtest of this group turns it on")
		}
		if msg := untrustedShape(wan, in, out); msg != "" {
			t.Fatal(msg)
		}
	})
	t.Run("a neighbor reaches only ssh", func(t *testing.T) {
		ip := net.ParseIP(inetAddr(pi(t, "ip -4 -o addr show dev "+wan)))
		if ip == nil {
			t.Fatalf("no IPv4 address on %s", wan)
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			t.Fatal(err)
		}
		if !onLink(addrs, ip) {
			t.Skipf("this machine is not on the Pi's uplink subnet (%s)", ip)
		}
		// The probes do not depend on each other, and a dropped one waits
		// for its full 3 s. Thus they run at the same time. The checks
		// occur after, in the same order as before.
		ports := []string{"22", "53", "80", "443", "853", "8080"}
		open := make([]bool, len(ports))
		var answers bool
		var wg sync.WaitGroup
		for i, p := range ports {
			wg.Go(func() { open[i] = tcpOpen(ip, p) })
		}
		wg.Go(func() { answers = dnsAnswers(ip) })
		wg.Wait()
		if open[0] == closed {
			t.Errorf("tcp 22 from the uplink: open=%v, want open=%v", open[0], !closed)
		}
		for i, p := range ports[1:] {
			if open[i+1] {
				t.Errorf("tcp %s is open from the uplink", p)
			}
		}
		if answers {
			t.Error("udp 53 answered from the uplink")
		}
	})

	// Nothing in any lab profile sets UNTRUSTED_UPLINK. Thus each subtest
	// above that needs it skipped, and a full operating mode
	// (docs/user_guide/public_wifi.md 3) was "proved" on a live box only
	// because no live box ever entered it. This is the one place that
	// enters it.
	//
	// Why the test changes it, and the lab profile does not pin it on: the
	// flag is global to the Pi. The desk, house and ops groups that run
	// after this one in the same TestLab would all meet a box with ssh
	// closed on its uplink. In the VirtualBox lab, that is the adapter that
	// vagrant itself uses to reach the Pi. A pin in net.env would also
	// remove the off state, which is the default for all other checklist
	// items. A change here proves both states in one run, and gives the box
	// back as it was.
	t.Run("closing the uplink shuts ssh on it and keeps the admin way in", func(t *testing.T) {
		if target() == "pi" {
			t.Skip("lab only: it rewrites /etc/pi-fortress/net.env.local and applies")
		}
		if closed {
			t.Skip("UNTRUSTED_UPLINK is already on; the mDNS subtest above is the check")
		}
		const (
			local   = "/etc/pi-fortress/net.env.local"
			bak     = "/tmp/pf-itest-uplink.bak"
			script  = "/tmp/pf-itest-uplink-restore.sh"
			deadman = "pf-itest-uplink-restore"
		)
		// The file does not have to exist. touch then copy makes the
		// restore one case, not two. An empty net.env.local has the same
		// effect as an untouched box.
		if out, err := ssh(t, 30*time.Second, "pi", "sudo sh -c 'touch "+local+"; cat "+local+" > "+bak+"'"); err != nil {
			if sudoRefused(out + err.Error()) {
				skipNoSudo(t, "pi", "cat "+local)
			}
			t.Fatalf("could not save %s: %v\n%s", local, err, out)
		}
		// The restore is a script on the Pi, so that the same two steps
		// run from t.Cleanup and from the timer below.
		mustSSH(t, "pi", "sudo tee "+script+" >/dev/null <<'SH'\ncat "+bak+" > "+local+"\nexec /usr/local/sbin/pf apply --local\nSH")
		// Armed before the mutation, never after. To close ssh on the
		// uplink is the one change that can remove the way back in. A
		// t.Cleanup cannot run over a connection that no longer exists. The
		// established,related accept of the input chain keeps the session
		// that this suite already has. But a session lost for a different
		// reason (a ControlMaster that timed out, a killed test binary)
		// would leave a lab that nobody can reach. This puts the box back
		// within ten minutes, whatever occurs to this process. If it cannot
		// be armed, the test does not enter the mode at all.
		if out, err := ssh(t, 30*time.Second, "pi", "sudo systemd-run --quiet --collect --on-active=600 --unit="+deadman+" /bin/sh "+script); err != nil {
			t.Skipf("no deadman restore could be armed, so the uplink is left open: %v\n%s", err, out)
		}
		t.Cleanup(func() {
			// ssh, not mustSSH. A restore that called t.Fatal would stop
			// the rest of the cleanup. The operator needs the name of the
			// deadman in the failure, not a bare fatal.
			if out, err := ssh(t, 5*time.Minute, "pi", "sudo sh "+script); err != nil {
				t.Errorf("RESTORE FAILED: the Pi may still have UNTRUSTED_UPLINK=1 with ssh shut on %s; the %s timer re-applies the saved config within ten minutes: %v\n%s", wan, deadman, err, out)
				return
			}
			_, _ = ssh(t, 30*time.Second, "pi", "sudo systemctl stop "+deadman+".timer")
			back, _ := ssh(t, 30*time.Second, "pi", "sudo nft list chain inet fortress input")
			if !lineWith(back, `iifname "`+wan+`" tcp dport 22`) {
				t.Errorf("the restore ran but ssh is still shut on %s:\n%s", wan, back)
			}
		})
		// A leading newline, because net.env.local does not have to end in
		// one. The last assignment of a key wins, both in the shell that
		// apply.sh sources it with and in base.ParseEnv.
		mustSSH(t, "pi", "sudo sh -c 'printf \"\\nUNTRUSTED_UPLINK=1\\n\" >> "+local+"'")
		if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
			// checkUplink's refusals all end this way and change nothing,
			// so there is no mutation to report and nothing to fail.
			if contains(out, "Nothing was changed.") {
				t.Skipf("apply refused to close the uplink and changed nothing: %s", out)
			}
			t.Fatalf("apply with UNTRUSTED_UPLINK=1: %v\n%s", err, out)
		}
		if msg := untrustedShape(wan, pi(t, "sudo nft list chain inet fortress input"), pi(t, "sudo nft list chain inet fortress output")); msg != "" {
			t.Error(msg)
		}
		// The uplink is closed, not the box. The refusal of apply only
		// reads the declared admin path from the config. Only a live box
		// can show that the path still carries ssh in this mode. That is
		// the full reason that the mode is safe to enable.
		if sshHosts["house"] {
			mustSSH(t, "house", "nc -z -w3 "+netenv(t)["LAB_HOUSE_IP"]+" 22")
		}
	})
}

// untrustedShape names the first thing that is missing from the chains
// of an untrusted uplink, or "" when they are correct: no ssh accept, no
// ping accept, and the multicast name protocols dropped on the way out.
// nft prints the two ports as one `udp dport { 5353, 5355 }` element.
// Thus the match for the drop uses the ports, not the string that
// ruleset.go renders. A match on `udp dport 5353` found nothing, and no
// run could see that while no run entered the mode.
func untrustedShape(wan, in, out string) string {
	switch {
	case lineWith(in, `iifname "`+wan+`" tcp dport 22`):
		return "ssh is still accepted on the uplink:\n" + in
	case lineWith(in, `iifname "`+wan+`" icmp type echo-request`):
		return "ping is still answered on the uplink:\n" + in
	case !lineWith(out, `oifname "`+wan+`"`, "5353", "5355", " drop"):
		return "mDNS and LLMNR still leave the uplink:\n" + out
	}
	return ""
}

// uplinkIF is the interface on which the input chain accepts DHCP replies.
// Only the uplink has that rule. The house accepts requests, 68 to 67.
func uplinkIF(input string) string {
	for line := range strings.SplitSeq(input, "\n") {
		if !strings.Contains(line, "udp sport 67 udp dport 68 accept") {
			continue
		}
		if _, rest, ok := strings.Cut(line, `iifname "`); ok {
			name, _, _ := strings.Cut(rest, `"`)
			return name
		}
	}
	return ""
}

// inetAddr is the first address in `ip -4 -o addr show`, without its
// prefix length.
func inetAddr(out string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "inet" {
			a, _, _ := strings.Cut(f[i+1], "/")
			return a
		}
	}
	return ""
}

// onLink reports whether ip is on a subnet of this machine and is not
// one of its own addresses: the view of a neighbor, not a routed view.
func onLink(addrs []net.Addr, ip net.IP) bool {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if ok && !n.IP.IsLoopback() && !n.IP.Equal(ip) && n.Contains(ip) {
			return true
		}
	}
	return false
}

func tcpOpen(ip net.IP, port string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 3*time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

// dnsAnswers sends one A query for example.com and waits 3 s for any
// reply. A refused port reads as an error, so it is not an answer.
func dnsAnswers(ip net.IP) bool {
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "53"), 3*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	q := []byte{0x70, 0x66, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return false
	}
	n, err := c.Read(make([]byte, 512))
	return err == nil && n > 0
}
