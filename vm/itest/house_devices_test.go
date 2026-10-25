//go:build vagrant

package itest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/testsupport"
)

// houseDeviceTests run from the pool devices that the house VM of the
// cloud lab has in network namespaces (vm/cloudlab/guest/house-ns.sh):
// phone, a MAC with no reservation that accepts IPv6 router
// advertisements; and iot, which ignores the DHCP DNS option and uses a
// hardcoded 8.8.8.8. Most of a real house is devices such as these. The
// admin address is one device.
func houseDeviceTests(t *testing.T) {
	cloudlabOnly(t)
	needHost(t, "house")
	e := netenv(t)
	agentIP, allow := e["AGENT_IP"], e["ALLOW_DOMAIN"]
	const gw, desk = "10.78.0.1", "10.79.0.2"
	if out, err := ssh(t, 15*time.Second, "house", "ip netns list"); err != nil || !contains(out, "phone") || !contains(out, "iot") {
		t.Skip("house VM has no phone/iot netns; recreate it: vagrant destroy -f house && lab.sh up house")
	}
	in := func(ns, cmd string) string { return "sudo ip netns exec " + ns + " " + cmd }

	t.Run("phone gets a pool lease, route and DNS", func(t *testing.T) {
		out := mustSSH(t, "house", in("phone", "ip -4 -o addr show dev phone0"))
		m := regexp.MustCompile(`inet 10\.78\.0\.(\d+)/24`).FindStringSubmatch(out)
		if m == nil {
			t.Fatal(out)
		}
		if n, _ := strconv.Atoi(m[1]); n < 100 || n > 199 {
			t.Fatalf("10.78.0.%s is outside the pool .100-.199", m[1])
		}
		if out := mustSSH(t, "house", in("phone", "ip route show default")); !contains(out, "via "+gw) {
			t.Fatal(out)
		}
		if out := mustSSH(t, "house", in("phone", "cat /etc/resolv.conf")); strings.TrimSpace(out) != "nameserver "+gw {
			t.Fatal(out)
		}
		if out := pi(t, "sudo cat /var/lib/pi-fortress/house.leases"); !contains(strings.ToLower(out), "56:54:00:78:00:31") {
			t.Fatalf("phone lease not in house.leases:\n%s", out)
		}
	})
	t.Run("phone resolves through its DHCP resolver", func(t *testing.T) {
		out, _ := ssh(t, 10*time.Second, "house", in("phone", "dig +short +time=2 +tries=1 "+allow))
		if !regexp.MustCompile(`(?m)^\d+\.\d+\.\d+\.\d+$`).MatchString(out) || contains(out, "0.0.0.0") {
			t.Fatal(out)
		}
		out, _ = ssh(t, 10*time.Second, "house", in("phone", "dig +short +time=2 +tries=1 ib.adnxs.com"))
		if !contains(out, "0.0.0.0") {
			t.Fatalf("%q (did the feeds fetch? sudo pf status)", out)
		}
	})
	t.Run("phone HTTPS works", func(t *testing.T) {
		out, _ := ssh(t, 20*time.Second, "house", in("phone", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://"+allow))
		if !curlOK(strings.TrimSpace(out)) {
			t.Fatal(out)
		}
	})
	t.Run("pool address has no ssh", func(t *testing.T) {
		mustFailAllOn(t, "house",
			in("phone", "nc -z -w3 "+gw+" 22"),
			in("phone", "nc -z -w3 "+agentIP+" 22"))
	})
	t.Run("setup page and desk unreachable", func(t *testing.T) {
		mustFailAllOn(t, "house",
			in("phone", "curl -sS --noproxy '*' -o /dev/null --max-time 5 http://10.77.0.1/setup.sh"),
			in("phone", "nc -z -w3 "+desk+" 22"))
	})
	// To an allowed site, not 1.1.1.1: 1.1.1.1 is in the DoH set, and the
	// rule before the QUIC rule would drop it.
	t.Run("QUIC dropped", func(t *testing.T) {
		ips := digOn(t, "house", allow, gw)
		if len(ips) == 0 {
			t.Fatal("no address for " + allow)
		}
		before := houseQUICDrops(t)
		_, _ = ssh(t, 15*time.Second, "house", in("phone", "sh -c 'echo quic | nc -u -w1 "+ips[0]+" 443'"))
		if after := houseQUICDrops(t); after <= before {
			t.Fatalf("house udp/443 drop counter %d -> %d", before, after)
		}
	})
	t.Run("phone gets no IPv6 route", func(t *testing.T) {
		time.Sleep(2 * time.Second)
		if out := mustSSH(t, "house", in("phone", "ip -6 route show default")); strings.TrimSpace(out) != "" {
			t.Fatalf("IPv6 default route on a house device:\n%s", out)
		}
		if out := mustSSH(t, "house", in("phone", "ip -6 -o addr show scope global")); strings.TrimSpace(out) != "" {
			t.Fatalf("global IPv6 address on a house device:\n%s", out)
		}
	})
	// A device with a hardcoded public resolver must fail fast (reject,
	// not drop). Then it uses a fallback or shows an error, and does not hang.
	t.Run("hardcoded resolver refused fast", func(t *testing.T) {
		if out := mustSSH(t, "house", in("iot", "cat /etc/resolv.conf")); !contains(out, "nameserver 8.8.8.8") {
			t.Fatal(out)
		}
		for _, proto := range []string{"+notcp", "+tcp"} {
			out, _ := ssh(t, 20*time.Second, "house", in("iot", "sh -c 's=$(date +%s%N); dig +short +time=5 +tries=1 "+proto+" "+allow+"; echo ms=$(( ($(date +%s%N)-s)/1000000 ))'"))
			m := regexp.MustCompile(`ms=(\d+)`).FindStringSubmatch(out)
			if m == nil {
				t.Fatal(out)
			}
			if regexp.MustCompile(`(?m)^\d+\.\d+\.\d+\.\d+$`).MatchString(out) {
				t.Fatalf("%s: 8.8.8.8 answered from the house:\n%s", proto, out)
			}
			if ms, _ := strconv.Atoi(m[1]); ms > 2000 {
				t.Fatalf("%s: 8.8.8.8 took %dms to fail; it is dropped, not rejected", proto, ms)
			}
		}
	})
	// The 2026-09-08 outage: the house NIC lost carrier, and the segment
	// did not come back. Disconnect the house cable of the gw. Wait for a
	// lease renewal attempt. Connect it again, and expect DNS and HTTPS again.
	t.Run("house cable pulled and back", func(t *testing.T) {
		gwID := strings.TrimSpace(mustRead(t, "vm/cloudlab/.vagrant/machines/gw/libvirt/id"))
		// Not run(): the context of t is already cancelled when Cleanup
		// runs. A link that stays down would break all later groups.
		link := func(state string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "virsh", "-c", "qemu:///system", "domif-setlink", gwID, e["GW_HOUSE_MAC"], state).CombinedOutput()
			if err != nil {
				return fmt.Errorf("virsh domif-setlink %s: %w\n%s", state, err, out)
			}
			return nil
		}
		if err := link("down"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := link("up"); err != nil {
				t.Error(err)
			}
		})
		time.Sleep(30 * time.Second)
		if err := link("up"); err != nil {
			t.Fatal(err)
		}
		houseIF := strings.TrimSpace(pi(t, ". /etc/pi-fortress/house.env && echo $HOUSE_IF"))
		eventuallyEvery(t, 60*time.Second, 2*time.Second, func() string {
			if out := pi(t, "ip -4 -o addr show dev "+houseIF); !contains(out, " "+gw+"/24") {
				return "house address gone after carrier loss:\n" + out
			}
			out, _ := ssh(t, 10*time.Second, "house", in("phone", "dig +short +time=2 +tries=1 "+allow))
			if !regexp.MustCompile(`(?m)^\d+\.\d+\.\d+\.\d+$`).MatchString(out) {
				return "phone DNS after carrier loss: " + out
			}
			out, _ = ssh(t, 20*time.Second, "house", in("phone", "curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://"+allow))
			if !curlOK(strings.TrimSpace(out)) {
				return "phone HTTPS after carrier loss: " + out
			}
			return ""
		})
	})
	t.Run("observe names house devices", func(t *testing.T) {
		if out := pi(t, "sudo pf observe once"); !contains(out, "house/") {
			t.Fatalf("no house/<name> in pf observe once:\n%s", out)
		}
	})
}

func mustRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testsupport.RepoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// houseQUICDrops reads the packet counter on the house udp/443 drop rule.
func houseQUICDrops(t *testing.T) int {
	t.Helper()
	houseIF := strings.TrimSpace(pi(t, ". /etc/pi-fortress/house.env && echo $HOUSE_IF"))
	out := pi(t, "sudo nft list ruleset")
	m := regexp.MustCompile(`iifname "` + regexp.QuoteMeta(houseIF) + `" udp dport 443 counter packets (\d+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no udp/443 drop rule for house interface %q", houseIF)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
