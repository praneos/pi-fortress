//go:build vagrant

package itest

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// segDHCPTests add a temporary DHCP=on segment on a VLAN of the house
// cable (the IoT-SSID case). They lease an address on it from a network
// namespace in the house VM that sends its frames tagged with that VLAN,
// as an AP that maps an SSID to a VLAN would. The house bridge of the
// cloud lab is a plain Linux bridge, so it carries the tag to the gw.
// t.Cleanup undoes each change, and is registered before the change: the
// segment file and its reservations, the apply (which must prune the
// NetworkManager profile of the segment itself), the allowlist and logs
// that it seeded, and the namespace in the house VM.
func segDHCPTests(t *testing.T) {
	cloudlabOnly(t)
	needHost(t, "house")
	e := netenv(t)
	allow, houseMAC := e["ALLOW_DOMAIN"], e["HOUSE_MAC"]
	const (
		name   = "itdhcp"
		vlan   = "36"
		segIP  = "10.36.0.1"
		file   = "/etc/pi-fortress/segments.d/" + name + ".env"
		hosts  = "/etc/pi-fortress/dhcp." + name + ".hosts"
		ns     = "pfsegdhcp"
		dev    = "pfseg0"
		pidf   = "/run/dhclient-" + dev + ".pid"
		leasef = "/var/lib/dhcp/dhclient-" + dev + ".leases"
		apply  = "sudo /usr/local/sbin/pf apply --local 2>&1"
	)
	houseIF := strings.TrimSpace(pi(t, ". /etc/pi-fortress/house.env && echo $HOUSE_IF"))
	if houseIF == "" || strings.Contains(houseIF, ".") {
		t.Skipf("HOUSE_IF=%q: this needs an untagged house port to hang a VLAN on", houseIF)
	}
	segIF := houseIF + "." + vlan
	if out, _ := ssh(t, 10*time.Second, "pi", "sudo test -e "+file+" && echo taken; sudo grep -lsE '^NET=10\\.36\\.' /etc/pi-fortress/segments.d/*.env || true"); strings.TrimSpace(out) != "" {
		t.Skipf("segment %s or a 10.36.0.0/24 network is already on this box: %s", name, out)
	}
	if houseMAC == "" {
		t.Fatal("lab.env has no HOUSE_MAC")
	}
	hostIF := strings.TrimSpace(mustSSH(t, "house", "ip -o link | awk -F': ' 'tolower($0) ~ /"+strings.ToLower(houseMAC)+"/ {print $2; exit}'"))
	if hostIF == "" {
		t.Fatalf("no NIC with %s on the house VM", houseMAC)
	}
	allowExisted := func() bool {
		_, err := ssh(t, 10*time.Second, "pi", "sudo test -e /etc/pi-fortress/allow."+name+".domains")
		return err == nil
	}()

	t.Cleanup(func() {
		_, _ = ssh(t, 20*time.Second, "house", "sudo sh -c 'test -f "+pidf+" && kill $(cat "+pidf+"); ip netns del "+ns+" 2>/dev/null; rm -f "+pidf+" "+leasef+"; rm -rf /etc/netns/"+ns+"'")
		if out, err := ssh(t, 20*time.Second, "pi", "sudo rm -f "+file+" "+hosts); err != nil {
			t.Errorf("%s was not removed: %v\n%s", file, err, out)
			return
		}
		out, err := ssh(t, 5*time.Minute, "pi", apply)
		if err != nil {
			t.Errorf("the apply that removes segment %s failed: %v\n%s", name, err, out)
		}
		// The apply itself prunes the profile of the removed segment. The
		// delete below only stops a failure here from leaving it behind.
		if left, _ := ssh(t, 15*time.Second, "pi", "nmcli -t -f NAME con show | grep -x seg-"+name+"; true"); strings.TrimSpace(left) != "" {
			t.Errorf("the apply that removed segment %s left its NetworkManager profile seg-%s:\n%s", name, name, out)
		} else if !contains(out, "pruned NetworkManager profile seg-"+name+" ("+segIF+"): segment "+name+" is gone") {
			t.Errorf("the apply did not report pruning seg-%s:\n%s", name, out)
		}
		rm := "sudo nmcli con delete seg-" + name + " >/dev/null 2>&1; sudo rm -f /var/log/pi-fortress/dns-" + name + ".jsonl* /var/log/pi-fortress/dhcp-" + name + ".log*"
		if !allowExisted {
			rm += " /etc/pi-fortress/allow." + name + ".domains"
		}
		_, _ = ssh(t, 30*time.Second, "pi", rm+"; true")
		if out, _ := ssh(t, 15*time.Second, "pi", "sudo ls /etc/pi-fortress/dhcp-"+name+".conf /var/lib/pi-fortress/dhcp-"+name+".leases /etc/systemd/system/multi-user.target.wants/pi-fortress-dhcp@"+name+".service 2>/dev/null; systemctl is-active pi-fortress-dhcp@"+name+".service 2>/dev/null; true"); strings.TrimSpace(out) != "inactive" && strings.TrimSpace(out) != "" {
			t.Errorf("removing segment %s left its DHCP behind:\n%s", name, out)
		}
	})

	writeSeg := func(dhcp string) {
		t.Helper()
		body := "IF=" + segIF + "\nNET=10.36.0.0/24\nIP=" + segIP + "\nDHCP=" + dhcp + "\nDHCP_START=10.36.0.100\nDHCP_END=10.36.0.109\n"
		pi(t, "printf '%s' '"+body+"' | sudo tee "+file+" >/dev/null && sudo chmod 0644 "+file)
	}
	writeSeg("on")
	out, err := ssh(t, 5*time.Minute, "pi", apply)
	if err != nil {
		t.Fatalf("apply with DHCP=on on %s: %v\n%s", segIF, err, out)
	}
	t.Run("apply warns about the house cable and the AP's DHCP, and keeps the house port quiet", func(t *testing.T) {
		if !contains(out, "rides the house cable") || !contains(out, "must not run its own DHCP") {
			t.Errorf("no house-cable warning naming the AP's DHCP:\n%s", out)
		}
		if contains(out, houseIF+" is a VLAN parent and still addressed") {
			t.Errorf("the trunk notice still fires for HOUSE_IF carrying its SSID VLAN:\n%s", out)
		}
	})
	t.Run("the instance is up, DHCP-only and bound to the segment", func(t *testing.T) {
		unit := "pi-fortress-dhcp@" + name
		eventually(t, 20*time.Second, func() string {
			if s := strings.TrimSpace(pi(t, "systemctl is-active "+unit+".service || true")); s != "active" {
				return unit + " is " + s
			}
			return ""
		})
		conf := pi(t, "sudo cat /etc/pi-fortress/dhcp-"+name+".conf")
		for _, want := range []string{"interface=" + segIF + "\n", "port=0\n", "dhcp-range=10.36.0.100,10.36.0.109,12h\n"} {
			if !contains(conf, want) {
				t.Errorf("dhcp-%s.conf lacks %q:\n%s", name, want, conf)
			}
		}
		pid := mainPID(t, unit)
		ss := pi(t, "sudo ss -lunp")
		n := 0
		for _, l := range strings.Split(ss, "\n") {
			if !contains(l, "pid="+pid+",") {
				continue
			}
			n++
			t.Logf("%s: %s", unit, strings.TrimSpace(l))
			if !regexp.MustCompile(`:67\s`).MatchString(l) {
				t.Errorf("%s listens on more than DHCP: %s", unit, strings.TrimSpace(l))
			}
		}
		if n == 0 {
			t.Errorf("%s (pid %s) holds no UDP socket:\n%s", unit, pid, ss)
		}
		// Each instance runs as its own account, which owns only the
		// lease file and the log of its segment.
		if u := strings.TrimSpace(pi(t, "sudo stat -c %U /proc/"+pid)); u != "pf-dhcp-"+name {
			t.Errorf("%s runs as %s, want pf-dhcp-%s", unit, u, name)
		}
		if s := pi(t, "sudo stat -c '%U %a' /var/lib/pi-fortress/dhcp-"+name+".leases /var/log/pi-fortress/dhcp-"+name+".log"); strings.Count(s, "pf-dhcp-"+name+" 640") != 2 {
			t.Errorf("lease file and log are not pf-dhcp-%s 0640:\n%s", name, s)
		}
		if rs := pi(t, "sudo nft list chain inet fortress input"); !contains(rs, `iifname "`+segIF+`" udp sport 68 udp dport 67 accept`) {
			t.Errorf("input does not take UDP 67 on %s", segIF)
		}
		if d, _ := ssh(t, 60*time.Second, "pi", "sudo /usr/local/sbin/pf doctor 2>&1"); !contains(d, unit+".service active") {
			t.Errorf("pf doctor has no dhcp rung for %s:\n%s", name, d)
		}
	})
	t.Run("a tagged client gets a lease, the Pi as router and DNS, and nothing else", func(t *testing.T) {
		mustSSH(t, "house", "sudo sh -c 'ip netns add "+ns+" && install -d -m 0755 /etc/netns/"+ns+" && touch /etc/netns/"+ns+"/resolv.conf && ip link add link "+hostIF+" name "+dev+" type vlan id "+vlan+" && ip link set "+dev+" netns "+ns+" && ip -n "+ns+" link set lo up && ip -n "+ns+" link set "+dev+" up'")
		if o, err := ssh(t, 60*time.Second, "house", "sudo ip netns exec "+ns+" /sbin/dhclient -4 -1 -pf "+pidf+" -lf "+leasef+" "+dev+" 2>&1"); err != nil {
			t.Fatalf("dhclient on VLAN %s: %v\n%s", vlan, err, o)
		}
		lease := mustSSH(t, "house", "sudo cat "+leasef)
		m := regexp.MustCompile(`fixed-address 10\.36\.0\.(\d+);`).FindStringSubmatch(lease)
		if m == nil {
			t.Fatalf("no lease in 10.36.0.0/24:\n%s", lease)
		}
		if n, _ := strconv.Atoi(m[1]); n < 100 || n > 109 {
			t.Errorf("10.36.0.%s is outside DHCP_START=10.36.0.100 to DHCP_END=10.36.0.109", m[1])
		}
		for _, want := range []string{"option routers " + segIP + ";", "option domain-name-servers " + segIP + ";", "option dhcp-lease-time 43200;"} {
			if !contains(lease, want) {
				t.Errorf("lease lacks %q:\n%s", want, lease)
			}
		}
		for _, bad := range []string{"domain-name ", "domain-search", "wpad", "ntp-servers"} {
			if contains(lease, "option "+bad) {
				t.Errorf("the lease hands out %s:\n%s", bad, lease)
			}
		}
		addr := "10.36.0." + m[1]
		eventually(t, 15*time.Second, func() string {
			if l := pi(t, "sudo cat /var/lib/pi-fortress/dhcp-"+name+".leases"); !contains(l, " "+addr+" ") {
				return "the Pi's lease file does not hold " + addr + ":\n" + l
			}
			return ""
		})
		if a := mustSSH(t, "house", "sudo ip -n "+ns+" -4 -o addr show dev "+dev); !contains(a, " "+addr+"/24") {
			t.Fatalf("dhclient did not put %s on %s:\n%s", addr, dev, a)
		}
		if ips, _ := ssh(t, 15*time.Second, "house", "sudo ip netns exec "+ns+" dig +short +time=3 +tries=1 @"+segIP+" "+allow); !regexp.MustCompile(`(?m)^\d+\.\d+\.\d+\.\d+$`).MatchString(ips) {
			t.Errorf("the segment's DNS on %s did not answer %s: %q", segIP, allow, ips)
		}
		// House trust at most: no SSH to the Pi or into the agents.
		mustFailAllOn(t, "house",
			"sudo ip netns exec "+ns+" nc -z -w3 "+segIP+" 22",
			"sudo ip netns exec "+ns+" nc -z -w3 "+e["AGENT_IP"]+" 22")
	})
	// A reservation for the MAC of the client, outside the dynamic range,
	// so that the address can only come from it. It is in dhcp.<name>.hosts
	// next to segments.d. Then the refusal of reservations with DHCP off.
	// The file is removed at the end. That lets the next subtest set
	// DHCP off.
	t.Run("a reservation gives the client its fixed address, and is refused with DHCP off", func(t *testing.T) {
		const fixed = "10.36.0.50"
		mac := strings.TrimSpace(mustSSH(t, "house", "sudo ip -n "+ns+" -o link show dev "+dev+" | sed -n 's/.*link\\/ether \\([0-9a-f:]*\\).*/\\1/p'"))
		if !regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`).MatchString(mac) {
			t.Fatalf("no MAC on %s in %s: %q", dev, ns, mac)
		}
		defer pi(t, "sudo rm -f "+hosts)
		pi(t, "printf '%s,%s,itclient\\n' "+mac+" "+fixed+" | sudo tee "+hosts+" >/dev/null && sudo chmod 0644 "+hosts)
		if o, err := ssh(t, 5*time.Minute, "pi", apply); err != nil {
			t.Fatalf("apply with a reservation: %v\n%s", err, o)
		}
		if conf := pi(t, "sudo cat /etc/pi-fortress/dhcp-"+name+".conf"); !contains(conf, "dhcp-host="+mac+","+fixed+",itclient\n") {
			t.Fatalf("dhcp-%s.conf does not carry the reservation:\n%s", name, conf)
		}
		mustSSH(t, "house", "sudo sh -c 'ip netns exec "+ns+" /sbin/dhclient -r -pf "+pidf+" -lf "+leasef+" "+dev+" >/dev/null 2>&1; ip -n "+ns+" addr flush dev "+dev+"; rm -f "+leasef+"'")
		if o, err := ssh(t, 60*time.Second, "house", "sudo ip netns exec "+ns+" /sbin/dhclient -4 -1 -pf "+pidf+" -lf "+leasef+" "+dev+" 2>&1"); err != nil {
			t.Fatalf("dhclient after the reservation: %v\n%s", err, o)
		}
		if lease := mustSSH(t, "house", "sudo cat "+leasef); !contains(lease, "fixed-address "+fixed+";") {
			t.Fatalf("the client was not given its reserved %s:\n%s", fixed, lease)
		}
		if a := mustSSH(t, "house", "sudo ip -n "+ns+" -4 -o addr show dev "+dev); !contains(a, " "+fixed+"/24") {
			t.Errorf("dhclient did not put %s on %s:\n%s", fixed, dev, a)
		}
		eventually(t, 15*time.Second, func() string {
			if l := pi(t, "sudo cat /var/lib/pi-fortress/dhcp-"+name+".leases"); !contains(l, " "+mac+" "+fixed+" ") {
				return "the Pi's lease file does not hold " + mac + " " + fixed + ":\n" + l
			}
			return ""
		})

		writeSeg("off")
		o, err := ssh(t, 5*time.Minute, "pi", apply)
		if err == nil {
			t.Errorf("apply took DHCP=off beside a reservation:\n%s", o)
		} else if !contains(o, "but DHCP is off") || !contains(o, "Nothing was changed.") {
			t.Errorf("the refusal of reservations with DHCP off does not say why:\n%s", o)
		}
		if s := strings.TrimSpace(pi(t, "systemctl is-active pi-fortress-dhcp@"+name+".service || true")); s != "active" {
			t.Errorf("the refused apply stopped pi-fortress-dhcp@%s (%s)", name, s)
		}
	})
	t.Run("DHCP off stops the instance and removes its conf and leases", func(t *testing.T) {
		writeSeg("off")
		if o, err := ssh(t, 5*time.Minute, "pi", apply); err != nil {
			t.Fatalf("apply with DHCP=off: %v\n%s", err, o)
		}
		if s := strings.TrimSpace(pi(t, "systemctl is-active pi-fortress-dhcp@"+name+".service || true")); s == "active" {
			t.Errorf("pi-fortress-dhcp@%s is still active with DHCP=off", name)
		}
		if l := pi(t, "sudo ls /etc/pi-fortress/dhcp-"+name+".conf /var/lib/pi-fortress/dhcp-"+name+".leases /etc/systemd/system/pi-fortress-dhcp@.service 2>/dev/null || true"); strings.TrimSpace(l) != "" {
			t.Errorf("DHCP=off left:\n%s", l)
		}
		if rs := pi(t, "sudo nft list ruleset"); contains(rs, `iifname "`+segIF+`" udp sport 68 udp dport 67`) {
			t.Errorf("UDP 67 is still open on %s with DHCP=off", segIF)
		}
	})
}
