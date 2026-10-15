//go:build vagrant

package itest

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// agentVMTests are about the agent as a guest of this host, not as a
// client of the gateway: what it got from the checkout, what host code it
// can still talk to, and if it can keep time without the Guest Additions
// that did this before. The gateway side cannot reach any of it. Thus it
// has its own group.
func agentVMTests(t *testing.T) {
	t.Run("the agent holds its own scripts and the topology, not the checkout", func(t *testing.T) {
		out := agent(t, "cd /vagrant 2>/dev/null && find . -type f | sort")
		if !contains(out, "./vm/agent/routes.sh") || !contains(out, "./vm/pi/net.env") {
			t.Fatalf("/vagrant lacks what the provisioner needs:\n%s", out)
		}
		for _, leak := range []string{"alert.url", "docs/", "internal/", "Vagrantfile", "Makefile", "agent-credentials"} {
			if contains(out, leak) {
				t.Errorf("/vagrant holds %s; the agent is handed only vm/agent, net.env and the public CA", leak)
			}
		}
		if got := strings.TrimSpace(agent(t, "findmnt -n -o FSTYPE /vagrant || true")); got == "vboxsf" {
			t.Errorf("/vagrant is a vboxsf mount: root in the agent can write to the operator's checkout")
		}
	})

	t.Run("no Guest Additions module is loaded", func(t *testing.T) {
		if out := strings.TrimSpace(agent(t, "lsmod | grep -E '^vbox(guest|sf|video) ' || true")); out != "" {
			t.Errorf("the guest still loads VirtualBox modules, the HGCM door to the host:\n%s", out)
		}
	})

	t.Run("the clock follows the gateway without them", func(t *testing.T) {
		if out := strings.TrimSpace(agent(t, "systemctl is-enabled pi-fortress-agent-clock.timer")); out != "enabled" {
			t.Fatalf("pi-fortress-agent-clock.timer is %q", out)
		}
		// A host suspend leaves the clock one hour wrong. The unit must
		// correct it without help, from the one port that the lock allows.
		agent(t, "sudo date -s '+1 hour' >/dev/null && sudo systemctl start pi-fortress-agent-clock.service")
		out := strings.TrimSpace(agent(t, "echo $(( $(date +%s) - $(date -d \"$(curl -fsSI --max-time 5 http://10.77.0.1/ca.pem | sed -n 's/^[Dd]ate: //p' | tr -d '\\r')\" +%s) ))"))
		if out != "0" && out != "1" && out != "-1" && out != "2" && out != "-2" {
			t.Errorf("the agent's clock is %s s from the gateway's after the unit ran", out)
		}
	})

	t.Run("the agent user has the sudo it was provisioned with and no other way up", func(t *testing.T) {
		want := strings.TrimSpace(agent(t, "sed -n 's/^AGENT_SUDO=//p' /etc/pi-fortress/agent.env"))
		if want == "" {
			t.Skip("this agent was provisioned before AGENT_SUDO existed")
		}
		// Ask sudo itself, as agent, and discard its output. The harness
		// reads "a password is required" anywhere in the output as "this
		// account has no sudo", and skips.
		can := strings.TrimSpace(agent(t, "sudo -u agent sudo -n true >/dev/null 2>&1 && echo yes || echo no"))
		if (want == "1") != (can == "yes") {
			t.Errorf("AGENT_SUDO=%s in agent.env but agent running sudo -n true: %s", want, can)
		}
		// With no sudo of its own, the account must not be able to borrow
		// the sudo of vagrant. A bento box ships vagrant with a password that
		// everyone knows and an sshd that accepts passwords. vagrant has sudo.
		for _, u := range []string{"vagrant", "agent", "root"} {
			if f := strings.TrimSpace(agent(t, "sudo awk -F: -v u="+u+" '$1==u{print substr($2,1,1)}' /etc/shadow")); f != "!" && f != "*" {
				t.Errorf("%s has a usable password (shadow field starts %q): any local user can su to it", u, f)
			}
		}
		if out := strings.TrimSpace(agent(t, "id -nG agent")); contains(" "+out+" ", " sudo ") {
			t.Errorf("agent is in the sudo group: %s", out)
		}
		if out := strings.TrimSpace(agent(t, "sudo -u agent sh -c 'test -r /home/vagrant/.ssh/authorized_keys && echo readable || echo no'")); out != "no" {
			t.Errorf("agent can read vagrant's ssh directory")
		}
	})

	t.Run("root in the agent cannot reach this host over its own NIC", func(t *testing.T) {
		agentReachesHost(t)
	})
	t.Run("the hypervisor settings read back as pinned", func(t *testing.T) {
		if target() == "cloudlab" {
			t.Skip("the cloud lab's VMs are libvirt domains, not VirtualBox")
		}
		if _, err := exec.LookPath("VBoxManage"); err != nil {
			t.Skip("no VBoxManage on this host")
		}
		_, self, _, _ := runtime.Caller(0)
		script := filepath.Join(filepath.Dir(self), "..", "agent", "audit.sh")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, script, "pi-fortress-agent").CombinedOutput(); err != nil {
			t.Errorf("vm/agent/audit.sh: %v\n%s", err, out)
		}
	})
}

// agentReachesHost is TODO "Lab: the fence cannot see services the host
// listens on". The agent NIC ends on this host and also at the gateway:
// a host-only management NIC in the lab, or else the VLAN device of a
// bridged agent. Linux answers on any interface for any address that it
// owns. Thus root in the VM, after it flushes its own guest lock, can
// send directly to the listeners of the host, and the fence never sees
// the connection. This test acts as that agent. It opens a listener on
// the host, opens a hole in the guest lock for the host address, pins
// the address to the host MAC on the agent NIC, and dials. The connection
// must not complete. When bridged, it cannot: the host has no route out
// of the agent VLAN device, so its reverse-path filter drops the SYN
// (TcpExtIPReversePathFilter counted each one on the desk host,
// 2026-09-27). An answer would leave by the routes of the host, through
// the desk segment of the Pi, whose isolation drops it. In the host-only
// lab, the host route is the management NIC itself. Thus the host guard
// that vm/agent/cut-nat.sh installs stops it. Without a guard this test
// fails, and that is the purpose (cut-nat.sh prints the command).
func agentReachesHost(t *testing.T) {
	if target() == "cloudlab" {
		t.Skip("the cloud lab's VMs are libvirt domains, not VirtualBox")
	}
	if _, err := exec.LookPath("VBoxManage"); err != nil {
		t.Skip("no VBoxManage on this host")
	}
	info, err := exec.Command("VBoxManage", "showvminfo", "pi-fortress-agent", "--machinereadable").Output()
	if err != nil {
		t.Skipf("no VirtualBox agent VM: %v", err)
	}
	var ifc string
	for _, ln := range strings.Split(string(info), "\n") {
		k, v, _ := strings.Cut(ln, "=")
		if strings.HasPrefix(k, "hostonlyadapter") || strings.HasPrefix(k, "bridgeadapter") {
			ifc = strings.Trim(v, `"`)
			break
		}
	}
	if ifc == "" {
		t.Skip("the agent VM has neither a host-only nor a bridged NIC")
	}
	nic, err := net.InterfaceByName(ifc)
	if err != nil {
		t.Skipf("host interface %s: %v", ifc, err)
	}
	// The host address on that NIC (host-only), or else the address that
	// its default route leaves by. A bridged host has no address on the
	// agent VLAN, but it still answers there for its other addresses.
	var addr string
	if as, _ := nic.Addrs(); len(as) > 0 {
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				addr = ipn.IP.String()
				break
			}
		}
	}
	if addr == "" {
		c, err := net.Dial("udp4", "192.0.2.1:9")
		if err != nil {
			t.Skipf("no host address to aim at: %v", err)
		}
		addr = c.LocalAddr().(*net.UDPAddr).IP.String()
		c.Close()
	}
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c.RemoteAddr().String()
			c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	// One bash -c, with cleanup on EXIT in all cases: it removes the rule
	// handle, the host route and the neighbour entry again.
	script := strings.Join([]string{
		"set -u",
		". /etc/pi-fortress/agent.env",
		"dev=${MGMT_IF:-${NET_IF}}",
		"h=$(nft -a insert rule inet agent_lock output ip daddr " + addr + " accept 2>/dev/null; nft -a list chain inet agent_lock output | awk '/ip daddr " + addr + " accept/ {print $NF; exit}')",
		"trap 'nft delete rule inet agent_lock output handle $h; ip route del " + addr + "/32 dev $dev 2>/dev/null; ip neigh del " + addr + " dev $dev 2>/dev/null' EXIT",
		"ip neigh replace " + addr + " lladdr " + nic.HardwareAddr.String() + " dev $dev nud permanent",
		"ip route replace " + addr + "/32 dev $dev",
		"timeout 8 nc -z -w 4 " + addr + " " + port + "; echo rc=$?",
	}, "; ")
	out, err := ssh(t, 60*time.Second, "agent", "sudo bash -c "+shellQuote(script))
	if err != nil && !strings.Contains(out, "rc=") {
		t.Fatalf("agent: %v\n%s", err, out)
	}
	t.Logf("agent dial to %s:%s over %s: %s", addr, port, ifc, strings.TrimSpace(out))
	if !strings.Contains(out, "rc=") {
		t.Fatalf("the agent's dial did not run:\n%s", out)
	}
	if strings.Contains(out, "rc=0") {
		t.Errorf("the agent opened a connection to %s:%s over %s without passing the gateway\n%s", addr, port, ifc, out)
	}
	select {
	case from := <-accepted:
		t.Errorf("the host accepted a connection from %s over %s", from, ifc)
	case <-time.After(500 * time.Millisecond):
	}
	if left := agent(t, "sudo nft list chain inet agent_lock output"); strings.Contains(left, addr) {
		t.Errorf("the guest lock kept the test's hole for %s:\n%s", addr, left)
	}
}
