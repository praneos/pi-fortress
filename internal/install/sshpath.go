package install

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A new Pi is often set up over SSH. pf apply gives the agent port (and
// the house port) a new address. If the SSH session of the operator
// arrives on that port, the session stops in the middle of the install,
// and the operator cannot see the result. Thus pf install refuses that
// plan before the first file write.

// SSHPorts reads the Port lines of sshd_config and of each
// sshd_config.d/*.conf next to it. With no Port line, sshd listens on 22.
func SSHPorts(sshdConfig string) map[int]bool {
	ports := map[int]bool{}
	files := []string{sshdConfig}
	more, _ := filepath.Glob(filepath.Join(filepath.Dir(sshdConfig), "sshd_config.d", "*.conf"))
	files = append(files, more...)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
				if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 && n < 65536 {
					ports[n] = true
				}
			}
		}
	}
	if len(ports) == 0 {
		ports[22] = true
	}
	return ports
}

// SSHLocalIPs returns the local address of each established TCP
// connection in a /proc/net/tcp or /proc/net/tcp6 table whose local port
// is in ports: the address that an inbound SSH session arrived on. The
// kernel prints each 32-bit word of the address in host byte order. The
// Pi (arm64) and amd64 are little-endian, so each word is reversed.
func SSHLocalIPs(table []byte, ports map[int]bool) []net.IP {
	var ips []net.IP
	sc := bufio.NewScanner(bytes.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "01" { // 01: ESTABLISHED
			continue
		}
		addr, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil || !ports[int(p)] {
			continue
		}
		raw, err := hex.DecodeString(addr)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for i := 0; i < len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		ips = append(ips, net.IP(raw))
	}
	return ips
}

// IfacesFor names the interfaces that hold one of ips. addrs maps an
// interface name to its addresses.
func IfacesFor(ips []net.IP, addrs map[string][]net.IP) []string {
	var out []string
	for name, have := range addrs {
		for _, a := range have {
			if containsIP(ips, a) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

func containsIP(ips []net.IP, a net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(a) {
			return true
		}
	}
	return false
}

// LiveSSHIfaces is the real SSHIfaces: the interfaces that carry an
// inbound SSH session now.
func LiveSSHIfaces() ([]string, error) {
	ports := SSHPorts("/etc/ssh/sshd_config")
	var ips []net.IP
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		ips = append(ips, SSHLocalIPs(b, ports)...)
	}
	if len(ips) == 0 {
		return nil, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	addrs := map[string][]net.IP{}
	for _, i := range ifs {
		as, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				addrs[i.Name] = append(addrs[i.Name], n.IP)
			}
		}
	}
	return IfacesFor(ips, addrs), nil
}

// checkSSHPath refuses an agent or house port that carries the SSH
// session of the operator, or a VLAN on it (eth0.20 on eth0).
func checkSSHPath(agent, house string, sshIfaces []string) error {
	for _, s := range sshIfaces {
		for _, p := range []struct{ role, name string }{{"agent", agent}, {"house", house}} {
			if p.name == "" || (s != p.name && !strings.HasPrefix(s, p.name+".")) {
				continue
			}
			return fmt.Errorf("pf install: your SSH session arrives on %s, and %s would be the %s port. "+
				"The install gives that port a new address, so this session would stop part-way. "+
				"Connect over the uplink (for example Wi-Fi), or choose a different %s port", s, p.name, p.role, p.role)
		}
	}
	return nil
}
