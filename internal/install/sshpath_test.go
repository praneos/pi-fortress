package install

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Rows as the kernel prints them. 192.168.1.20:22 (0114A8C0:0016) has an
// established session, 0.0.0.0:22 listens (0A), and 192.168.1.20:443 is
// established but not SSH.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 1401A8C0:0016 0B01A8C0:D431 01 00000000:00000000 02:0009F0A1 00000000     0        0 2 4 0 20 4 30 10 -1
   2: 1401A8C0:01BB 0B01A8C0:D432 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 20 4 30 10 -1
`

// fe80::1 on port 2222, established.
const procTCP6 = `  sl  local_address                         remote_address                        st
   0: 000080FE000000000000000001000000:08AE 000080FE000000000000000002000000:C350 01 00000000:00000000
`

func TestSSHLocalIPsKeepsEstablishedSSHOnly(t *testing.T) {
	got := SSHLocalIPs([]byte(procTCP), map[int]bool{22: true})
	if len(got) != 1 || !got[0].Equal(net.ParseIP("192.168.1.20")) {
		t.Fatalf("got %v, want [192.168.1.20]", got)
	}
	got = SSHLocalIPs([]byte(procTCP6), map[int]bool{2222: true})
	if len(got) != 1 || !got[0].Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("tcp6: got %v, want [fe80::1]", got)
	}
	if got := SSHLocalIPs([]byte(procTCP6), map[int]bool{22: true}); len(got) != 0 {
		t.Fatalf("port 22 matched a session on 2222: %v", got)
	}
}

func TestSSHPortsReadsPortLinesOrDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	if got := SSHPorts(cfg); !got[22] || len(got) != 1 {
		t.Fatalf("no config: got %v, want only 22", got)
	}
	if err := os.WriteFile(cfg, []byte("# Port 99\nPort 2222\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", "x.conf"), []byte("port 2200\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got := SSHPorts(cfg)
	if !got[2222] || !got[2200] || got[22] || got[99] {
		t.Fatalf("got %v, want 2222 and 2200 only", got)
	}
}

func TestIfacesForNamesTheInterfaceThatHoldsTheAddress(t *testing.T) {
	addrs := map[string][]net.IP{
		"eth0":  {net.ParseIP("192.168.1.20")},
		"wlan0": {net.ParseIP("192.168.1.30")},
	}
	got := IfacesFor([]net.IP{net.ParseIP("192.168.1.20")}, addrs)
	if !slices.Equal(got, []string{"eth0"}) {
		t.Fatalf("got %v, want [eth0]", got)
	}
}

func TestCheckSSHPath(t *testing.T) {
	for _, c := range []struct {
		agent, house string
		ssh          []string
		refuse       string
	}{
		{"eth0", "", []string{"eth0"}, "agent port"},
		{"eth0", "", []string{"eth0.79"}, "agent port"},
		{"eth1", "eth0", []string{"eth0"}, "house port"},
		{"eth1", "", []string{"wlan0"}, ""},
		{"eth1", "", []string{"eth10"}, ""},
		{"eth1", "", nil, ""},
	} {
		err := checkSSHPath(c.agent, c.house, c.ssh)
		if c.refuse == "" && err != nil {
			t.Errorf("agent=%s house=%s ssh=%v: refused: %v", c.agent, c.house, c.ssh, err)
		}
		if c.refuse != "" && (err == nil || !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("agent=%s house=%s ssh=%v: err = %v, want %q", c.agent, c.house, c.ssh, err, c.refuse)
		}
	}
}

func TestInstallRefusesTheSSHPortAsAgentBeforeWritingAnything(t *testing.T) {
	r := newInstallRig(t)
	r.in.SSHIfaces = func() ([]string, error) { return []string{"eth1"}, nil }
	r.in.Bundle, r.in.Sig = r.bundle(200, r.priv)
	if err := r.in.Run(); err == nil || !strings.Contains(err.Error(), "SSH session arrives on eth1") {
		t.Fatalf("err = %v", err)
	}
	r.nothingWritten()
}
