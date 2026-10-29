package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/ca"
	"pi-fortress/internal/fetch"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/testsupport"
	"pi-fortress/internal/www"
)

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	if err := os.MkdirAll(filepath.Join(policy, "generated"), 0755); err != nil {
		t.Fatal(err)
	}
	c := &Config{
		PolicyDir:   policy,
		HouseEnv:    filepath.Join(dir, "house.env"),
		HouseHosts:  filepath.Join(dir, "house.hosts"),
		HouseLeases: filepath.Join(dir, "house.leases"),
		SecretsPath: filepath.Join(dir, "secrets.env"),
		ObservePath: filepath.Join(dir, "observe.json"),
		OffsetPath:  filepath.Join(dir, "dns.offset"),
		DNSLogPath:  filepath.Join(dir, "dns.jsonl"),
		StripLog:    filepath.Join(dir, "strip.jsonl"),
		MonitorDir:  filepath.Join(dir, "monitor"),
		LockPath:    filepath.Join(dir, "apply.lock"),
		Net:         map[string]string{"PI_IP": "10.77.0.1", "AGENT_IP": "10.77.0.10", "AGENT_NET": "10.77.0.0/24"},
	}
	write(t, c.SecretsPath, "")
	write(t, filepath.Join(policy, "blacklist.domains"), "pi-fortress-block.test\n")
	write(t, filepath.Join(policy, "house.domains"), "# ads\nads.example\n")
	write(t, c.HouseEnv, "HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.100\nHOUSE_DHCP_END=10.78.0.199\n# admin\nHOUSE_ADMIN_IP=\n#HOUSE_DNS_UPSTREAM=9.9.9.9\n")
	write(t, c.HouseHosts, "# reservations\naa:bb:cc:dd:ee:01,10.78.0.20,mac\n")
	write(t, c.HouseLeases, "1893456000 aa:bb:cc:dd:ee:01 10.78.0.20 mac 01:aa:bb:cc:dd:ee:01\n1893456000 aa:bb:cc:dd:ee:02 10.78.0.101 * *\nbogus line\n")
	write(t, c.ObservePath, `{"dns":{"example.com":{"count":2,"src":"10.77.0.10","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:01Z"},"house/ads.example":{"count":1,"segment":"house"}},"flows":{"10.77.0.10>1.2.3.4:443/tcp":{"dst":"1.2.3.4","dport":443,"proto":"tcp","bytes":900,"first_seen":"2026-01-01T00:00:02Z","last_seen":"2026-01-01T00:00:02Z"}},"started":"2026-01-01T00:00:00Z"}`)
	return c
}

func TestLeasesAndReservations(t *testing.T) {
	c := testConfig(t)
	leases := c.Leases()
	if len(leases) != 2 || leases[0].Hostname != "mac" || leases[1].Hostname != "" || leases[0].ClientID != "01:aa:bb:cc:dd:ee:01" {
		t.Fatalf("%+v", leases)
	}
	if got := c.Reservations(); len(got) != 1 || got[0] != (Reservation{MAC: "aa:bb:cc:dd:ee:01", IP: "10.78.0.20", Name: "mac"}) {
		t.Fatalf("%+v", got)
	}
	hosts := c.Hosts()
	if len(hosts) != 2 || !hosts[0].Reserved || hosts[0].Lease == nil || hosts[1].Reserved || hosts[1].IP != "10.78.0.101" {
		t.Fatalf("%+v", hosts)
	}
}

func TestReserveRoundTrip(t *testing.T) {
	c := testConfig(t)
	cases := []struct {
		mac, ip, name string
		wantIP, err   string
	}{
		{"AA:BB:CC:DD:EE:02", "", "phone", "10.78.0.2", ""},
		{"aa:bb:cc:dd:ee:03", "10.78.0.30", "tv", "10.78.0.30", ""},
		{"aa:bb:cc:dd:ee:04", "10.78.0.30", "dup", "", "already reserved"},
		{"aa:bb:cc:dd:ee:05", "10.79.0.5", "x", "", "not inside"},
		{"nope", "", "x", "", "invalid MAC"},
		{"aa:bb:cc:dd:ee:06", "", "bad name!", "", "invalid name"},
	}
	for _, tc := range cases {
		r, err := c.Reserve(tc.mac, tc.ip, tc.name)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("%s: want %q got %v", tc.mac, tc.err, err)
			}
			continue
		}
		if err != nil || r.IP != tc.wantIP {
			t.Fatalf("%s: %+v %v", tc.mac, r, err)
		}
	}
	text := testsupport.ReadFile(t, c.HouseHosts)
	if !strings.HasPrefix(text, "# reservations\n") || !strings.Contains(text, "aa:bb:cc:dd:ee:02,10.78.0.2,phone\n") || !strings.Contains(text, "aa:bb:cc:dd:ee:03,10.78.0.30,tv\n") {
		t.Fatal(text)
	}
	if _, err := c.Reserve("aa:bb:cc:dd:ee:02", "10.78.0.3", "phone"); err != nil || strings.Count(testsupport.ReadFile(t, c.HouseHosts), "aa:bb:cc:dd:ee:02") != 1 {
		t.Fatal(err, testsupport.ReadFile(t, c.HouseHosts))
	}
	if err := c.Unreserve("AA:BB:CC:DD:EE:02"); err != nil || strings.Contains(testsupport.ReadFile(t, c.HouseHosts), "ee:02") {
		t.Fatal(err, testsupport.ReadFile(t, c.HouseHosts))
	}
	if err := c.Unreserve("aa:bb:cc:dd:ee:02"); err == nil {
		t.Fatal("second unreserve succeeded")
	}
}

func TestNextFreeIPSkipsPoolAndLeases(t *testing.T) {
	c := testConfig(t)
	write(t, c.HouseEnv, "HOUSE_NET=10.78.0.0/30\nHOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.2\nHOUSE_DHCP_END=10.78.0.2\n")
	write(t, c.HouseHosts, "")
	write(t, c.HouseLeases, "")
	if _, err := c.NextFreeIP(); err == nil {
		t.Fatal("expected exhaustion")
	}
	write(t, c.HouseEnv, "HOUSE_NET=10.78.0.0/29\nHOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.2\nHOUSE_DHCP_END=10.78.0.3\n")
	write(t, c.HouseLeases, "1 aa:bb:cc:dd:ee:09 10.78.0.4 x *\n")
	if ip, err := c.NextFreeIP(); err != nil || ip != "10.78.0.5" {
		t.Fatal(ip, err)
	}
}

func TestSetHouseEnv(t *testing.T) {
	c := testConfig(t)
	cases := []struct{ key, val, err string }{
		{"HOUSE_ADMIN_IP", "10.78.0.20", ""},
		{"HOUSE_ADMIN_IP", "10.79.0.20", "not inside"},
		{"HOUSE_DNS_UPSTREAM", "1.1.1.1", ""},
		{"HOUSE_NET", "nope", "CIDR"},
		{"HOUSE_IF", "eth 1", "interface"},
		// The old name stays unknown. The code writes only HOUSE_PRIVATE_DNS.
		{"HOUSE_DEV_MODE", "on", "unknown key"},
		{"HOUSE_PRIVATE_DNS", "yes", "on or off"},
		{"HOUSE_PRIVATE_DNS", "on", ""},
		{"HOUSE_PRIVATE_DNS", "", ""},
		{"HOUSE_PRIVATE_DNS", "off", ""},
		{"HOUSE_BLOCK_DIRECT_IP", "no", "on or off"},
		{"HOUSE_BLOCK_DIRECT_IP", "off", ""},
		{"HOUSE_BLOCK_HTTP", "1", "on or off"},
		{"HOUSE_BLOCK_HTTP", "on", ""},
		{"WG_IF", "wg0", ""},
		{"WG_IF", "wg 0", "interface"},
		{"WG_BYPASS_MARK", "0x1", ""},
		{"WG_BYPASS_MARK", "1", "hex"},
		{"PATH", "/tmp", "unknown key"},
	}
	for _, tc := range cases {
		err := c.SetHouseEnv(tc.key, tc.val)
		if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Fatalf("%s=%s: %v", tc.key, tc.val, err)
		}
	}
	text := testsupport.ReadFile(t, c.HouseEnv)
	want := "HOUSE_IF=eth1\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\nHOUSE_DHCP_START=10.78.0.100\nHOUSE_DHCP_END=10.78.0.199\n# admin\nHOUSE_ADMIN_IP=10.78.0.20\n#HOUSE_DNS_UPSTREAM=9.9.9.9\nHOUSE_DNS_UPSTREAM=1.1.1.1\nHOUSE_PRIVATE_DNS=off\nHOUSE_BLOCK_DIRECT_IP=off\nHOUSE_BLOCK_HTTP=on\nWG_IF=wg0\nWG_BYPASS_MARK=0x1\n"
	if text != want {
		t.Fatalf("got:\n%s", text)
	}
	if c.House()["HOUSE_DNS_UPSTREAM"] != "1.1.1.1" {
		t.Fatal(c.House())
	}
}

func TestListsEdit(t *testing.T) {
	c := testConfig(t)
	if err := c.ListAdd("house.domains", "Tracker.Example."); err != nil {
		t.Fatal(err)
	}
	if err := c.ListAdd("house.domains", "ads.example"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.List("house.domains"); strings.Join(got, ",") != "ads.example,tracker.example" {
		t.Fatal(got)
	}
	if err := c.ListRemove("house.domains", "ads.example"); err != nil || testsupport.ReadFile(t, c.PolicyDir+"/house.domains") != "# ads\ntracker.example\n" {
		t.Fatal(err, testsupport.ReadFile(t, c.PolicyDir+"/house.domains"))
	}
	if err := c.ListAdd("blacklist.ips", "not-an-ip"); !errors.Is(err, errToken) {
		t.Fatal(err)
	}
	// The shipped defaults are code, not an overlay. They are not readable as a
	// list and never writable. If not, the next ship would revert the edit.
	if _, err := c.List("house_default.domains"); !errors.Is(err, errList) {
		t.Fatal("shipped defaults exposed as an overlay:", err)
	}
	if err := c.ListAdd("house_default.domains", "x.example"); !errors.Is(err, errList) {
		t.Fatal("shipped defaults writable:", err)
	}
	if err := c.ListAdd("../etc/passwd", "x"); !errors.Is(err, errList) {
		t.Fatal(err)
	}
	if err := c.ListAdd("never_block.ips", "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	// allow.domains is an operator list like the others. The TUI edits it, and
	// pi-ship does not change it (docs/paranoid_mode.md K16).
	if err := c.ListAdd("allow.domains", "Example.COM"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.List("allow.domains"); strings.Join(got, ",") != "example.com" {
		t.Fatal(got)
	}
	if err := c.ListAdd("allow.domains", "not a domain"); !errors.Is(err, errToken) {
		t.Fatal(err)
	}
}

func TestSSHAllowListEdit(t *testing.T) {
	c := testConfig(t)
	if err := c.ListAdd("ssh_allow.ips", "not-an-ip"); !errors.Is(err, errToken) {
		t.Fatal(err)
	}
	// ParseIPv4 as-is: ssh_allow.ips takes public addresses only, never RFC1918.
	if err := c.ListAdd("ssh_allow.ips", "10.0.0.0/8"); !errors.Is(err, errToken) {
		t.Fatal("reserved space listable:", err)
	}
	if err := c.ListAdd("ssh_allow.ips", "93.184.216.0/22"); err != nil {
		t.Fatal(err)
	}
	if err := c.ListAdd("ssh_allow.ips", "151.101.1.9"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.List("ssh_allow.ips"); strings.Join(got, ",") != "93.184.216.0/22,151.101.1.9" {
		t.Fatal(got)
	}
}

func TestFeedToggleAndFetchSkip(t *testing.T) {
	c := testConfig(t)
	write(t, c.sourcesPath(), `{"comment":"c","feeds":[{"id":"a","kind":"domains","format":"plain","url":"http://x/a","why":"w"},{"id":"b","kind":"domains","format":"plain","segment":"house","url":"http://x/b"}]}`)
	if err := c.SetFeedEnabled("b", false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetFeedEnabled("zzz", false); err == nil {
		t.Fatal("unknown feed accepted")
	}
	text := testsupport.ReadFile(t, c.sourcesPath())
	if !strings.Contains(text, `"enabled": false`) || !strings.Contains(text, `"why": "w"`) || !strings.Contains(text, `"comment": "c"`) {
		t.Fatal(text)
	}
	spec, err := c.Feeds()
	if err != nil || !spec.Feeds[0].On() || spec.Feeds[1].On() {
		t.Fatalf("%+v %v", spec, err)
	}
	f := &fetch.Fetcher{PolicyDir: c.PolicyDir, OutDir: filepath.Join(c.PolicyDir, "generated"), Get: func(url, _ string, _ time.Duration) (string, error) {
		return "bad.example\n", nil
	}}
	report, _, _, err := f.Run()
	if err != nil || !strings.Contains(strings.Join(report, "\n"), "SKIP b: disabled") {
		t.Fatal(report, err)
	}
	if err := c.SetFeedEnabled("b", true); err != nil || strings.Contains(testsupport.ReadFile(t, c.sourcesPath()), "enabled") {
		t.Fatal(err, testsupport.ReadFile(t, c.sourcesPath()))
	}
}

func TestWriteFileKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 || testsupport.ReadFile(t, p) != "new" {
		t.Fatal(fi.Mode(), testsupport.ReadFile(t, p))
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("tmp left behind")
	}
	fresh := filepath.Join(t.TempDir(), "sub", "g")
	if err := WriteFile(fresh, []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0640 {
		t.Fatal(fi.Mode())
	}
}

func TestTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	if got, err := Tail(p, 5); err != nil || got != nil {
		t.Fatal(got, err)
	}
	write(t, p, "a\n\nb\nc\n")
	if got, _ := Tail(p, 2); strings.Join(got, ",") != "b,c" {
		t.Fatal(got)
	}
	big := strings.Repeat("0123456789\n", 200000)
	write(t, p, big+"last\n")
	if got, _ := Tail(p, 1); len(got) != 1 || got[0] != "last" {
		t.Fatal(got)
	}
}

func TestLockContention(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock", "apply.lock")
	l, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(p); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if !Held(p) {
		t.Fatal("Held false while locked")
	}
	l.Release()
	if Held(p) {
		t.Fatal("Held true after release")
	}
}

func TestUnitsAndLogsViaExec(t *testing.T) {
	c := testConfig(t)
	var calls [][]string
	c.Exec = func(_ context.Context, argv []string) ([]byte, error) {
		calls = append(calls, argv)
		switch argv[0] + " " + argv[1] {
		case "systemctl is-active":
			return []byte("active\ninactive\n"), errors.New("exit 3")
		case "journalctl -k":
			return []byte("kernel: pi-fortress house-drop: IN=eth1\n"), nil
		}
		return nil, errors.New("unexpected " + strings.Join(argv, " "))
	}
	st := c.UnitsHealth()
	if st[0].State != "active" || st[1].State != "inactive" || st[2].State != "unknown" {
		t.Fatalf("%+v", st)
	}
	lines, err := c.Log(LogHouseDrops, 50)
	if err != nil || len(lines) != 1 || !strings.Contains(lines[0], "house-drop") {
		t.Fatal(lines, err)
	}
	if err := c.ReloadHouseDNS(); err == nil {
		t.Fatal("expected the fake exec to fail")
	}
	if got := calls[len(calls)-1]; strings.Join(got, " ") != "systemctl reload "+HouseDNSUnit {
		t.Fatal(got)
	}
	fs := c.firstSeen(10)
	if len(fs) != 3 || !strings.Contains(fs[1], "example.com") || !strings.Contains(fs[2], "flow") {
		t.Fatal(fs)
	}
}

func TestDeviceResetAndSlots(t *testing.T) {
	c := testConfig(t)
	write(t, c.StripLog, `{"a":1}`+"\n"+`{"b":2}`+"\n")
	d := c.Device()
	if d.DNSNames != 1 || d.HouseNames != 1 || d.DNSQueries != 2 || d.Flows != 1 || d.Bytes != 900 || d.Strips != 2 || d.LastSeen != "2026-01-01T00:00:02Z" || d.TopDests[0].Dst != "1.2.3.4" {
		t.Fatalf("%+v", d)
	}
	write(t, c.DNSLogPath, "some log\n")
	if err := c.ResetObserve(); err != nil {
		t.Fatal(err)
	}
	// The checkpoint is the offset and the inode where the code counted it.
	// Thus a rotation cannot change it into a position in a different file.
	off := testsupport.ReadFile(t, c.OffsetPath)
	if d := c.Device(); d.DNSNames != 0 || d.Flows != 0 || !strings.HasPrefix(off, "9 ") {
		t.Fatalf("%+v %q", d, off)
	}
	st := secrets.Open(c.SecretsPath)
	slot, err := st.MintKinds([]string{"GITHUB_TOKEN"}, map[string]string{"GITHUB_TOKEN": "sk-ant-oat01-SHOULDNEVERLEAK"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Slots()
	if err != nil || len(rows) != 1 || rows[0].Slot != slot || rows[0].Keys[0].Dummy != secrets.Placeholder(slot, "GITHUB_TOKEN") {
		t.Fatalf("%+v %v", rows, err)
	}
	if strings.Contains(rows[0].Keys[0].Dummy, "SHOULDNEVERLEAK") {
		t.Fatal(rows)
	}
	if kinds, err := c.DeleteSlot(strings.ToUpper(slot)); err != nil || len(kinds) != 1 {
		t.Fatal(kinds, err)
	}
	if rows, _ := c.Slots(); len(rows) != 0 {
		t.Fatal(rows)
	}
}

func TestStreamActions(t *testing.T) {
	c := testConfig(t)
	c.PfCmd = []string{"/bin/echo", "pf"}
	var out strings.Builder
	if err := c.Apply(context.Background(), true, &out); err != nil || out.String() != "pf apply --local\n" {
		t.Fatal(out.String(), err)
	}
	out.Reset()
	if err := c.Fetch(context.Background(), &out); err != nil || out.String() != "pf feeds run --fresh 0\n" {
		t.Fatal(out.String(), err)
	}
}

func TestVerbRoles(t *testing.T) {
	c := testConfig(t)
	c.Exec = func(context.Context, []string) ([]byte, error) { return []byte("active\n"), nil }
	adminOnly := []string{"apply", "fetch", "feed.enable", "house.env.set", "net.env.set", "segment.set", "agent.add", "agent.del", "dns.restart", "reboot", "poweroff", "slot.delete", "slot.restore", "slot.purge", "secrets.unlock", "secrets.lock"}
	for _, v := range Verbs {
		if v.Roles == 0 || v.Run == nil {
			t.Fatalf("%s: no role or no Run", v.Name)
		}
		if v.Roles&RoleAdmin == 0 {
			t.Fatalf("%s: admin cannot call it", v.Name)
		}
		wantDenied := slices.Contains(adminOnly, v.Name)
		if _, err := c.Call(RoleOperator, v.Name, Args{}); errors.Is(err, ErrDenied) != wantDenied {
			t.Fatalf("%s: operator err=%v want denied=%v", v.Name, err, wantDenied)
		}
	}
	if _, err := c.Call(RoleAdmin, "nope", Args{}); !errors.Is(err, ErrNoVerb) {
		t.Fatal(err)
	}
	if _, err := c.Call(RoleAdmin, "house.add", Args{List: "blacklist.domains", Value: "x.example"}); !errors.Is(err, errList) {
		t.Fatal("house verb reached an agent list:", err)
	}
	if _, err := c.Call(RoleAdmin, "house.add", Args{List: "house_default.domains", Value: "x.example"}); !errors.Is(err, errList) {
		t.Fatal("house verb reached the shipped defaults:", err)
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house.domains", Value: "x.example"}); err != nil {
		t.Fatal(err)
	}
	// The private-DNS lists are operator state, as the other house lists are.
	// But they open something. domains takes only a per-profile endpoint, never
	// a provider. ips takes single addresses, never a range, because the range
	// of a provider also holds its public resolvers.
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.domains", Value: "abc123.dns.controld.com"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"controld.com", "dns.controld.com"} {
		if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.domains", Value: v}); err == nil {
			t.Fatalf("%s accepted as a private DNS endpoint", v)
		}
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.ips", Value: "76.76.2.22"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.ips", Value: "76.76.2.0/24"}); err == nil {
		t.Fatal("a /24 accepted as a private DNS endpoint address")
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.ips", Value: "10.0.0.1"}); err == nil {
		t.Fatal("reserved space accepted as a private DNS provider")
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_private_dns.ips", Value: "76.0.0.0/8"}); err == nil {
		t.Fatal("a /8 accepted as a private DNS provider")
	}
	// house_direct_ip.allow shares the validator.
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_direct_ip.allow", Value: "76.76.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_direct_ip.allow", Value: "10.0.0.1"}); err == nil {
		t.Fatal("reserved space accepted in house_direct_ip.allow")
	}
	if _, err := c.Call(RoleOperator, "house.add", Args{List: "house_direct_ip.allow", Value: "76.0.0.0/8"}); err == nil {
		t.Fatal("a /8 accepted in house_direct_ip.allow")
	}
	got, err := c.Call(RoleOperator, "house.list", Args{List: "house.domains"})
	if err != nil || !slices.Contains(got.([]string), "x.example") {
		t.Fatal(got, err)
	}
	if _, err := c.Call(RoleAdmin, "apply", Args{}); !errors.Is(err, errNoWrite) {
		t.Fatal(err)
	}
}

func TestEnrollStats(t *testing.T) {
	c := testConfig(t)
	dir := t.TempDir()
	c.WWWDir, c.CACertPath = dir, filepath.Join(dir, "ca-cert.pem")
	write(t, filepath.Join(dir, "setup.sh"), "#!/bin/sh\n")
	st, err := c.EnrollStats()
	if err != nil || st.CAFP != "" || st.SetupSH.IsZero() || !st.CAPEM.IsZero() {
		t.Fatalf("%+v %v", st, err)
	}
	if err := ca.Init(filepath.Join(dir, "ca.pem"), c.CACertPath); err != nil {
		t.Fatal(err)
	}
	st, _ = c.EnrollStats()
	if len(st.CAFP) != 16 || time.Until(st.CANotAfter) < 365*24*time.Hour || st.CASubject == "" {
		t.Fatalf("%+v", st)
	}
}

func TestClaimsQuarantineAndLedger(t *testing.T) {
	c := testConfig(t)
	c.WWWDir = t.TempDir()
	c.UseLog = filepath.Join(t.TempDir(), "use.jsonl")
	if err := os.MkdirAll(filepath.Join(c.WWWDir, "claims"), 0770); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(c.WWWDir, "setup.sh"), "#!/bin/sh\n")
	write(t, filepath.Join(c.WWWDir, "ca.pem"), "-----BEGIN CERTIFICATE-----\n")
	st := secrets.Open(c.SecretsPath)
	slot, err := st.MintKinds([]string{"CLAUDE_OAT", "CLAUDE_ORT"}, map[string]string{"CLAUDE_OAT": "sk-ant-oat01-x", "CLAUDE_ORT": "sk-ant-ort01-y"})
	if err != nil {
		t.Fatal(err)
	}
	write(t, c.UseLog, `{"t":"2026-09-01T10:00:00Z","slot":"`+slot+`","host":"api.anthropic.com"}`+"\n"+`{"t":"2026-09-02T10:00:00Z","slot":"`+slot+`","host":"claude.ai"}`+"\n")
	rows, _ := c.Slots()
	if len(rows) != 1 || rows[0].LastHost != "claude.ai" || rows[0].LastUsed.Day() != 2 || !rows[0].DisabledAt.IsZero() {
		t.Fatalf("%+v", rows)
	}
	v, err := c.Call(RoleOperator, "claim.issue", Args{Name: strings.ToUpper(slot)})
	if err != nil {
		t.Fatal(err)
	}
	cl := v.(Claim)
	// -f, not bare -s: without -f, the code saves a 404 body and checks it. The
	// code checks the script against its hash before sh sees it.
	if len(cl.Code) != 8 || !strings.Contains(cl.Command, `curl -fsSo "$f" http://10.77.0.1/claim/`+cl.Code+" && ") ||
		!strings.Contains(cl.Command, `sha256sum -c && sh "$f"`) || strings.HasSuffix(cl.Command, "| sh") ||
		len(cl.CommandLines) != 3 || time.Until(cl.Expires) > www.ClaimTTL {
		t.Fatalf("%+v", cl)
	}
	if _, err := os.Stat(filepath.Join(c.WWWDir, "claims", cl.Code+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(RoleOperator, "claim.issue", Args{Name: "0000000000000000"}); err == nil {
		t.Fatal("unknown slot claimed")
	}
	if _, err := c.Call(RoleOperator, "slot.disable", Args{Name: slot}); err != nil {
		t.Fatal(err)
	}
	if rows, _ = c.Slots(); rows[0].DisabledAt.IsZero() {
		t.Fatal("not disabled")
	}
	if _, err := c.Call(RoleAdmin, "claim.issue", Args{Name: slot}); err == nil {
		t.Fatal("disabled slot claimed")
	}
	if _, err := c.Call(RoleAdmin, "slot.restore", Args{Name: slot}); err != nil {
		t.Fatal(err)
	}
	_ = www.AppendEvent(filepath.Join(c.WWWDir, "claims"), www.Event{Ev: "redeemed", Code: cl.Code, Slot: slot, IP: "10.77.0.10"})
	_ = www.AppendEvent(filepath.Join(c.WWWDir, "claims"), www.Event{Ev: "setup", IP: "10.77.0.10", Path: "/setup.sh"})
	es, _ := c.EnrollStats()
	if es.Issued != 1 || es.Redeemed != 1 || es.LastRedeemIP != "10.77.0.10" || es.LastRedeem.IsZero() || es.LastSetup.IsZero() || es.Slots != 1 || es.Disabled != 0 {
		t.Fatalf("%+v", es)
	}
	if _, err := c.Call(RoleAdmin, "slot.purge", Args{Name: slot}); err != nil {
		t.Fatal(err)
	}
	if rows, _ = c.Slots(); len(rows) != 0 {
		t.Fatal(rows)
	}
}

func TestWriteFileRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	write(t, victim, "keep")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("owned"), 0644); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatal(err)
	}
	if testsupport.ReadFile(t, victim) != "keep" {
		t.Fatal("wrote through a symlink target")
	}
	target := filepath.Join(dir, "target")
	write(t, target, "old")
	if err := os.Symlink(victim, target+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(target, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if testsupport.ReadFile(t, victim) != "keep" || testsupport.ReadFile(t, target) != "new" {
		t.Fatal(testsupport.ReadFile(t, victim), testsupport.ReadFile(t, target))
	}
	// The staging name is no longer target + ".tmp". Thus a symlink at that
	// location has no effect. The point is that WriteFile does not touch it.
	// The old exclusive create worked because the code unlinked that name. That
	// unlink is also how two concurrent writers deleted the staging file of each
	// other. WriteFile removes only what it created.
	if _, err := os.Lstat(target + ".tmp"); err != nil {
		t.Fatalf("WriteFile removed a path it does not own: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".target.") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}
}

func TestReserveRefusesReservedAddresses(t *testing.T) {
	c := testConfig(t)
	if err := c.SetHouseEnv("HOUSE_ADMIN_IP", "10.78.0.20"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"10.78.0.1":   "gateway",
		"10.78.0.20":  "HOUSE_ADMIN_IP",
		"10.78.0.0":   "network or broadcast",
		"10.78.0.255": "network or broadcast",
		"10.79.0.5":   "not inside",
		"10.78.0.5":   "",
	}
	for ip, want := range cases {
		_, err := c.Reserve("aa:bb:cc:dd:ee:09", ip, "")
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Fatalf("%s: want %q got %v", ip, want, err)
		}
	}
}

func TestSetHouseEnvRevalidatesTuple(t *testing.T) {
	c := testConfig(t)
	before := testsupport.ReadFile(t, c.HouseEnv)
	bad := []struct{ key, val, err string }{
		{"HOUSE_NET", "10.79.0.0/24", "HOUSE_IP"},
		{"HOUSE_NET", "10.78.0.0/31", "no room"},
		{"HOUSE_IP", "10.78.0.150", "inside the DHCP range"},
		{"HOUSE_IP", "10.78.0.0", "network or broadcast"},
		{"HOUSE_DHCP_START", "10.78.0.200", "below"},
		{"HOUSE_DHCP_END", "10.78.0.255", "network or broadcast"},
		{"HOUSE_ADMIN_IP", "10.78.0.1", "is the gateway"},
		{"HOUSE_IF", "eth0;reboot", "interface"},
		{"HOUSE_IF", "$(id)", "interface"},
		{"HOUSE_IF", "1eth", "interface"},
		{"HOUSE_IF", "abcdefghijklmnop", "interface"},
	}
	for _, tc := range bad {
		if err := c.SetHouseEnv(tc.key, tc.val); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s=%s: want %q got %v", tc.key, tc.val, tc.err, err)
		}
	}
	if testsupport.ReadFile(t, c.HouseEnv) != before {
		t.Fatal("a refused edit reached the file")
	}
	good := [][2]string{{"HOUSE_IF", "wlan0.10"}, {"HOUSE_NET", "10.78.0.0/23"}, {"HOUSE_DHCP_END", "10.78.1.254"}}
	for _, kv := range good {
		if err := c.SetHouseEnv(kv[0], kv[1]); err != nil {
			t.Fatalf("%s=%s: %v", kv[0], kv[1], err)
		}
	}
}

func TestTryLockRefusesSymlinkAndMakesDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	write(t, real, "")
	link := filepath.Join(dir, "apply.lock")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if Held(link) {
		t.Fatal("Held true on a symlink")
	}
	p := filepath.Join(dir, "sub", "apply.lock")
	l, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm()&0027 != 0 {
		t.Fatal(fi.Mode())
	}
}

func TestFetchTakesApplyLock(t *testing.T) {
	c := testConfig(t)
	c.PfCmd = []string{"/bin/echo", "pf"}
	l, err := TryLock(c.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if _, err := c.Call(RoleAdmin, "fetch", Args{Out: &out}); !errors.Is(err, ErrLocked) || out.Len() != 0 {
		t.Fatal(err, out.String())
	}
	l.Release()
	if _, err := c.Call(RoleAdmin, "fetch", Args{Out: &out}); err != nil || out.String() != "pf feeds run --fresh 0\n" {
		t.Fatal(err, out.String())
	}
	if Held(c.LockPath) {
		t.Fatal("lock still held after fetch")
	}
}

func TestActionVerbsBoundedAndConfirmed(t *testing.T) {
	c := testConfig(t)
	c.Stream = func(ctx context.Context, _ []string, _ io.Writer) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("no deadline")
		}
		return nil
	}
	// apply is the exception: TestApplyVerbHasNoDeadline.
	for _, v := range []string{"fetch"} {
		if _, err := c.Call(RoleAdmin, v, Args{Out: io.Discard}); err != nil {
			t.Fatal(v, err)
		}
	}
	var calls [][]string
	c.Exec = func(_ context.Context, argv []string) ([]byte, error) {
		calls = append(calls, argv)
		return nil, nil
	}
	for _, v := range []string{"reboot", "poweroff"} {
		if _, err := c.Call(RoleAdmin, v, Args{}); !errors.Is(err, ErrConfirm) {
			t.Fatal(v, err)
		}
	}
	if len(calls) != 0 {
		t.Fatal(calls)
	}
	if _, err := c.Call(RoleAdmin, "reboot", Args{Confirm: true}); err != nil || len(calls) != 1 || strings.Join(calls[0], " ") != "systemctl reboot" {
		t.Fatal(err, calls)
	}
}
