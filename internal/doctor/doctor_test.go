package doctor

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/render"
)

func up(name string) *net.Interface {
	return &net.Interface{Name: name, Flags: net.FlagUp}
}

func addr(cidr string) net.Addr {
	ip, n, _ := net.ParseCIDR(cidr)
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

// stub points every probe at fixtures and restores them after the test.
func stub(t *testing.T) {
	t.Helper()
	oldIf, oldAddrs, oldRead := ifaceByName, ifaceAddrs, readFile
	oldUnit, oldUSB, oldRes := unitActive, usbList, resolveVia
	t.Cleanup(func() {
		ifaceByName, ifaceAddrs, readFile = oldIf, oldAddrs, oldRead
		unitActive, usbList, resolveVia = oldUnit, oldUSB, oldRes
	})
	ifaceByName = func(string) (*net.Interface, error) { return nil, errors.New("no such network interface") }
	ifaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nil, nil }
	readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	unitActive = func(string) bool { return true }
	usbList = func() string { return "" }
	resolveVia = func(string, string, time.Duration) ([]string, error) { return nil, errors.New("timeout") }
}

func TestMissingInterfaceNamesTheAdapter(t *testing.T) {
	stub(t)
	usbList = func() string {
		return "Bus 004 Device 002: ID 0bda:8151 Realtek Semiconductor Corp. RTL8151\n"
	}
	rs := Check(Segment{Name: "house", IF: "eth1", IP: "10.78.0.1"})
	if len(rs) != 1 || rs[0].Status != Fail {
		t.Fatalf("want one failed rung, got %+v", rs)
	}
	for _, want := range []string{"RTL8153", "pi-fortress-usb-nic-switch.service", "plug it back in"} {
		if !strings.Contains(rs[0].Detail, want) {
			t.Fatalf("hint lacks %q: %q", want, rs[0].Detail)
		}
	}
}

func TestMissingInterfaceWithoutKnownAdapter(t *testing.T) {
	stub(t)
	rs := Check(Segment{Name: "house", IF: "eth1", IP: "10.78.0.1"})
	if strings.Contains(rs[0].Detail, "usb_modeswitch") {
		t.Fatalf("hint offered with no such device on the bus: %q", rs[0].Detail)
	}
}

func TestAddressMissingStopsTheLadder(t *testing.T) {
	stub(t)
	ifaceByName = func(n string) (*net.Interface, error) { return up(n), nil }
	rs := Check(Segment{Name: "house", IF: "eth1", IP: "10.78.0.1", Unit: "u"})
	if len(rs) != 2 {
		t.Fatalf("want link + address only, got %d rungs", len(rs))
	}
	if rs[1].Rung != "address" || rs[1].Status != Fail {
		t.Fatalf("want a failed address rung, got %+v", rs[1])
	}
	if !strings.Contains(rs[1].Detail, "pf apply") {
		t.Fatalf("no remedy named: %q", rs[1].Detail)
	}
}

// The state of the box at 00:40 on 2026-09-09: eth1 up with no
// address, while apply had just printed HOUSE_IP=10.78.0.1.
func TestReportExitsNonZeroOnFail(t *testing.T) {
	rs := []Result{{Rung: "link", Status: OK}, {Rung: "address", Status: Fail}}
	var b strings.Builder
	if code := Report(&b, rs); code != 1 {
		t.Fatalf("want exit 1, got %d", code)
	}
	if !strings.Contains(b.String(), "FAIL") {
		t.Fatalf("failure not marked: %q", b.String())
	}
}

func TestNoLeasesBlamesTheFarSide(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "house.leases")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readFile = os.ReadFile
	s := Segment{Name: "house", Leases: empty, DHCP: true}
	got := s.leaseRung(func(rung, detail string, st Status) Result {
		return Result{Rung: rung, Detail: detail, Status: st}
	})
	if got.Status != Warn || !strings.Contains(got.Detail, "own DHCP") {
		t.Fatalf("want a far-side warning, got %+v", got)
	}
}

func TestLeasesCounted(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "house.leases")
	body := "1757000000 aa:bb:cc:dd:ee:ff 10.78.0.100 mac *\n1757009999 11:22:33:44:55:66 10.78.0.101 tab *\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	readFile = os.ReadFile
	got := Segment{Leases: f}.leaseRung(func(rung, detail string, st Status) Result {
		return Result{Rung: rung, Detail: detail, Status: st}
	})
	if got.Status != OK || !strings.HasPrefix(got.Detail, "2, newest") {
		t.Fatalf("want 2 leases, got %+v", got)
	}
}

func TestLoadWithoutHouseEnv(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	body := "PI_IP=10.77.0.1\nINT_IF=eth0\nALLOW_DOMAIN=example.com\n"
	if err := os.WriteFile(netEnv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	segs, err := Load(netEnv, filepath.Join(dir, "absent.env"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || segs[0].Name != "agent" || segs[0].IF != "eth0" {
		t.Fatalf("want one agent segment on eth0, got %+v", segs)
	}
	if segs[0].probe != "example.com" {
		t.Fatalf("probe not taken from ALLOW_DOMAIN: %q", segs[0].probe)
	}
}

// If INT_IF is unset, the code uses the interface that holds PI_IP, as
// apply does. With neither, the message must say both.
func TestLoadWithoutIntIF(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("PI_IP=10.77.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(netEnv, filepath.Join(dir, "absent.env"), "")
	if err == nil || !strings.Contains(err.Error(), "10.77.0.1") {
		t.Fatalf("want the address named in the error, got %v", err)
	}
}

func TestFullLadder(t *testing.T) {
	stub(t)
	ifaceByName = func(n string) (*net.Interface, error) { return up(n), nil }
	ifaceAddrs = func(*net.Interface) ([]net.Addr, error) { return []net.Addr{addr("10.78.0.1/24")}, nil }
	resolveVia = func(_, name string, _ time.Duration) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	s := Segment{Name: "house", IF: "eth1", IP: "10.78.0.1", Unit: "u", probe: "example.com"}
	rs := Check(s)
	var b strings.Builder
	if code := Report(&b, rs); code != 0 {
		t.Fatalf("healthy segment reported %d:\n%s", code, b.String())
	}
	for _, want := range []string{"link", "address", "resolver", "resolve"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("rung %q missing:\n%s", want, b.String())
		}
	}
}

func TestPulledCableIsNotGreen(t *testing.T) {
	stub(t)
	readFile = func(path string) ([]byte, error) {
		switch filepath.Base(path) {
		case "speed":
			return []byte("1000\n"), nil
		case "carrier":
			return []byte("0\n"), nil
		}
		return nil, os.ErrNotExist
	}
	got, st := linkRung("eth1", up("eth1"))
	if !strings.Contains(got, "disconnected") || !strings.Contains(got, "no carrier") {
		t.Fatalf("want it called out as disconnected, got %q", got)
	}
	if st != Warn {
		t.Fatalf("a pulled cable read as %v, not a warning", st)
	}
}

// A pulled cable is not a failure: segments need not stay connected.
// But the ladder must say so plainly, and the process exit must stay 0
// when a disconnected link is the only non-OK rung.
func TestPulledCableReportsDisconnectedAndExitsZero(t *testing.T) {
	stub(t)
	ifaceByName = func(n string) (*net.Interface, error) { return up(n), nil }
	ifaceAddrs = func(*net.Interface) ([]net.Addr, error) { return []net.Addr{addr("10.78.0.1/24")}, nil }
	resolveVia = func(_, name string, _ time.Duration) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	readFile = func(path string) ([]byte, error) {
		if filepath.Base(path) == "carrier" {
			return []byte("0\n"), nil
		}
		return nil, os.ErrNotExist
	}
	s := Segment{Name: "house", IF: "eth1", IP: "10.78.0.1", Unit: "u", probe: "example.com"}
	rs := Check(s)
	if rs[0].Rung != "link" || rs[0].Status != Warn {
		t.Fatalf("want a warn link rung, got %+v", rs[0])
	}
	if rs[0].Detail != "eth1: disconnected (no carrier: nothing on the other end of the cable)" {
		t.Fatalf("detail wording changed: %q", rs[0].Detail)
	}
	var b strings.Builder
	if code := Report(&b, rs); code != 0 {
		t.Fatalf("a disconnected segment exited %d, want 0:\n%s", code, b.String())
	}
}

// house.env may name only the interface. apply sets a default address, so
// doctor must set the same default, or it asserts against "".
func TestLoadDefaultsHouseIP(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	houseEnv := filepath.Join(dir, "house.env")
	for path, body := range map[string]string{
		netEnv:   "PI_IP=10.77.0.1\nINT_IF=eth0\n",
		houseEnv: "HOUSE_IF=eth1\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	segs, err := Load(netEnv, houseEnv, "")
	if err != nil {
		t.Fatal(err)
	}
	if segs[1].IP != render.DefaultHouseIP {
		t.Fatalf("HOUSE_IP not defaulted: %q", segs[1].IP)
	}
}

// The lease file is 0640 root:root. So an unprivileged run must say
// so, and must not print the path twice inside a wrapped error.
func TestLeasesUnreadableAsksForSudo(t *testing.T) {
	stub(t)
	readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	got := Segment{Leases: "/var/lib/pi-fortress/house.leases"}.leaseRung(
		func(rung, detail string, st Status) Result {
			return Result{Rung: rung, Detail: detail, Status: st}
		})
	if got.Status != Warn || !strings.Contains(got.Detail, "sudo") {
		t.Fatalf("want a sudo hint, got %+v", got)
	}
	if strings.Count(got.Detail, "house.leases") != 1 {
		t.Fatalf("path repeated: %q", got.Detail)
	}
}

// The house is a segment of pf dns, while dnsmasq keeps DHCP at port=0.
// The two roles are two units. One "resolver: active" rung that reports
// the DHCP-only dnsmasq would tell an operator that the house has DNS,
// when the daemon that answers for it may be dead.
func TestLoadSplitsTheHouseResolverFromItsDHCP(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	netEnv := filepath.Join(dir, "net.env")
	if err := os.WriteFile(netEnv, []byte("PI_IP=10.77.0.1\nINT_IF=eth0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	houseEnv := filepath.Join(dir, "house.env")
	if err := os.WriteFile(houseEnv, []byte("HOUSE_IF=eth1\nHOUSE_IP=10.78.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	segs, err := Load(netEnv, houseEnv, "probe.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("got %d segments", len(segs))
	}
	if segs[1].probe != "probe.test" {
		t.Fatalf("--probe ignored: %q", segs[1].probe)
	}
	house := segs[1]
	if house.Name != "house" {
		t.Fatalf("second segment is %q", house.Name)
	}
	if house.Unit != "pi-fortress-dns-agent-go.service" {
		t.Fatalf("house resolver unit = %q", house.Unit)
	}
	if house.DHCPUnit != "pi-fortress-dns-house.service" {
		t.Fatalf("house dhcp unit = %q", house.DHCPUnit)
	}
	// Leases stay with dnsmasq. The decision that it keeps DHCP is what
	// makes the lease rung independent of the resolver that moved.
	if !house.DHCP || house.Leases == "" {
		t.Fatalf("house lost its DHCP rung: %+v", house)
	}
}
