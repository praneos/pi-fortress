package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A plain segment with DHCP=on gets the dhcp rung of the house, with its
// own unit named and the lease count after it. A segment without DHCP
// says nothing.
func TestSegmentDHCPRung(t *testing.T) {
	stub(t)
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	put := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(segs, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	put("desk.env", "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\n")
	put("iot.env", "IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=on\nDHCP_START=10.30.0.100\nDHCP_END=10.30.0.199\n")
	put("cam.env", "IF=eth1.40\nNET=10.40.0.0/24\nIP=10.40.0.1\nDHCP=off\n")

	unitActive = func(u string) bool { return u != "pi-fortress-dhcp@iot.service" }
	rs := SegmentDHCP(segs)
	if len(rs) != 1 || rs[0].Where != "iot" || rs[0].Rung != "dhcp" || rs[0].Status != Fail ||
		!strings.Contains(rs[0].Detail, "pi-fortress-dhcp@iot.service is not active; journalctl -u pi-fortress-dhcp@iot.service") {
		t.Fatalf("inactive instance: %+v", rs)
	}

	unitActive = func(string) bool { return true }
	readFile = func(p string) ([]byte, error) {
		if p == "/var/lib/pi-fortress/dhcp-iot.leases" {
			return []byte("1900000000 aa:bb:cc:dd:ee:ff 10.30.0.120 plug *\n"), nil
		}
		return nil, os.ErrNotExist
	}
	rs = SegmentDHCP(segs)
	if len(rs) != 2 || rs[0].Status != OK || !strings.Contains(rs[0].Detail, "pi-fortress-dhcp@iot.service active") {
		t.Fatalf("active instance: %+v", rs)
	}
	if rs[1].Rung != "leases" || rs[1].Where != "iot" || rs[1].Status != OK || !strings.HasPrefix(rs[1].Detail, "1,") {
		t.Fatalf("lease rung: %+v", rs[1])
	}

	if rs = SegmentDHCP(filepath.Join(dir, "nope")); len(rs) != 0 {
		t.Fatalf("no segments.d: %+v", rs)
	}
}
