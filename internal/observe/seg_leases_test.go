package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A plain segment with DHCP=on has a lease file next to the file of the
// house. It supplies the same two things: the device name on the clients
// of that segment, and the "address leased to another MAC" claim of the ARP watch.
func TestSegmentLeasesNameClientsAndBackTheARPClaim(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	if err := os.Mkdir(o.SegmentsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.SegmentsDir, "iot.env"), []byte("IF=eth1.30\nNET=10.30.0.0/24\nIP=10.30.0.1\nDHCP=on\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dhcp-iot.leases"), []byte("0 08:00:27:11:11:11 10.30.0.50 plug *\n"), 0644); err != nil {
		t.Fatal(err)
	}

	st := o.Load()
	arpFile(t, o.ARPPath, "10.30.0.50", "08:00:27:99:99:99")
	o.watchARP(st)
	got := alertsOf(st)
	if len(got) != 1 || got[0].Threat != arpLease || got[0].Segment != "iot" {
		t.Fatalf("alerts = %+v, want one arp_lease on iot", got)
	}

	arpFile(t, o.ARPPath, "10.30.0.50", "08:00:27:11:11:11")
	st = o.empty()
	o.client(st, "iot", "10.30.0.50", o.nowISO())
	o.enrich(st)
	if c := st.Clients["iot/10.30.0.50"]; c.Name != "plug" || c.MAC != "08:00:27:11:11:11" {
		t.Fatalf("segment client: %+v", c)
	}
}
