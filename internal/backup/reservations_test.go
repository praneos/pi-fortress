package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// DHCP reservations are operator state with no other copy: house.hosts of
// the house, and dhcp.<segment>.hosts of each segment beside segments.d
// (render.SegmentHostsPath). Both are carried, and both come back. The file
// of a segment comes back only for a segment that exists, and only that
// shape is let back in.
func TestArchiveCarriesAndRestoresDHCPReservations(t *testing.T) {
	c, etc, _ := box(t)
	files := map[string]string{
		"house.hosts":      "aa:bb:cc:dd:ee:ff,10.78.0.20,laptop\n",
		"dhcp.lab.hosts":   "02:00:00:00:00:0a,10.30.0.50,cam\n",
		"dhcp.ghost.hosts": "02:00:00:00:00:0b,10.31.0.50\n",
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(etc, n), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	buf, man := archive(t, c)
	got := map[string]bool{}
	for _, f := range man.Files {
		got[f.Name] = true
	}
	for _, want := range []string{"etc/house.hosts", "etc/dhcp.lab.hosts"} {
		if !got[want] {
			t.Errorf("the archive is missing %q", want)
		}
	}
	if got["etc/dhcp.ghost.hosts"] {
		t.Error("reservations for a segment that does not exist were carried")
	}

	arc, err := Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	dstEtc := filepath.Join(dst, "etc")
	plan, err := arc.Plan(dstEtc, filepath.Join(dst, "policy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"house.hosts", "dhcp.lab.hosts"} {
		raw, err := os.ReadFile(filepath.Join(dstEtc, n))
		if err != nil {
			t.Fatalf("%s was not restored: %v", n, err)
		}
		if string(raw) != files[n] {
			t.Errorf("%s restored as %q, want %q", n, raw, files[n])
		}
	}

	for _, name := range []string{"etc/house.hosts", "etc/dhcp.lab.hosts", "etc/dhcp.lab-2.hosts"} {
		if !safeName(name) {
			t.Errorf("safeName rejected %q", name)
		}
	}
	for _, name := range []string{"etc/dhcp.hosts", "etc/dhcp.Lab.hosts", "etc/dhcp.../x.hosts", "etc/dhcp.lab.hosts.bak", "etc/segments.d/dhcp.lab.hosts", "etc/core.hosts", "etc/dns-agent-go.hosts"} {
		if safeName(name) {
			t.Errorf("safeName accepted %q", name)
		}
	}
}
