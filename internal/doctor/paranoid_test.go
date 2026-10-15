package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSegmentParanoidRung(t *testing.T) {
	dir := t.TempDir()
	segs := filepath.Join(dir, "segments.d")
	if err := os.Mkdir(segs, 0755); err != nil {
		t.Fatal(err)
	}
	put := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(segs, "desk.env"), "IF=eth0.79\nNET=10.79.0.0/30\nIP=10.79.0.1\nPARANOID=on\n")
	put(filepath.Join(segs, "guest.env"), "IF=eth2\nNET=10.80.0.0/24\nIP=10.80.0.1\n")
	put(filepath.Join(segs, "lab.env"), "IF=eth3\nNET=10.81.0.0/24\nIP=10.81.0.1\nPARANOID=off\n")

	// Missing: FAIL, naming the file.
	rs := SegmentParanoid(segs)
	if len(rs) != 1 || rs[0].Where != "desk" || rs[0].Status != Fail || !strings.Contains(rs[0].Detail, "allow.desk.domains") {
		t.Fatalf("missing allowlist: %+v", rs)
	}
	// Comments only: still FAIL.
	allow := filepath.Join(dir, "allow.desk.domains")
	put(allow, "# later\n")
	if rs = SegmentParanoid(segs); len(rs) != 1 || rs[0].Status != Fail || !strings.Contains(rs[0].Detail, "no usable name") {
		t.Fatalf("empty allowlist: %+v", rs)
	}
	// Filled: ok, with the count.
	put(allow, "github.com\npypi.org\n")
	if rs = SegmentParanoid(segs); len(rs) != 1 || rs[0].Status != OK || !strings.Contains(rs[0].Detail, "2 name(s)") {
		t.Fatalf("filled allowlist: %+v", rs)
	}
	// No segments.d at all: no rung.
	if rs = SegmentParanoid(filepath.Join(dir, "nope")); len(rs) != 0 {
		t.Fatalf("no segments.d: %+v", rs)
	}
}
