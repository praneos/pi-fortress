package www

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RedeemedDir is 2770 root:pf-fortress (vm/pi/apply.sh). So www
// can unlink ledger.jsonl and put its own symlink at that name. The TUI
// then issues a claim as root and appends through the same name. If the
// append follows the link, a compromised www has made a root process into
// a writer of any path on the gateway.
func TestAppendRefusesASymlinkedLedger(t *testing.T) {
	claims := newClaimsDir(t)
	target := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(target, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, LedgerPath(claims)); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(claims, Event{Ev: "issued", Code: "ABCDEF", Slot: "canary"}); err == nil {
		t.Fatal("append through a symlinked ledger was allowed")
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original\n" {
		t.Fatalf("root wrote outside the ledger: %q", raw)
	}
	if evs := ReadLedger(claims); evs != nil {
		t.Fatalf("read followed the symlink: %+v", evs)
	}
}

// A hard link is the same attack without the symlink. www can point the
// ledger name at any file that it can write itself, and the append of root
// goes there. A ledger that the deployment created has one link only.
func TestAppendRefusesAHardLinkedLedger(t *testing.T) {
	claims := newClaimsDir(t)
	target := filepath.Join(claims, "decoy")
	if err := os.WriteFile(target, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, LedgerPath(claims)); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(claims, Event{Ev: "issued", Code: "ABCDEF", Slot: "canary"}); err == nil {
		t.Fatal("append through a hard-linked ledger was allowed")
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original\n" {
		t.Fatalf("root wrote through the second link: %q", raw)
	}
}

// Nothing rotates this file. It is in /var/lib, not /var/log, so the hourly
// logrotate run (vm/pi/logrotate.conf) never sees it. Sweep keeps it,
// because its name does not end .redeemed. So appends must bound
// themselves. If not, a public fetch loop fills the partition that the
// broker and the audit log also write to.
func TestLedgerStaysBounded(t *testing.T) {
	claims := newClaimsDir(t)
	pad := strings.Repeat("a", 4096)
	for range 4 * ledgerCap / 4096 {
		if err := AppendEvent(claims, Event{Ev: "setup", IP: "10.77.0.2", Path: "/" + pad}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(RedeemedDir(claims))
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total > 2*ledgerCap {
		t.Fatalf("ledger grew to %d bytes, above the %d cap", total, 2*ledgerCap)
	}
	if evs := ReadLedger(claims); len(evs) == 0 {
		t.Fatal("rotation left nothing readable")
	}
}

// /setup.sh and /ca.pem are the unauthenticated half of the surface. They
// have none of the throttles of the claim endpoint, so one client in a loop
// used to append a line per request. The record to keep is that an address
// fetched the file, not the number of its retries.
func TestRepeatedSetupFetchesCollapse(t *testing.T) {
	s, ts := testServer(t)
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(RedeemedDir(claims), 0770); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		res, err := ts.Client().Get(ts.URL + "/setup.sh")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatal(res.StatusCode)
		}
	}
	n := 0
	for _, ev := range ReadLedger(claims) {
		if ev.Ev == "setup" {
			n++
		}
	}
	if n > 5 {
		t.Fatalf("%d setup events for 200 fetches from one address", n)
	}
	if n == 0 {
		t.Fatal("the fetch went unrecorded entirely")
	}
}

// apply makes and repairs the ledger as root on each pass, in a directory
// that www can write. A link at the name must not give the chown and chmod
// of root to the file that the link points at. A ledger made or found with
// the group write bit off must come out 0660. If not, one appender loses it.
func TestInitLedgerWorksThroughTheDescriptor(t *testing.T) {
	claims := newClaimsDir(t)
	target := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(target, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, LedgerPath(claims)); err != nil {
		t.Fatal(err)
	}
	if err := InitLedger(claims); err == nil {
		t.Fatal("InitLedger accepted a symlinked ledger")
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("the link's target changed: %v %v", fi.Mode(), err)
	}

	for _, existing := range []bool{false, true} {
		claims := newClaimsDir(t)
		if existing {
			if err := os.WriteFile(LedgerPath(claims), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := InitLedger(claims); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(LedgerPath(claims))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0660 {
			t.Fatalf("existing=%v: ledger is %v (%v), want a regular file 0660", existing, fi.Mode(), err)
		}
	}
}
