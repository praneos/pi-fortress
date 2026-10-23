package www

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// A rotation that removes the group write bit removes the other appender
// from the ledger. Root and www are different principals, and both append.
func TestRotatedLedgerStaysGroupWritable(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := newClaimsDir(t)
	p := LedgerPath(dir)
	if err := os.WriteFile(p, []byte(strings.Repeat("x", ledgerCap+1)), 0660); err != nil {
		t.Fatal(err)
	}
	if err := AppendEvent(dir, Event{Ev: "setup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("no rotated generation: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("rotated ledger is %o, want 660: the other appender cannot write it", fi.Mode().Perm())
	}
}
