package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Status screen shows the last monitor sample. If the code could not
// read the /proc files of a sample, the sample parses as zeros. The screen
// showed those zeros with the same confidence as a measurement. An operator
// who reads "temp 0C conntrack 0" gets two facts, not two failures.
func TestStatusDoesNotPrintAFailedReadAsZero(t *testing.T) {
	c, _ := testConfig(t)
	row := `{"ts":"2026-01-02T00:00:00Z","cpu_pct":0,"load1":0,"mem_used_mb":0,"mem_used_pct":0,` +
		`"temp_c":0,"conntrack":0,"missing":["cpu","load","mem","temp","conntrack","disk"]}`
	if err := os.WriteFile(filepath.Join(c.MonitorDir, "system-2026-01-02.jsonl"), []byte(row+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(130, 40).Type(keys(netSystem, secHealth))).Last()
	for _, fiction := range []string{"cpu 0.0%", "load 0.00", "mem used 0 MB", "temp 0C", "conntrack 0"} {
		if strings.Contains(last, fiction) {
			t.Fatalf("an unread metric rendered as a measurement (%q):\n%s", fiction, last)
		}
	}
	if !strings.Contains(last, "n/a") {
		t.Fatalf("nothing on the screen says the sample was incomplete:\n%s", last)
	}
}

// A metric that the box did read still shows as a figure, also a true
// zero. The signal exists so that absent and zero are different. It does
// not exist to stop the display of zero.
func TestStatusStillPrintsAMeasuredZero(t *testing.T) {
	c, _ := testConfig(t)
	row := `{"ts":"2026-01-02T00:00:00Z","cpu_pct":0,"load1":0,"mem_used_mb":0,"mem_used_pct":0,"temp_c":0,"conntrack":0}`
	if err := os.WriteFile(filepath.Join(c.MonitorDir, "system-2026-01-02.jsonl"), []byte(row+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last := run(t, c, NewFake(130, 40).Type(keys(netSystem, secHealth))).Last()
	if !strings.Contains(last, "temp 0C") || !strings.Contains(last, "conntrack 0") {
		t.Fatalf("a measured zero was hidden:\n%s", last)
	}
}

// ReadLedgerCovering already reports that what it read is a tail of the
// ledger. A generation rotated away, or the live one is longer than the
// read window. The screen showed the counts of the tail as totals, and its
// silence as "never". This tells the operator that a credential was not
// used. What occurred is that nobody looked at the part of the record that
// would say.
