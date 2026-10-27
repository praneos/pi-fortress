package eyeball

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"off": Off, "audit": Audit, "": Audit, "refuse": Refuse} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseMode("block"); err == nil {
		t.Error("ParseMode accepted block")
	}
}

func TestAllowExempt(t *testing.T) {
	a, warn, err := ParseAllow(strings.NewReader("# exemptions\nAS64497\nhome.example.com # a note\nbad entry here\n64498\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 2 {
		t.Errorf("warnings %v, want two (a line with spaces, an ASN without AS)", warn)
	}
	for _, c := range []struct {
		name string
		asn  uint32
		want bool
	}{
		{"other.example", 64497, true},
		{"home.example.com", 64496, true},
		{"a.b.home.example.com.", 64496, true},
		{"HOME.example.com", 64496, true},
		{"nothome.example.com", 64496, false},
		{"example.com", 64496, false},
		{"other.example", 64498, false},
	} {
		if got := a.Exempt(c.name, c.asn); got != c.want {
			t.Errorf("Exempt(%s, %d) = %v", c.name, c.asn, got)
		}
	}
	var none *Allow
	if none.Exempt("home.example.com", 64497) {
		t.Error("a nil list exempted")
	}
}

func TestCheckerModes(t *testing.T) {
	tab := testTable(t)
	a, _, _ := ParseAllow(strings.NewReader("AS64497\nok.example\n"))
	addr := netip.MustParseAddr("192.0.2.10")
	if _, hit := Static(Off, tab, nil).Match("x.example", addr); hit {
		t.Error("off matched")
	}
	c := Static(Audit, tab, a)
	if asn, hit := c.Match("x.example", addr); !hit || asn != 64496 {
		t.Errorf("audit: %d %v", asn, hit)
	}
	if _, hit := c.Match("ok.example", addr); hit {
		t.Error("an exempt name matched")
	}
	if _, hit := c.Match("x.example", netip.MustParseAddr("203.0.113.5")); hit {
		t.Error("an exempt ASN matched")
	}
	if _, hit := c.Match("x.example", netip.MustParseAddr("198.51.100.77")); hit {
		t.Error("an address outside the table matched")
	}
	var nilChecker *Checker
	if _, hit := nilChecker.Match("x.example", addr); hit || nilChecker.Ready() {
		t.Error("a nil checker matched")
	}
}

type logs struct{ lines []string }

func (l *logs) logf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func writeTable(t *testing.T, path string, when time.Time) {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, when, []Range{mustRange(t, "192.0.2.0", "192.0.2.255", "64496")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestCheckerFailsOpen: no table, a bad table, and a stale table each
// give no match and one log line. A bad file after a good one keeps the
// good table.
func TestCheckerFailsOpen(t *testing.T) {
	dir := t.TempDir()
	now := built.Add(24 * time.Hour)
	l := &logs{}
	c := &Checker{
		Mode:      Refuse,
		TablePath: filepath.Join(dir, TableFile),
		AllowPath: filepath.Join(dir, "eyeball.allow"),
		Now:       func() time.Time { return now },
		Logf:      l.logf,
	}
	addr := netip.MustParseAddr("192.0.2.1")
	c.Reload()
	c.Reload()
	if _, hit := c.Match("x.example", addr); hit || c.Ready() {
		t.Fatal("matched with no table")
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "fail open") {
		t.Fatalf("log %q, want one fail-open line", l.lines)
	}

	writeTable(t, c.TablePath, built)
	c.Reload()
	if _, hit := c.Match("x.example", addr); !hit {
		t.Fatalf("no match with a table; log %q", l.lines)
	}

	// A damaged file keeps the last good table.
	if err := os.WriteFile(c.TablePath, []byte(Magic+"\n# built 2026-10-01T00:00:00Z\nnot a range\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c.Reload()
	if _, hit := c.Match("x.example", addr); !hit {
		t.Error("a damaged file stopped the last good table")
	}
	if last := l.lines[len(l.lines)-1]; !strings.Contains(last, "did not load") {
		t.Errorf("log %q, want the load error", last)
	}

	// Age stops the table, with one line.
	n := len(l.lines)
	now = built.Add(DefaultMaxAge + time.Hour)
	c.Reload()
	c.Reload()
	if _, hit := c.Match("x.example", addr); hit {
		t.Error("a stale table matched")
	}
	if len(l.lines) != n+1 || !strings.Contains(l.lines[n], "older than") {
		t.Errorf("log %q, want one stale line", l.lines[n:])
	}

	// A new table starts the check again.
	writeTable(t, c.TablePath, now)
	c.Reload()
	if _, hit := c.Match("x.example", addr); !hit {
		t.Error("a new table did not start the check again")
	}

	// The allow list loads without a restart.
	if err := os.WriteFile(c.AllowPath, []byte("x.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c.Reload()
	if _, hit := c.Match("x.example", addr); hit {
		t.Error("the new allow list did not exempt the name")
	}
}
