package admin

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// awkwardLines are lines that people write by hand into a list file. Some
// are good in a different form, some the seat refuses, and some are not
// rows at all.
var awkwardLines = []string{
	"# a note",
	"",
	"   ",
	".lead.example.com",
	"..two.example.com",
	"x..mid.example.com",
	"UPPER.Example.COM.",
	"*.star.example.com",
	"münchen.example",
	strings.Repeat("a", 64) + ".example.com",
	"abc.dns.Profile.example # an endpoint",
	"192.0.2.1 # a host",
	"192.0.2.0/24",
	"not an address",
	"Example.org  txt",
	"bad.example TXET",
	"pi-fortress-block.test",
	"PI-FORTRESS-BLOCK.test",
}

// A row that the TUI shows is a row that the TUI can remove. Each list
// that the admin layer serves gets the same awkward lines. Each row that
// List gives must go away with ListRemove of that row, and must take its
// lines with it. A line that the seat refuses shows as it is written, so
// the row itself names the line.
func TestEveryListRowRoundTripsThroughRemove(t *testing.T) {
	lists := slices.Concat(AgentLists, HouseLists)
	for _, list := range lists {
		t.Run(list, func(t *testing.T) {
			c := &Config{PolicyDir: t.TempDir()}
			path := filepath.Join(c.PolicyDir, list)
			write(t, path, strings.Join(awkwardLines, "\n")+"\n")
			rows, err := c.List(list)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				t.Fatal("no rows")
			}
			if len(slices.Compact(slices.Sorted(slices.Values(rows)))) != len(rows) {
				t.Errorf("a row shows two times: %q", rows)
			}
			for _, row := range rows {
				if _, err := ValidateToken(list, row); err != nil && !slices.ContainsFunc(awkwardLines, func(l string) bool { return strings.Contains(l, row) }) {
					t.Errorf("refused row %q does not name its line", row)
				}
				if err := c.ListRemove(list, row); err != nil {
					t.Errorf("ListRemove(%q) = %v", row, err)
					continue
				}
				after, err := c.List(list)
				if err != nil {
					t.Fatal(err)
				}
				if slices.Contains(after, row) {
					t.Errorf("row %q is still there after its remove", row)
				}
			}
			if left, _ := c.List(list); len(left) != 0 {
				t.Errorf("rows left: %q", left)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "# a note\n\n   \n" {
				t.Errorf("file after the removes: %q", raw)
			}
		})
	}
}
