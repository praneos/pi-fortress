package policycompile

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedListsParse is the guard against a silent failure mode.
// LoadTokens discards, without a warning, a token that ParseDomain refuses.
// Thus a typo in a shipped list is a domain that the operator thinks is
// blocked, but it is not. A list is only as good as its worst line.
func TestShippedListsParse(t *testing.T) {
	dir := filepath.Join("..", "..", "vm", "policy")
	entries, err := filepath.Glob(filepath.Join(dir, "*.domains"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no shipped .domains files under %s: %v", dir, err)
	}
	for _, path := range entries {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			seen := map[string]int{}
			sc := bufio.NewScanner(f)
			for n := 1; sc.Scan(); n++ {
				line := sc.Text()
				if i := strings.Index(line, "#"); i >= 0 {
					line = line[:i]
				}
				bits := strings.Fields(strings.TrimSpace(line))
				if len(bits) == 0 {
					continue
				}
				name, ok := ParseDomain(bits[0])
				if !ok {
					t.Errorf("line %d: %q is dropped silently by ParseDomain", n, bits[0])
					continue
				}
				if first, dup := seen[name]; dup {
					t.Errorf("line %d: %q already listed on line %d", n, name, first)
					continue
				}
				seen[name] = n
			}
			if err := sc.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBlacklistIsNotUndoneByNeverBlock finds a pair of edits that cancel
// each other. never_block.domains filters blacklist.domains in collect().
// Thus a name on the two lists looks blocked, but it is not.
func TestBlacklistIsNotUndoneByNeverBlock(t *testing.T) {
	dir := filepath.Join("..", "..", "vm", "policy")
	never, err := LoadTokens(filepath.Join(dir, "never_block.domains"), "domains")
	if err != nil {
		t.Fatal(err)
	}
	black, err := LoadTokens(filepath.Join(dir, "blacklist.domains"), "domains")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range black {
		if IsNeverDomain(d, set(never)) {
			t.Errorf("%q is on blacklist.domains and never_block.domains shields it", d)
		}
	}
}

// TestShippedNTPPassCompiles: each line of the shipped ntp_pass.ips
// compiles, with no warning and no duplicate. The lab group ntp uses
// 8.8.8.8 as a server that is not on the list, so it must stay off.
func TestShippedNTPPassCompiles(t *testing.T) {
	var warn []string
	ips, err := loadOperator(filepath.Join("..", "..", "vm", "policy", NTPPassFile), "allow_ips", &warn)
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) > 0 || len(ips) == 0 {
		t.Fatalf("%d addresses, warnings %q", len(ips), warn)
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("%s is listed twice", ip)
		}
		seen[ip] = true
	}
	for _, ip := range []string{"8.8.8.8", "8.8.8.8/32", "192.0.2.1"} {
		if seen[ip] {
			t.Errorf("%s must not be on the shipped list", ip)
		}
	}
}
