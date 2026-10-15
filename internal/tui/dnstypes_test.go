package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/admin"
)

// dns_types.allow is in the Filtering of the agent network, beside
// allow.domains. The seat refuses a misspelt type and shows the wrong word.
// It does not write the type for pf dns to skip with only a journal line.
// A hand-written line that pf dns would skip shows as not applied. One
// confirm deletes it.
func TestDNSTypesScreen(t *testing.T) {
	c, _ := testConfig(t)
	path := filepath.Join(c.PolicyDir, admin.DNSTypesList)
	if err := os.WriteFile(path, []byte("# overrides\nbad.example TXET\n"), 0644); err != nil {
		t.Fatal(err)
	}
	open := func() *Fake {
		f := NewFake(140, 30).Type(keys(netAgent, secFiltering))
		for range slices.Index(admin.AgentLists, admin.DNSTypesList) {
			f = f.Press(KeyTab)
		}
		return f
	}

	last := run(t, c, open()).Last()
	for _, want := range []string{"DNS record types: dns_types.allow", "name TYPE...", "bad.example TXET", "not applied", `"TXET" is not a record type`} {
		if !strings.Contains(last, want) {
			t.Fatalf("no %q:\n%s", want, last)
		}
	}

	f := run(t, c, open().Type("a").Type("_xmpp._tcp.Example.com srv txet").Press(KeyEnter))
	if !strings.Contains(f.Last(), `"txet" is not a record type`) {
		t.Fatalf("the refusal does not name the bad type:\n%s", f.Last())
	}
	f = run(t, c, open().Type("a").Type("_xmpp._tcp.Example.com srv txt").Press(KeyEnter))
	if !strings.Contains(f.Last(), "added _xmpp._tcp.example.com SRV TXT; A applies") {
		t.Fatalf("the add did not say what it wrote:\n%s", f.Last())
	}

	run(t, c, open().Type("d").Type("y"))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# overrides\n_xmpp._tcp.example.com SRV TXT\n" {
		t.Fatalf("file after add and delete:\n%s", got)
	}
}
