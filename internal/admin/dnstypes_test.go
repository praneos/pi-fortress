package admin

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pi-fortress/internal/dnsd"
)

// The check of the seat and the parser of pf dns are two copies, because
// dnsd keeps its parser unexported. This test gives both the same lines.
// pf dns gets them through New, as -check loads a segment, and the test
// reads its "line ignored" reports. A type that the seat refuses because it
// changes nothing must get a "no effect" report from pf dns. The test holds
// the one important property: pf dns never skips a line that the seat
// accepts. Where they
// differ, the seat is stricter, and this test names each such line.
func TestDNSTypesLineMatchesPfDNS(t *testing.T) {
	cases := []struct {
		line         string
		seat, pfdns  bool
		stricterSeat string
	}{
		{line: "example.com TXT", seat: true, pfdns: true},
		{line: "*.example.com MX SRV", seat: true, pfdns: true},
		{line: "Example.COM. txt", seat: true, pfdns: true},
		{line: "_sip._tcp.example.com SRV", seat: true, pfdns: true},
		{line: "example.com TYPE10", seat: true, pfdns: true},
		{line: "example.com TYPE257 TXT ns", seat: true, pfdns: true},
		{line: "example.com A CNAME SOA PTR", seat: true, pfdns: true},
		{line: "localhost PTR", seat: true, pfdns: true},
		{line: "example.com"},
		{line: "example.com TXET"},
		{line: "example.com TXT TXET"},
		{line: "*.* TXT"},
		{line: "*. TXT"},
		{line: "**.example.com TXT"},
		{line: "example.com TYPE"},
		{line: "example.com TYPE70000"},
		{line: "example.com TYPE-1"},
		{line: "exa!mple.com TXT", pfdns: true, stricterSeat: "a name of DNS labels"},
		{line: "a..b TXT", pfdns: true, stricterSeat: "no empty label"},
		{line: "example.com AAAA", pfdns: true, stricterSeat: "filtered ahead of the list"},
		{line: "example.com TXT HTTPS", pfdns: true, stricterSeat: "filtered ahead of the list"},
		{line: "example.com TYPE28", pfdns: true, stricterSeat: "AAAA by number"},
		{line: "example.com SVCB", pfdns: true, stricterSeat: "filtered ahead of the list"},
	}

	dir := t.TempDir()
	var file strings.Builder
	for _, c := range cases {
		file.WriteString(c.line + "\n")
	}
	path := filepath.Join(dir, "dns_types.allow")
	sink := filepath.Join(dir, "sink.conf")
	for p, b := range map[string]string{path: file.String(), sink: ""} {
		if err := os.WriteFile(p, []byte(b), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var logged bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()
	if _, err := dnsd.New(dnsd.Config{
		NFTTable: "inet fortress",
		Segments: []dnsd.Segment{{
			Name: "agent", Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: "127.0.0.1:1",
			SinkholeFiles: []string{sink}, NFTSet: "resolved_v4", AddressOnly: true, TypesAllowPath: path,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	// report says whether pf dns logged a line for file line n with word in it.
	report := func(n int, word string) bool {
		for l := range strings.Lines(logged.String()) {
			if strings.Contains(l, fmt.Sprintf("%s:%d: ", path, n)) && strings.Contains(l, word) {
				return true
			}
		}
		return false
	}
	for i, c := range cases {
		pfdns := !report(i+1, "line ignored")
		_, err := CheckDNSTypesLine(c.line)
		seat := err == nil
		if err != nil && strings.Contains(err.Error(), "changes nothing") && !report(i+1, "this entry has no effect") {
			t.Errorf("%q: pf dns gave no warning for a type that changes nothing", c.line)
		}
		if pfdns != c.pfdns {
			t.Errorf("%q: pf dns took it %v, the test says %v (the parser moved; update both)", c.line, pfdns, c.pfdns)
		}
		if seat != c.seat {
			t.Errorf("%q: the seat took it %v, want %v (%v)", c.line, seat, c.seat, err)
		}
		if seat && !pfdns {
			t.Errorf("%q: the seat writes a line pf dns skips", c.line)
		}
		if seat != pfdns && c.stricterSeat == "" {
			t.Errorf("%q: the seat and pf dns differ with no reason given", c.line)
		}
	}
	if !strings.Contains(logged.String(), "line ignored") {
		t.Fatalf("pf dns reported nothing; the capture is broken:\n%s", logged.String())
	}
}

// The line that the seat writes is canonical. This also makes it possible
// to delete a hand-written line from the screen that shows it.
func TestDNSTypesLineCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.  txt   mx": "example.com TXT MX",
		"*.Corp.Example type10":  "*.corp.example TYPE10",
	} {
		if got, err := CheckDNSTypesLine(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	_, err := CheckDNSTypesLine("example.com TXET")
	if err == nil || !strings.Contains(err.Error(), `"TXET" is not a record type`) {
		t.Errorf("a misspelt type does not say which: %v", err)
	}
}

// dns_types.allow is an agent list like allow.domains. The same verb adds
// lines, and a refusal gives the reason. A hand-written line can be one
// that the check canonicalises differently, or one that the check refuses.
// The code deletes such a line by the text that the screen shows.
func TestDNSTypesListAddRemove(t *testing.T) {
	c := testConfig(t)
	p := filepath.Join(c.PolicyDir, DNSTypesList)
	seed := "# overrides\nExample.org  txt\nbad.example TXET\n"
	if err := os.WriteFile(p, []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(RoleAdmin, "agent.add", Args{List: DNSTypesList, Value: "*.example.com  mx srv"}); err != nil {
		t.Fatal(err)
	}
	_, err := c.Call(RoleAdmin, "agent.add", Args{List: DNSTypesList, Value: "example.com AAAA"})
	if !errors.Is(err, errToken) || !strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("an inert type was not refused with its reason: %v", err)
	}
	items, err := c.List(DNSTypesList)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Example.org  txt", "bad.example TXET", "*.example.com MX SRV"}; strings.Join(items, "|") != strings.Join(want, "|") {
		t.Fatalf("items %q, want %q", items, want)
	}
	for _, it := range []string{"Example.org  txt", "bad.example TXET"} {
		if _, err := c.Call(RoleAdmin, "agent.del", Args{List: DNSTypesList, Value: it}); err != nil {
			t.Fatalf("del %q: %v", it, err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "# overrides\n*.example.com MX SRV\n" {
		t.Fatalf("file after the edits:\n%s", b)
	}
}
