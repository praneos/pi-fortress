package policycompile

import (
	"slices"
	"strings"
	"testing"
)

// operatorLists are the files that the operator edits and that pf compile
// reads: the lists of each segment, the local DoH lists and core.hosts.
func operatorLists() []string {
	files := []string{"doh.ips.local", "doh.domains.local", "core.hosts", "core.hosts.local"}
	for _, seg := range Segments {
		for _, l := range seg.Lists() {
			files = append(files, l.Name)
		}
	}
	return files
}

// A line of the operator that pf compile refuses, or that a shield removes,
// must never go silently. One line of the summary (Line), or the error,
// names the file, the line and the reason. The table has a row for each way that a line
// can fail to compile, on each list. The test also needs a row for each
// list that the operator edits, and it writes a bad line into each of them.
// Thus a new list, or a new way to skip a line, fails here until it warns.
// A feed line that does not parse, or that a shield removes, is feed noise
// and gets no line. A feed entry that a guard removes is in the summary.
func TestNoLineDropsSilently(t *testing.T) {
	type row struct {
		file, line string
		with       map[string]string
		want       []string
	}
	rows := []row{
		{"blacklist.domains", "bad!name", nil, []string{`blacklist.domains line 1: "bad!name"`, "is not a name"}},
		{"blacklist.domains", "münchen.de", nil, []string{`blacklist.domains line 1: "münchen.de"`, "xn--mnchen-3ya.de"}},
		{"blacklist.domains", "10.79.0.5", nil, []string{`blacklist.domains line 1: "10.79.0.5"`, "private or reserved"}},
		{"blacklist.domains", "203.0.113.0/24", nil, []string{`blacklist.domains line 1: "203.0.113.0/24"`, "private or reserved"}},
		{"blacklist.domains", "2.0.0.0/7", nil, []string{`blacklist.domains line 1: "2.0.0.0/7"`, "wider than /8"}},
		{"blacklist.domains", "www.example.com", map[string]string{"never_block.domains": "example.com"}, []string{`blacklist.domains: "www.example.com"`, "never_block.domains shields it"}},
		{"blacklist.domains", "example.com", map[string]string{"core.hosts": "api.example.com CLAUDE_OAT"}, []string{`blacklist.domains: "example.com"`, "core.hosts shields it"}},
		{"blacklist.domains", "192.0.2.1", map[string]string{"never_block.domains": "192.0.2.1"}, []string{`blacklist.domains: "192.0.2.1"`, "never_block.domains shields it"}},
		{"blacklist.domains", "192.0.2.1", map[string]string{"never_block.ips": "192.0.2.0/24"}, []string{`blacklist.domains: "192.0.2.1"`, "never_block.ips shields it"}},
		{"blacklist.domains", "192.0.2.1", map[string]string{"core.hosts": "192.0.2.1 CLAUDE_OAT"}, []string{`blacklist.domains: "192.0.2.1"`, "core.hosts shields it"}},
		{"blacklist.ips", "example.com", nil, []string{`blacklist.ips line 1: "example.com"`, "a name is not accepted"}},
		{"blacklist.ips", "10.0.0.0/8", nil, []string{`blacklist.ips line 1: "10.0.0.0/8"`, "private or reserved"}},
		{"blacklist.ips", "2.0.0.0/7", nil, []string{`blacklist.ips line 1: "2.0.0.0/7"`, "wider than /8"}},
		{"blacklist.ips", "192.0.2.0/24", map[string]string{"never_block.ips": "192.0.2.1"}, []string{`blacklist.ips: "192.0.2.0/24"`, "never_block.ips shields it"}},
		{"blacklist.ips", "192.0.2.0/24", map[string]string{"never_block.domains": "192.0.2.1"}, []string{`blacklist.ips: "192.0.2.0/24"`, "never_block.domains shields it"}},
		{"blacklist.ips", "192.0.2.0/24", map[string]string{"core.hosts": "192.0.2.1 CLAUDE_OAT"}, []string{`blacklist.ips: "192.0.2.0/24"`, "core.hosts shields it"}},
		{"never_block.domains", "192.0.2.0/24", nil, []string{`never_block.domains line 1: "192.0.2.0/24"`, "an address range is not a name"}},
		{"never_block.ips", "example.com", nil, []string{`never_block.ips line 1: "example.com"`, "a name is not accepted"}},
		{"direct_ip.allow", "93.184.0.0/16", nil, []string{`direct_ip.allow line 1: "93.184.0.0/16"`, "wider than /24"}},
		{"direct_ip.allow", "93.184.216.40/24", nil, []string{`direct_ip.allow line 1: "93.184.216.40/24"`, "host bits"}},
		{"ssh_allow.ips", "github.com", nil, []string{`ssh_allow.ips line 1: "github.com"`, "a name is not accepted"}},
		{"ssh_allow.ips", "10.0.0.5", nil, []string{`ssh_allow.ips line 1: "10.0.0.5"`, "private or reserved"}},
		{"allow.domains", "*.example.com", nil, []string{`allow.domains line 1: "*.example.com"`, "write example.com"}},
		{"allow.domains", "com", nil, []string{`allow.domains line 1: "com"`, "one label"}},
		{"allow.domains", "*.*.x.example", nil, []string{`allow.domains line 1: "*.*.x.example"`, "allows no name"}},
		{"allow.domains", "bücher.example", nil, []string{`allow.domains line 1: "bücher.example"`, "xn--bcher-kva.example"}},
		{"house.domains", "bad!name", nil, []string{`house.domains line 1: "bad!name"`, "is not a domain name"}},
		{"house.domains", "ads.example.com", map[string]string{"house_never_block.domains": "example.com"}, []string{`house.domains: "ads.example.com"`, "house_never_block.domains shields it"}},
		{"house.domains", "192.0.2.1", nil, []string{`house.domains line 1: "192.0.2.1"`, "names only"}},
		{"house_never_block.domains", "192.0.2.1", nil, []string{`house_never_block.domains line 1: "192.0.2.1"`, "names only"}},
		{"house_never_block.domains", "bad!name", nil, []string{`house_never_block.domains line 1: "bad!name"`, "is not a domain name"}},
		{"house_private_dns.domains", "dns.example.com", map[string]string{"house_private_dns.ips": "192.0.2.53"}, []string{`house_private_dns.domains: dns.example.com`, "per-profile endpoint"}},
		{"house_private_dns.ips", "example.com", nil, []string{`house_private_dns.ips line 1: "example.com"`, "a name is not accepted"}},
		{"house_private_dns.ips", "10.0.0.1", nil, []string{`house_private_dns.ips line 1: "10.0.0.1"`, "private or reserved"}},
		{"house_direct_ip.allow", "tv.example", nil, []string{`house_direct_ip.allow line 1: "tv.example"`, "a name is not accepted"}},
		{"doh.ips.local", "10.0.0.1", nil, []string{`doh.ips.local line 1: "10.0.0.1"`, "private or reserved"}},
		{"doh.domains.local", "bad!name", nil, []string{`doh.domains.local line 1: "bad!name"`, "is not a domain name"}},
		{"core.hosts", "localhost CLAUDE_OAT", nil, []string{`core.hosts line 1: "localhost"`, "one label"}},
		{"core.hosts.local", "a_b.example CLAUDE_OAT", nil, []string{`core.hosts.local line 1: "a_b.example"`, `"_"`}},
		{"generated/blacklist.domains", "github.io", map[string]string{SharedParentsFile: "github.io"}, []string{"github.io", "at a shared parent"}},
		{"generated/blacklist.ips", "2.0.0.0/8", nil, []string{"2.0.0.0/8", "wider than /12"}},
	}
	// A name that the DNS refuses: an empty label, a label over 63 bytes, a
	// name over 253 bytes. Each name list refuses it, and each one tells why.
	// The lists that ParseDomain reads also refuse a hyphen at the end of a
	// label. The broker takes such a Host, so core.hosts and allow.domains
	// keep it.
	long := strings.Repeat("a", 64) + ".example"
	huge := strings.Repeat("abcdefghi.", 26) + "example"
	for _, file := range []string{"blacklist.domains", "never_block.domains", "house.domains", "house_never_block.domains", "house_private_dns.domains", "doh.domains.local", "allow.domains", "core.hosts"} {
		bads := [][2]string{{"..x.example", "empty label"}, {long, "63 bytes"}, {huge, "253 bytes"}}
		if file != "allow.domains" && file != "core.hosts" {
			bads = append(bads, [2]string{"-bad-.example", "hyphen"}, [2]string{"a+b.example", "character"})
		}
		for _, bad := range bads {
			rows = append(rows, row{file, bad[0], nil, []string{file + " line 1: ", `"` + bad[0] + `"`, bad[1]}})
		}
	}
	lists := operatorLists()
	for _, file := range lists {
		if !slices.ContainsFunc(rows, func(r row) bool { return r.file == file }) {
			t.Errorf("%s: no row; add one for each way that a line of it can fail to compile", file)
		}
		rows = append(rows, row{file, "bad!token", nil, []string{file + " line 1: ", `"bad!token"`}})
	}
	for _, r := range rows {
		files := map[string]string{r.file: r.line + "\n"}
		for name, body := range r.with {
			files[name] = body + "\n"
		}
		sum, _, err := compileAllErr(t, files)
		text := sum.Line()
		if err != nil {
			text = err.Error()
		}
		if !slices.ContainsFunc(strings.Split(text, "\n"), func(l string) bool { return hasWarning([]string{l}, r.want...) }) {
			t.Errorf("%s %q (with %v): no line has %q:\n%s", r.file, r.line, r.with, r.want, text)
		}
	}
}
