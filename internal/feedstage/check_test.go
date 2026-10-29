package feedstage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckLineAcceptsCanonical(t *testing.T) {
	for _, c := range []struct {
		k    Kind
		line string
	}{
		{KindIPs, "192.0.2.1"},
		{KindIPs, "1.2.3.0/24"},
		{KindIPs, "8.0.0.0/8"},
		{KindBlockDomains, "pi-fortress-block.test"},
		{KindBlockDomains, "ads.example.com"},
		{KindBlockDomains, "xn--80ak6aa92e.com"},
		{KindBlockDomains, "192.0.2.1"},
		{KindBlockDomains, "001.002.003.004"},
		{KindNames, "tracker.example.net"},
	} {
		if why := CheckLine(c.k, c.line); why != "" {
			t.Errorf("CheckLine(%v, %q) = %q, want accepted", c.k, c.line, why)
		}
	}
}

func TestCheckLineRefusesOtherForms(t *testing.T) {
	for _, c := range []struct {
		k    Kind
		line string
		why  string
	}{
		{KindIPs, "", "empty"},
		{KindIPs, "1.2.3.4 ", "byte 0x20"},
		{KindIPs, "1.2.3.4\r", "byte 0x0d"},
		{KindIPs, "1.2.3.4\x00", "byte 0x00"},
		{KindIPs, "1.2.3.4/24", "canonical"},
		{KindIPs, "1.2.3.4/32", "canonical"},
		{KindIPs, "01.2.3.4", "not an IPv4"},
		{KindIPs, "1.2.3.0/032", ""},
		{KindIPs, "10.0.0.1", "not an IPv4"},
		{KindIPs, "1.0.0.0/7", "not an IPv4"},
		{KindIPs, "::ffff:1.2.3.4", "byte 0x3a"},
		{KindIPs, "2001:db8::1", "byte 0x3a"},
		{KindIPs, "1.2.3.4 }", "byte 0x20"},
		{KindIPs, "1.2.3.4;flush", "byte 0x3b"},
		{KindIPs, "255.255.255.255/320", "longer than"},
		{KindBlockDomains, "Ads.example.com", "byte 0x41"},
		{KindBlockDomains, "*.example.com", "byte 0x2a"},
		{KindBlockDomains, ".example.com", "canonical"},
		{KindBlockDomains, "example.com.", "canonical"},
		{KindBlockDomains, "x.com/1.2.3.4", "byte 0x2f"},
		{KindBlockDomains, "1.2.3.0/24", "byte 0x2f"},
		{KindBlockDomains, "server=/x/1.1.1.1", "byte 0x3d"},
		{KindBlockDomains, "exаmple.com", "byte 0xd0"},
		{KindBlockDomains, "a\x1b]0;t\x07.com", "byte 0x1b"},
		{KindBlockDomains, "under_score.com", "byte 0x5f"},
		{KindBlockDomains, "printer.local", ".local"},
		{KindBlockDomains, "x.localhost", ".local"},
		{KindBlockDomains, "single", "not a domain"},
		{KindBlockDomains, "-a.example.com", "not a domain"},
		{KindBlockDomains, strings.Repeat("a", 250) + ".com", "longer than"},
		{KindNames, "192.0.2.1", "not a domain"},
		{KindNames, "x.com\nadd rule", "byte 0x0a"},
	} {
		why := CheckLine(c.k, c.line)
		if why == "" || !strings.Contains(why, c.why) {
			t.Errorf("CheckLine(%v, %q) = %q, want a refusal with %q", c.k, c.line, why, c.why)
		}
	}
}

func TestCheckList(t *testing.T) {
	got, err := CheckList(KindIPs, []byte("192.0.2.1\n1.2.3.0/24\n"), 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("good list: %v %v", got, err)
	}
	if got, err := CheckList(KindIPs, nil, 0); err != nil || got != nil {
		t.Fatalf("empty list: %v %v", got, err)
	}
	for name, c := range map[string]struct {
		text string
		max  int
		want string
	}{
		"no newline at the end": {"192.0.2.1", 5, "no newline"},
		"empty line":            {"192.0.2.1\n\n1.2.3.4\n", 5, "line 2: empty"},
		"comment":               {"# feed\n192.0.2.1\n", 5, "line 1"},
		"repeat":                {"192.0.2.1\n1.2.3.4\n192.0.2.1\n", 5, "line 3: repeats"},
		"over the cap":          {"192.0.2.1\n1.2.3.4\n", 1, "more than the cap of 1"},
		"bad line names it":     {"192.0.2.1\n1.2.3.4 }\n", 5, "line 2: byte 0x20"},
		"CRLF":                  {"192.0.2.1\r\n", 5, "line 1: byte 0x0d"},
	} {
		if _, err := CheckList(KindIPs, []byte(c.text), c.max); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestCheckMap(t *testing.T) {
	items := map[string]struct{}{"ads.example.com": {}, "192.0.2.1": {}}
	ids := map[string]bool{"hagezi": true, "feodo": true}
	good := "ads.example.com\thagezi\n192.0.2.1\tfeodo\nads.example.com\thagezi\n"
	if err := CheckMap([]byte(good), items, ids, 3); err != nil {
		t.Fatalf("good map: %v", err)
	}
	for name, c := range map[string]struct {
		text string
		want string
	}{
		"item in no list":  {"other.example.com\thagezi\n", "in no staged list"},
		"unknown feed":     {"ads.example.com\tother\n", "not a feed id"},
		"feed with slash":  {"ads.example.com\t../x\n", "not a feed id"},
		"only dots":        {"ads.example.com\t..\n", "not a feed id"},
		"two tabs":         {"ads.example.com\thagezi\tx\n", "one TAB"},
		"no tab":           {"ads.example.com hagezi\n", "one TAB"},
		"second feed":      {"ads.example.com\thagezi\nads.example.com\tfeodo\n", "second feed"},
		"no newline":       {"ads.example.com\thagezi", "no newline"},
		"over the entries": {"ads.example.com\thagezi\n192.0.2.1\tfeodo\nads.example.com\thagezi\nads.example.com\thagezi\n", "more than"},
	} {
		if err := CheckMap([]byte(c.text), items, ids, 3); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestFilterReport(t *testing.T) {
	in := "OK a: 1 ips\n" +
		"FAIL b: x509: certificate is valid for a\x1b]0;t\x07.example, not b\r\n" +
		"junk line\n" +
		"WARN c: caf\xc3\xa9\n" +
		"STALE d: " + strings.Repeat("x", 600) + "\n" +
		"\n"
	got := FilterReport([]byte(in))
	want := []string{
		"OK a: 1 ips",
		"FAIL b: x509: certificate is valid for a?]0;t?.example, not b?",
		"WARN c: caf??",
		"STALE d: " + strings.Repeat("x", 512-len("STALE d: ")),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("FilterReport:\n got %q\nwant %q", got, want)
	}
	many := strings.Repeat("OK x: 1 ips\n", reportLines+10)
	if n := len(FilterReport([]byte(many))); n != reportLines {
		t.Fatalf("FilterReport kept %d lines, want %d", n, reportLines)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	run, err := NewRun()
	if err != nil || !ValidRun(run) {
		t.Fatalf("NewRun: %q %v", run, err)
	}
	for _, d := range []time.Duration{0, 30 * time.Minute} {
		r := Request{Fresh: d, Run: run}
		got, err := ParseRequest(r.Bytes())
		if err != nil || got != r {
			t.Fatalf("ParseRequest(%q) = %+v, %v", r.Bytes(), got, err)
		}
	}
}

func TestParseRequestRefusesOtherForms(t *testing.T) {
	run := strings.Repeat("ab", 16)
	for _, in := range []string{
		"",
		"fresh 0s\n",
		"fresh 0s\nrun " + run,
		"fresh 0s\nrun " + run + "\nextra\n",
		"fresh -1s\nrun " + run + "\n",
		"fresh 25h\nrun " + run + "\n",
		"fresh 1\nrun " + run + "\n",
		"fresh 0s\nrun " + strings.ToUpper(run) + "\n",
		"fresh 0s\nrun " + run[:31] + "\n",
		"run " + run + "\nfresh 0s\n",
		"fresh 0s\nrun " + run + "\n" + strings.Repeat(" ", 100),
	} {
		if _, err := ParseRequest([]byte(in)); err == nil {
			t.Errorf("ParseRequest(%q) accepted", in)
		}
	}
}

func TestReadLimits(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"feeds":[{"id":"a"},{"id":"b.c-d_e"},{"id":"../x"}]}`)
	l, err := ReadLimits(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.MaxIPs != DefaultMaxIPs || l.MaxDomains != DefaultMaxDomains {
		t.Fatalf("defaults: %+v", l)
	}
	if !l.FeedIDs["a"] || !l.FeedIDs["b.c-d_e"] || l.FeedIDs["../x"] || len(l.FeedIDs) != 2 {
		t.Fatalf("feed ids: %v", l.FeedIDs)
	}
	write(`{"max_ips":5,"max_domains":7}`)
	if l, err := ReadLimits(dir); err != nil || l.MaxIPs != 5 || l.MaxDomains != 7 {
		t.Fatalf("caps: %+v %v", l, err)
	}
	write(`{"max_ips":-1}`)
	if _, err := ReadLimits(dir); err == nil {
		t.Fatal("a negative cap was accepted")
	}
	// A cap above the ceiling gives the ceiling.
	write(`{"max_ips":1000001,"max_domains":9000000000}`)
	if l, err := ReadLimits(dir); err != nil || l.MaxIPs != MaxCap || l.MaxDomains != MaxCap {
		t.Fatalf("caps over the ceiling: %+v %v", l, err)
	}
	write(`{"max_ips":1000000}`)
	if l, err := ReadLimits(dir); err != nil || l.MaxIPs != 1000000 {
		t.Fatalf("a cap at the ceiling: %+v %v", l, err)
	}
}

func TestInputFilesNameThePolicyFiles(t *testing.T) {
	want := "sources.json never_block.ips never_block.domains house_never_block.domains"
	if got := strings.Join(InputFiles(), " "); got != want {
		t.Fatalf("InputFiles = %q, want %q", got, want)
	}
	want = "blacklist.ips blacklist.domains house.domains house_vpn.domains eyeball.table"
	if got := strings.Join([]string{IPsFile, DomainsFile, HouseDomainsFile, HouseVPNFile, EyeballFile}, " "); got != want {
		t.Fatalf("staged names = %q, want %q", got, want)
	}
}

func TestCommitRefusesAPathBeforeAnyRename(t *testing.T) {
	out := t.TempDir()
	err := Commit(out, []File{{"a", []byte("x\n")}, {"../b", []byte("y\n")}})
	if err == nil {
		t.Fatal("Commit took ../b")
	}
	if _, err := os.Stat(filepath.Join(out, "a")); !os.IsNotExist(err) {
		t.Fatalf("a was renamed in before the refusal: %v", err)
	}
}
