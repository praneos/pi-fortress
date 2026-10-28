package fetch

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/eyeball"
)

// The fixtures use the documentation ASNs (RFC 5398: 64496-64511) and the
// TEST-NET ranges (RFC 5737).
const (
	eyeRangesURL = "https://ranges.test/ip2asn-v4.tsv.gz"
	eyeClassURL  = "https://asn.test/asns.csv"
	eyeTagURL    = "https://asn.test/dsl.csv"
	eyePDBURL    = "https://asn.test/net.json"
)

var eyeRanges = strings.Join([]string{
	"192.0.2.0\t192.0.2.127\t64496\tZZ\tHOME-NET-A",
	// Adjacent, same ASN: joined with the line before.
	"192.0.2.128\t192.0.2.255\t64496\tZZ\tHOME-NET-A",
	// Unknown ASN: in no ASN feed, so not in the table.
	"192.0.3.0\t192.0.3.255\t64498\tZZ\tUNKNOWN",
	// Included by the tag list, excluded by its Content class.
	"198.51.100.0\t198.51.100.255\t64497\tZZ\tCONTENT-NET",
	"203.0.113.0\t203.0.113.63\t64499\tZZ\tDSL-NET",
	"203.0.113.64\t203.0.113.127\t64500\tZZ\tPDB-ISP",
	"203.0.113.128\t203.0.113.255\t64501\tZZ\tPDB-NSP",
	"0.0.0.0\t0.255.255.255\t0\tNone\tNot routed",
	"2001:db8::\t2001:db8::ffff\t64496\tZZ\tV6",
	"not a line",
}, "\n") + "\n"

const (
	eyeClass = "asn,name,class,cc\nAS64496,\"Home, Net A\",Eyeball,ZZ\nAS64497,Content Net,Content,ZZ\nAS64498,Unknown Net,Unknown,ZZ\n"
	eyeTag   = "AS64499,DSL Net\nAS64497,Content Net\n"
	eyePDB   = `{"data":[{"asn":64500,"info_type":"Cable/DSL/ISP","info_types":["Cable/DSL/ISP"]},{"asn":64501,"info_type":"NSP","info_types":["NSP"]},{"asn":64502,"info_type":"","info_types":["Cable/DSL/ISP"]}]}`
)

const eyeSpec = `{"user_agent":"pf-test","timeout_sec":2,"feeds":[],
"eyeball":{"user_agent":"pf-test-eyeball","max_ranges":%MAX%,
 "ranges":{"id":"ranges","format":"ip2asn","url":"` + eyeRangesURL + `"},
 "asns":[{"id":"class","format":"bgptools","url":"` + eyeClassURL + `"},
         {"id":"tag","format":"asn","url":"` + eyeTagURL + `"},
         {"id":"pdb","format":"peeringdb","url":"` + eyePDBURL + `"}]}}`

type eyeFeeds struct {
	down map[string]bool
	uas  map[string]string
}

func eyeDir(t *testing.T, max string, feeds *eyeFeeds, now func() time.Time) (*Fetcher, string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"never_block.domains", "never_block.ips", "house_never_block.domains"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	spec := strings.ReplaceAll(eyeSpec, "%MAX%", max)
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	gz := string(gzipped(t, eyeRanges))
	bodies := map[string]string{eyeRangesURL: gz, eyeClassURL: eyeClass, eyeTagURL: eyeTag, eyePDBURL: eyePDB}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Now: now, Get: func(u, ua string, _ time.Duration) (string, error) {
		feeds.uas[u] = ua
		if feeds.down[u] {
			return "", errors.New("HTTP 503")
		}
		b, ok := bodies[u]
		if !ok {
			return "", errors.New("no such feed")
		}
		return b, nil
	}}
	return f, out
}

func readEyeTable(t *testing.T, out string) *eyeball.Table {
	t.Helper()
	fh, err := os.Open(filepath.Join(out, eyeball.TableFile))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	tab, err := eyeball.Parse(fh)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestEyeballTableBuilt(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	feeds := &eyeFeeds{down: map[string]bool{}, uas: map[string]string{}}
	f, out := eyeDir(t, "0", feeds, func() time.Time { return now })
	report, _, _, _ := f.Run()
	raw, err := os.ReadFile(filepath.Join(out, eyeball.TableFile))
	if err != nil {
		t.Fatalf("no table: %v; report %q", err, report)
	}
	want := eyeball.Magic + "\n# built 2026-10-02T04:00:00Z\n" +
		"192.0.2.0 192.0.2.255 64496\n203.0.113.0 203.0.113.63 64499\n203.0.113.64 203.0.113.127 64500\n"
	if string(raw) != want {
		t.Fatalf("table:\n%s\nwant:\n%s\nreport %q", raw, want, report)
	}
	for _, line := range []string{"OK ranges: 6 asn ranges", "OK class: 2 asns", "OK tag: 2 asns", "OK pdb: 2 asns", "OK eyeball: 3 ranges in eyeball.table"} {
		if !strings.Contains(strings.Join(report, "\n"), line) {
			t.Errorf("report %q has no %q", report, line)
		}
	}
	for u, ua := range feeds.uas {
		if ua != "pf-test-eyeball" {
			t.Errorf("%s got user agent %q", u, ua)
		}
	}
}

func TestEyeballFeedServesItsLastCopy(t *testing.T) {
	base := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	clock := base
	feeds := &eyeFeeds{down: map[string]bool{}, uas: map[string]string{}}
	f, out := eyeDir(t, "0", feeds, func() time.Time { return clock })
	f.Run()
	if err := os.Chtimes(filepath.Join(out, "feeds", "ranges.list"), base, base); err != nil {
		t.Fatal(err)
	}
	feeds.down[eyeRangesURL] = true
	feeds.down[eyeTagURL] = true
	clock = base.Add(48 * time.Hour)
	report, _, _, _ := f.Run()
	text := strings.Join(report, "\n")
	if !strings.Contains(text, "STALE ranges: 6 asn ranges (last good 2d0h ago: HTTP 503)") {
		t.Errorf("report %q", report)
	}
	tab := readEyeTable(t, out)
	// The table has the time of its oldest data: the copy of the ranges.
	if tab.Len() != 3 || !tab.Built.Equal(base) {
		t.Errorf("len %d built %v, want 3 and %v", tab.Len(), tab.Built, base)
	}
}

func TestEyeballNoDataNoTable(t *testing.T) {
	feeds := &eyeFeeds{down: map[string]bool{eyeRangesURL: true}, uas: map[string]string{}}
	f, out := eyeDir(t, "0", feeds, nil)
	report, _, _, _ := f.Run()
	if _, err := os.Stat(filepath.Join(out, eyeball.TableFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a table with no ranges: %v", err)
	}
	if !strings.Contains(strings.Join(report, "\n"), "FAIL eyeball: no table built") {
		t.Errorf("report %q", report)
	}
	fails, _, _ := CountWarnings(report)
	if fails < 2 {
		t.Errorf("fails %d, want the feed and the table", fails)
	}
}

func TestEyeballRangesCap(t *testing.T) {
	feeds := &eyeFeeds{down: map[string]bool{}, uas: map[string]string{}}
	f, out := eyeDir(t, "2", feeds, nil)
	report, _, _, _ := f.Run()
	if !strings.Contains(strings.Join(report, "\n"), "OK ranges: 2 asn ranges (more than the cap of 2; the rest not read)") {
		t.Errorf("report %q", report)
	}
	if tab := readEyeTable(t, out); tab.Len() != 1 {
		t.Errorf("len %d, want the first range only", tab.Len())
	}
}

func TestEyeballSpecRefused(t *testing.T) {
	ok := `"ranges":{"id":"r","format":"ip2asn","url":"https://r.test/x"}`
	for name, section := range map[string]string{
		"ranges format": `"ranges":{"id":"r","format":"plain","url":"https://r.test/x"},"asns":[]`,
		"asn format":    ok + `,"asns":[{"id":"a","format":"hosts","url":"https://a.test/x"}]`,
		"no url":        ok + `,"asns":[{"id":"a","format":"asn"}]`,
		"bad id":        ok + `,"asns":[{"id":"../x","format":"asn","url":"https://a.test/x"}]`,
		"dup id":        ok + `,"asns":[{"id":"r","format":"asn","url":"https://a.test/x"}]`,
		"dup feed id":   ok + `,"asns":[{"id":"d","format":"asn","url":"https://a.test/x"}]`,
		"neg max":       `"max_ranges":-1,` + ok,
	} {
		raw := `{"feeds":[{"id":"d","kind":"domains","url":"https://d.test/x"}],"eyeball":{` + section + `}}`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readSpec(dir); err == nil {
			t.Errorf("%s: spec accepted", name)
		}
	}
}

func TestParseASNFormats(t *testing.T) {
	got, err := parseASNs(Feed{Format: "asn"}, "# list\nAS64496, a\n64497\nas64498 x\nAS0\nnot an asn\n\r\n")
	if err != nil || strings.Join(got, " ") != "+64496 +64497 +64498" {
		t.Errorf("asn: %q %v", got, err)
	}
	if _, err := parseASNs(Feed{Format: "bgptools"}, "a,b\n1,2\n"); err == nil {
		t.Error("bgptools without asn and class columns parsed")
	}
	if _, err := parseASNs(Feed{Format: "peeringdb"}, "<html>"); err == nil {
		t.Error("peeringdb html parsed")
	}
}

// heapBytes gives the bytes that fn allocates on the heap.
func heapBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestEyeballPeeringDBStreams: the PeeringDB answer is read one network at
// a time. A list with more networks than maxASNs is refused. The
// info_types list of a network is not kept, so a long list does not use
// memory for each item.
func TestEyeballPeeringDBStreams(t *testing.T) {
	pdb := Feed{Format: "peeringdb"}
	over := `{"data":[{}` + strings.Repeat(",{}", maxASNs) + `]}`
	if _, err := parseASNs(pdb, over); err == nil {
		t.Errorf("%d networks parsed, want a refusal", maxASNs+1)
	}
	got, err := parseASNs(pdb, `{"meta":{"a":[1,{"b":null}]},"data":[{"asn":64500,"info_types":["NSP","Cable/DSL/ISP"]},null,{"asn":64501,"info_types":null}],"c":"d"}`)
	if err != nil || strings.Join(got, " ") != "+64500" {
		t.Errorf("other keys: %q %v", got, err)
	}
	for _, bad := range []string{`{"data":[]} x`, `{"data":{}}`, `{"data":[{"asn":"64500"}]}`, `{"data":[{"info_types":"Cable/DSL/ISP"}]}`, `{"data":[{}`} {
		if got, err := parseASNs(pdb, bad); err == nil {
			t.Errorf("%s parsed: %q", bad, got)
		}
	}
	long := `{"data":[{"asn":64500,"info_types":[` + strings.Repeat(`"",`, 1<<20) + `"Cable/DSL/ISP"]}]}`
	var items []string
	n := heapBytes(func() { items, err = parseASNs(pdb, long) })
	if err != nil || strings.Join(items, " ") != "+64500" {
		t.Fatalf("long info_types: %q %v", items, err)
	}
	if n > 8*uint64(len(long)) {
		t.Errorf("a body of %d bytes allocated %d bytes", len(long), n)
	}
}

// TestEyeballASNListLines: an asn list is read line by line. Many empty
// lines use little memory, and a line longer than the line cap is refused.
func TestEyeballASNListLines(t *testing.T) {
	asn := Feed{Format: "asn"}
	body := "AS64496 home\n" + strings.Repeat("\n", 4<<20)
	var items []string
	var err error
	n := heapBytes(func() { items, err = parseASNs(asn, body) })
	if err != nil || strings.Join(items, " ") != "+64496" {
		t.Fatalf("empty lines: %q %v", items, err)
	}
	if n > uint64(len(body))/4 {
		t.Errorf("a body of %d bytes allocated %d bytes", len(body), n)
	}
	if got, err := parseASNs(asn, "AS64496\n"+strings.Repeat("1 ", 1<<19)+"\n"); err == nil {
		t.Errorf("a line of 1 MiB parsed: %d items", len(got))
	}
}

// TestEyeballCSVRecordCap: a bgp.tools CSV record longer than the line cap
// is refused: a row of many fields, and a quoted field that joins many
// lines into one record. The cap of one record, not the size of the body,
// sets the memory of the parse.
func TestEyeballCSVRecordCap(t *testing.T) {
	for name, body := range map[string]string{
		"commas":          "asn,class\nAS64496,Eyeball\n" + strings.Repeat(",", 1<<20) + "\n",
		"quoted newlines": "asn,class\nAS64496,Eyeball\n" + strings.Repeat("\"a\na\",", 1<<18) + "\n",
	} {
		var err error
		n := heapBytes(func() { _, err = parseASNs(Feed{Format: "bgptools"}, body) })
		if err == nil {
			t.Errorf("%s: parsed", name)
		}
		if n > 16<<20 {
			t.Errorf("%s: a body of %d bytes allocated %d bytes", name, len(body), n)
		}
	}
}

// TestEyeballBodyCapPerFormat: each eyeball format has its own download
// cap. A PeeringDB answer of 17 MiB is refused; a ranges feed of 20 MiB is
// read.
func TestEyeballBodyCapPerFormat(t *testing.T) {
	pad := strings.Repeat("\n", 17<<20)
	// The ranges feed gets rows with ASN 0 as padding, not empty lines. A
	// ranges feed with many lines that are not rows is refused.
	row := "192.0.2.0\t192.0.2.0\t0\tNone\t" + strings.Repeat("x", 1000) + "\n"
	bodies := map[string]string{
		eyePDBURL:    eyePDB + pad,
		eyeRangesURL: eyeRanges + strings.Repeat(row, (20<<20)/len(row)+1),
	}
	f := &Fetcher{Get: func(u, _ string, _ time.Duration) (string, error) { return bodies[u], nil }}
	var report []string
	if _, _, ok := f.eyeballItems(t.TempDir(), "", 0, Feed{ID: "pdb", Kind: kindASNs, Format: "peeringdb", URL: eyePDBURL}, 0, &report); ok {
		t.Errorf("a PeeringDB answer of 17 MiB was read: %q", report)
	}
	if _, _, ok := f.eyeballItems(t.TempDir(), "", 0, Feed{ID: "ranges", Kind: kindRanges, Format: "ip2asn", URL: eyeRangesURL}, 100, &report); !ok {
		t.Errorf("a ranges feed of 20 MiB was refused: %q", report)
	}
}

// TestEyeballFailureKeepsBlocklistCommit: pf fetch writes the blocklist
// before it gets the eyeball feeds. Thus a run that stops in the eyeball
// step still leaves the new blocklist. At the end of the run, fetch.report
// has the eyeball lines, and the last-good copies of all feeds stay.
func TestEyeballFailureKeepsBlocklistCommit(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"never_block.domains", "never_block.ips", "house_never_block.domains"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	const blockURL = "https://block.test/domains"
	spec := `{"feeds":[{"id":"d","kind":"domains","url":"` + blockURL + `"}],
"eyeball":{"ranges":{"id":"ranges","format":"ip2asn","url":"` + eyeRangesURL + `"},
 "asns":[{"id":"pdb","format":"peeringdb","url":"` + eyePDBURL + `"}]}}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	atEyeball := ""
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(u, _ string, _ time.Duration) (string, error) {
		switch u {
		case blockURL:
			return "fresh.example\n", nil
		case eyePDBURL:
			raw, _ := os.ReadFile(filepath.Join(out, "blacklist.domains"))
			atEyeball = string(raw)
			return `{"data":[{}` + strings.Repeat(",{}", maxASNs) + `]}`, nil
		case eyeRangesURL:
			return eyeRanges, nil
		}
		return "", errors.New("no such feed")
	}}
	report, _, nDoms, err := f.Run()
	if err != nil || nDoms != 1 {
		t.Fatalf("err %v, domains %d, report %q", err, nDoms, report)
	}
	if atEyeball != "fresh.example\n" {
		t.Errorf("blocklist at the eyeball fetch: %q, want the new list", atEyeball)
	}
	rep, err := os.ReadFile(filepath.Join(out, "fetch.report"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"OK d: 1 domains", "OK ranges: 6 asn ranges", "FAIL pdb: does not parse", "FAIL eyeball: no table built"} {
		if !strings.Contains(string(rep), line) {
			t.Errorf("fetch.report has no %q:\n%s", line, rep)
		}
	}
	for _, id := range []string{"d", "ranges"} {
		if _, err := os.Stat(filepath.Join(out, "feeds", id+".list")); err != nil {
			t.Errorf("last-good copy of %s: %v", id, err)
		}
	}
}

func TestParseRangesPlainAndGzip(t *testing.T) {
	plain, _, err := parseRanges(eyeRanges, 100)
	if err != nil {
		t.Fatal(err)
	}
	gz, _, err := parseRanges(string(gzipped(t, eyeRanges)), 100)
	if err != nil || strings.Join(plain, "|") != strings.Join(gz, "|") || len(plain) != 6 {
		t.Fatalf("plain %q gz %q %v", plain, gz, err)
	}
	if _, _, err := parseRanges("\x1f\x8bnot gzip", 100); err == nil {
		t.Error("a broken gzip parsed")
	}
}

func TestMergeSeedEyeball(t *testing.T) {
	seed := []byte(`{"feeds":[],"eyeball":{"ranges":{"id":"r","format":"ip2asn","url":"https://r.test/x"},` +
		`"asns":[{"id":"a","format":"asn","url":"https://a.test/x"},{"id":"b","format":"asn","url":"https://b.test/x"}]}}`)
	// A box with no section gets it.
	out, changed, err := MergeSeed([]byte(`{"feeds":[]}`), seed)
	if err != nil || !changed || !strings.Contains(string(out), `"eyeball"`) {
		t.Fatalf("no section: %s %v %v", out, changed, err)
	}
	// The same merge again changes nothing.
	if _, changed, _ := MergeSeed(out, seed); changed {
		t.Error("a second merge changed the file")
	}
	// A box that was offered the section and deleted it keeps it deleted.
	if out, changed, _ := MergeSeed([]byte(`{"feeds":[],"seeded":["r","a","b"]}`), seed); changed || strings.Contains(string(out), `"eyeball"`) {
		t.Errorf("deleted section came back: %s", out)
	}
	// A box with a section gets a new ASN feed, and keeps its own settings.
	box := []byte(`{"feeds":[],"seeded":["r","a"],"eyeball":{"max_ranges":5,"ranges":{"id":"r","format":"ip2asn","url":"https://own.test/x"},"asns":[]}}`)
	out, changed, err = MergeSeed(box, seed)
	if err != nil || !changed {
		t.Fatalf("new feed: %v %v", changed, err)
	}
	s := string(out)
	if !strings.Contains(s, `"id": "b"`) || strings.Contains(s, `"id": "a"`) || !strings.Contains(s, "own.test") || !strings.Contains(s, `"max_ranges": 5`) {
		t.Errorf("merged %s", s)
	}
}

// FuzzEyeballFeeds: the parsers of the eyeball feeds never panic, and each
// item that they give is an item that the last-good copy reads back.
func FuzzEyeballFeeds(f *testing.F) {
	f.Add(eyeRanges)
	f.Add(eyeClass)
	f.Add(eyeTag)
	f.Add(eyePDB)
	f.Add("\x1f\x8b")
	f.Fuzz(func(t *testing.T, body string) {
		items, _, err := parseRanges(body, 50)
		if err == nil {
			for _, it := range items {
				if got, ok := parseEyeballToken(it, kindRanges); !ok || got != it {
					t.Fatalf("range item %q reads back as %q, %v", it, got, ok)
				}
			}
		}
		for _, format := range []string{"bgptools", "peeringdb", "asn"} {
			items, err := parseASNs(Feed{Format: format}, body)
			if err != nil {
				continue
			}
			for _, it := range items {
				if got, ok := parseEyeballToken(it, kindASNs); !ok || got != it {
					t.Fatalf("%s item %q reads back as %q, %v", format, it, got, ok)
				}
			}
		}
	})
}
