package fetch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/feedstage"
	"pi-fortress/internal/testsupport"
)

const stageSpec = `{"feeds":[
  {"id":"ips","kind":"ips","format":"plain","url":"https://ips.test/"},
  {"id":"doms","kind":"domains","format":"plain","url":"https://doms.test/"},
  {"id":"ads","kind":"domains","format":"plain","segment":"house","url":"https://ads.test/"},
  {"id":"vpn","kind":"domains","format":"plain","segment":"house","role":"vpn","url":"https://vpn.test/"},
  {"id":"tls","kind":"domains","format":"plain","url":"https://tls.test/"}
]}`

// stageBodies answers the feeds of stageSpec. The tls feed fails with the
// text of a hostname error whose certificate name has ESC and BEL in it.
func stageBodies(url, _ string, _ time.Duration) (string, error) {
	switch url {
	case "https://ips.test/":
		return "192.0.2.1\n1.2.3.0/24\n10.0.0.1\n", nil
	case "https://doms.test/":
		return "Ads.Example.com\n0.0.0.0 tracker.example.org\n192.0.2.7\n", nil
	case "https://ads.test/":
		return "tracker.example.net\n192.0.2.5\n", nil
	case "https://vpn.test/":
		return "vpn.example.com\n", nil
	}
	return "", errors.New("x509: certificate is valid for a\x1b]0;t\x07.example, not tls.test")
}

type stageDirs struct {
	policy, state, stage, cache, gen string
}

func newStageDirs(t *testing.T) stageDirs {
	t.Helper()
	d := stageDirs{policy: t.TempDir(), state: t.TempDir()}
	d.stage = filepath.Join(d.state, feedstage.StageName)
	d.cache = filepath.Join(d.state, feedstage.CacheName)
	d.gen = filepath.Join(d.policy, "generated")
	if err := os.WriteFile(filepath.Join(d.policy, "sources.json"), []byte(stageSpec), 0644); err != nil {
		t.Fatal(err)
	}
	return d
}

func (d stageDirs) fetcher(run string) *Fetcher {
	return &Fetcher{PolicyDir: d.policy, OutDir: d.stage, CacheDir: d.cache, RunID: run, Get: stageBodies}
}

func (d stageDirs) importCfg(t *testing.T, run string) feedstage.Config {
	t.Helper()
	l, err := feedstage.ReadLimits(d.policy)
	if err != nil {
		t.Fatal(err)
	}
	return feedstage.Config{StateDir: d.state, OutDir: d.gen, Limits: l, Run: run, UID: os.Getuid()}
}

// The stage that pf fetch writes passes the check of root, and root then
// has the same lists in generated/.
func TestStageRunMakesASetThatRootImports(t *testing.T) {
	d := newStageDirs(t)
	run, err := feedstage.NewRun()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.fetcher(run).Run(); err != nil {
		t.Fatal(err)
	}
	if got := testsupport.ReadFile(t, filepath.Join(d.stage, feedstage.RunFile)); got != run+"\n" {
		t.Fatalf("run file %q", got)
	}
	if got := testsupport.ReadFile(t, filepath.Join(d.stage, "house.domains")); got != "tracker.example.net\n" {
		t.Fatalf("house list %q: an address went into a name list", got)
	}
	report := testsupport.ReadFile(t, filepath.Join(d.stage, "fetch.report"))
	if strings.ContainsAny(report, "\x1b\x07") || !strings.Contains(report, "a?]0;t?.example") {
		t.Fatalf("report has a control byte:\n%q", report)
	}
	if _, err := os.Stat(filepath.Join(d.cache, "ips.list")); err != nil {
		t.Fatalf("no last-good copy in the cache directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.stage, "feeds")); !os.IsNotExist(err) {
		t.Fatalf("copies went into the stage: %v", err)
	}
	res, err := feedstage.Import(d.importCfg(t, run))
	if err != nil || !res.Imported {
		t.Fatalf("root refused the stage of pf fetch: %+v %v", res, err)
	}
	for name, want := range map[string]string{
		"blacklist.ips":     "192.0.2.1\n1.2.3.0/24\n",
		"blacklist.domains": "ads.example.com\ntracker.example.org\n192.0.2.7\n",
		"house.domains":     "tracker.example.net\n",
		"house_vpn.domains": "vpn.example.com\n",
		"sample.domain":     "ads.example.com\n",
	} {
		if got := testsupport.ReadFile(t, filepath.Join(d.gen, name)); got != want {
			t.Errorf("generated/%s = %q, want %q", name, got, want)
		}
	}
}

// A run removes the staged files of the run before it. When all feeds
// fail, the stage has only the report and the run id, so root keeps its
// lists.
func TestStageRunClearsTheEarlierSet(t *testing.T) {
	d := newStageDirs(t)
	if err := os.MkdirAll(d.stage, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blacklist.ips", "eyeball.table", "feeds.map", "run"} {
		if err := os.WriteFile(filepath.Join(d.stage, name), []byte("old\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f := d.fetcher(strings.Repeat("ab", 16))
	f.Get = func(string, string, time.Duration) (string, error) { return "", errors.New("down") }
	if _, _, _, err := f.Run(); err == nil {
		t.Fatal("a run in which all feeds failed returned no error")
	}
	ents, err := os.ReadDir(d.stage)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, " "); got != "fetch.report run" {
		t.Fatalf("stage after a failed run: %s", got)
	}
	if got := testsupport.ReadFile(t, filepath.Join(d.stage, "run")); got != strings.Repeat("ab", 16)+"\n" {
		t.Fatalf("run file %q", got)
	}
}

// A run that cannot clear its stage writes no run id. Root then imports
// nothing.
func TestStageRunThatCannotWriteItsStageHasNoRunID(t *testing.T) {
	d := newStageDirs(t)
	if err := os.MkdirAll(filepath.Join(d.stage, "blacklist.ips", "x"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.fetcher(strings.Repeat("cd", 16)).Run(); err == nil {
		t.Fatal("Run did not fail")
	}
	if _, err := os.Stat(filepath.Join(d.stage, "run")); !os.IsNotExist(err) {
		t.Fatalf("run file written: %v", err)
	}
}

// The first run of the download unit has no copy of its own. A feed that
// fails then serves the copy that root put in the seed directory.
func TestStageRunReadsTheSeedCopy(t *testing.T) {
	d := newStageDirs(t)
	seed := filepath.Join(d.policy, "seed")
	spec, err := readSpec(d.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCacheIn(seed, spec.Feeds[0], []string{"192.0.2.99"}); err != nil {
		t.Fatal(err)
	}
	f := d.fetcher(strings.Repeat("ef", 16))
	f.SeedDir = seed
	f.Get = func(url, ua string, to time.Duration) (string, error) {
		if url == "https://ips.test/" {
			return "", errors.New("down")
		}
		return stageBodies(url, ua, to)
	}
	report, _, _, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(report, "\n"), "STALE ips: 1 ips") {
		t.Fatalf("report:\n%s", strings.Join(report, "\n"))
	}
	if got := testsupport.ReadFile(t, filepath.Join(d.stage, "blacklist.ips")); got != "192.0.2.99\n" {
		t.Fatalf("ips %q", got)
	}
	if _, err := os.Stat(filepath.Join(d.cache, "ips.list")); !os.IsNotExist(err) {
		t.Fatalf("the seed copy was written to the cache: %v", err)
	}
}

// A second stage run within -fresh serves the feeds from the copies in
// -cache, and does not download them again.
func TestStageRunReusesTheCacheCopy(t *testing.T) {
	d := newStageDirs(t)
	if _, _, _, err := d.fetcher(strings.Repeat("aa", 16)).Run(); err != nil {
		t.Fatal(err)
	}
	f := d.fetcher(strings.Repeat("bb", 16))
	f.FreshFor = 30 * time.Minute
	f.Get = func(url, ua string, to time.Duration) (string, error) {
		if url != "https://tls.test/" {
			t.Errorf("%s downloaded again within -fresh", url)
		}
		return stageBodies(url, ua, to)
	}
	report, _, _, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(report, "\n"), "OK ips: 2 ips (last good") {
		t.Fatalf("report:\n%s", strings.Join(report, "\n"))
	}
	if got := testsupport.ReadFile(t, filepath.Join(d.stage, "blacklist.ips")); !strings.Contains(got, "1.2.3.0/24\n") {
		t.Fatalf("ips %q", got)
	}
}

func TestReportTextHasOnlyPrintableASCII(t *testing.T) {
	got := reportText([]string{"FAIL x: a\x1b]0;t\x07b\r", "OK y: caf\xc3\xa9"})
	if want := "FAIL x: a?]0;t?b?\nOK y: caf??\n"; got != want {
		t.Fatalf("reportText = %q, want %q", got, want)
	}
}

// As root, Run downloads nothing and writes nothing, in stage mode and in
// the mode that writes generated/.
func TestRunAsRootDownloadsNothing(t *testing.T) {
	old := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = old })
	d := newStageDirs(t)
	get := func(string, string, time.Duration) (string, error) {
		t.Fatal("a feed was downloaded as root")
		return "", nil
	}
	for _, f := range []*Fetcher{
		d.fetcher(strings.Repeat("ab", 16)),
		{PolicyDir: d.policy},
	} {
		f.Get = get
		if _, _, _, err := f.Run(); !errors.Is(err, ErrRoot) {
			t.Fatalf("Run as root: %v", err)
		}
	}
	for _, dir := range []string{d.state, d.gen} {
		if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 || err != nil && !os.IsNotExist(err) {
			t.Fatalf("%s written as root: %v %v", dir, ents, err)
		}
	}
}

// Run refuses root. When root runs go test, as in some containers, the
// tests of this package use a different euid. Only the root test above
// sets 0.
func TestMain(m *testing.M) {
	if geteuid() == 0 {
		geteuid = func() int { return 65534 }
	}
	os.Exit(m.Run())
}
