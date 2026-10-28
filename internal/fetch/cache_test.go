package fetch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/policycompile"
	"pi-fortress/internal/testsupport"
)

// staleDir writes a policy whose one feed is served by body, and returns
// the fetcher and its generated directory.
func staleDir(t *testing.T, body *string, fail *error, now func() time.Time) (*Fetcher, string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"never_block.domains", "never_block.ips", "house_never_block.domains"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	spec := `{"user_agent":"pf-test","timeout_sec":2,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://feed.test/d"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Now: now, Get: func(string, string, time.Duration) (string, error) {
		if *fail != nil {
			return "", *fail
		}
		return *body, nil
	}}
	return f, out
}

// This is the bug: a feed that the fetcher could not reach used to add
// nothing. So the compiled list was rebuilt without it, and each name that
// it carried was quietly no longer blocked.
func TestUnreachableFeedServesItsLastCopy(t *testing.T) {
	body := "a.example\nb.example\n"
	var boom error
	base := time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)
	clock := base
	f, out := staleDir(t, &body, &boom, func() time.Time { return clock })

	if _, _, n, err := f.Run(); err != nil || n != 2 {
		t.Fatalf("first run: %d domains, %v", n, err)
	}

	// The age comes from the mtime of the copy, so the copy also gets a date.
	if err := os.Chtimes(filepath.Join(out, "feeds", "d.list"), base, base); err != nil {
		t.Fatal(err)
	}
	boom = fmt.Errorf("HTTP 503")
	clock = base.Add(26 * time.Hour)
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	if n != 2 {
		t.Fatalf("%d domains after the feed went away, want the 2 it last carried", n)
	}
	got := testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains"))
	if !strings.Contains(got, "a.example") || !strings.Contains(got, "b.example") {
		t.Fatalf("compiled list lost the stale feed's names: %q", got)
	}
	line := strings.Join(report, "\n")
	if !strings.Contains(line, "STALE d: 2 domains") {
		t.Fatalf("report does not name the fallback: %q", line)
	}
	// The age and the reason are the full purpose of the line. Without
	// them, an operator cannot tell a feed that broke an hour ago from
	// a feed that has been dead since March.
	if !strings.Contains(line, "1d2h ago") || !strings.Contains(line, "HTTP 503") {
		t.Fatalf("report line lacks the age or the reason: %q", line)
	}
	if strings.Contains(line, "FAIL") {
		t.Fatalf("a served fallback is not a failure: %q", line)
	}
}

// A feed with no cache behind it is still a plain failure. A run in which
// that feed is the only feed still refuses to write empty lists.
func TestFirstEverFetchFailingIsStillFail(t *testing.T) {
	body := ""
	boom := fmt.Errorf("dial: no route to host")
	f, out := staleDir(t, &body, &boom, nil)
	report, _, _, err := f.Run()
	if err == nil {
		t.Fatal("a run with nothing fetched and nothing cached reported success")
	}
	if !strings.Contains(strings.Join(report, "\n"), "FAIL d:") {
		t.Fatal(report)
	}
	if _, err := os.Stat(filepath.Join(out, "blacklist.domains")); err == nil {
		t.Fatal("wrote a list from a run that fetched nothing")
	}
}

// This is the actual shape of the 3am failure: the feed answers 200 with
// an error page, which parses to no tokens at all. To count that as a feed
// with zero entries is the same silent shrink as an unreachable feed.
func TestEmptyAnswerFallsBackAndDoesNotOverwriteTheCopy(t *testing.T) {
	body := "a.example\n"
	var boom error
	f, out := staleDir(t, &body, &boom, nil)
	if _, _, n, err := f.Run(); err != nil || n != 1 {
		t.Fatalf("seed run: %d, %v", n, err)
	}
	body = "<html><body>502 Bad Gateway</body></html>"
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	if n != 1 {
		t.Fatalf("%d domains from an error page, want the cached 1", n)
	}
	if !strings.Contains(strings.Join(report, "\n"), "STALE d:") {
		t.Fatal(report)
	}
	cached := testsupport.ReadFile(t, filepath.Join(out, "feeds", "d.list"))
	if !strings.Contains(cached, "a.example") {
		t.Fatalf("the error page overwrote the copy it was meant to fall back on: %q", cached)
	}
}

// never_block is the "do not break this" list of the operator, and it
// changes between runs. So it must also apply to a stale copy, and must not
// be baked into the copy at fetch time.
func TestNeverBlockAppliesToAStaleCopy(t *testing.T) {
	body := "a.example\nb.example\n"
	var boom error
	f, out := staleDir(t, &body, &boom, nil)
	if _, _, n, err := f.Run(); err != nil || n != 2 {
		t.Fatalf("seed run: %d, %v", n, err)
	}
	if err := os.WriteFile(filepath.Join(f.PolicyDir, "never_block.domains"), []byte("a.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	boom = fmt.Errorf("HTTP 503")
	if _, _, n, err := f.Run(); err != nil || n != 1 {
		t.Fatalf("%d domains, want b.example alone: %v", n, err)
	}
	got := testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains"))
	if strings.Contains(got, "a.example") {
		t.Fatalf("never_block was ignored on the stale copy: %q", got)
	}
}

// pf compile reads never_block too, and it skips a line that is not a
// name. fetch kept such a line as it was written. A line with two fields
// then shielded nothing, with no word to the operator. A single label
// ("test") shielded each feed name under it in fetch, but not in compile.
// Now fetch skips the same lines as compile, and the report names each one.
func TestNeverBlockRefusesALineThatIsNotAName(t *testing.T) {
	body := "keep.example\nx.test\nshield.example\n"
	var boom error
	f, out := staleDir(t, &body, &boom, nil)
	never := "0.0.0.0 keep.example\ntest\nshield.example.\n"
	if err := os.WriteFile(filepath.Join(f.PolicyDir, "never_block.domains"), []byte(never), 0644); err != nil {
		t.Fatal(err)
	}
	report, _, n, err := f.Run()
	if err != nil || n != 2 {
		t.Fatalf("Run: %d domains, %v, %q", n, err, report)
	}
	if got := testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains")); got != "keep.example\nx.test\n" {
		t.Fatalf("blacklist.domains = %q", got)
	}
	rep := strings.Join(report, "\n")
	for _, want := range []string{
		`WARN never_block.domains line 1: "0.0.0.0 keep.example" is not a domain; skipped`,
		`WARN never_block.domains line 2: "test" is not a domain; skipped`,
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report has no %q:\n%s", want, rep)
		}
	}
	if strings.Contains(rep, "line 3") {
		t.Errorf("a valid line is reported:\n%s", rep)
	}
	path := filepath.Join(f.PolicyDir, "never_block.domains")
	var warn []string
	compiled, err := policycompile.LoadTokens(path, "domains")
	if got := readListFile(path, "domains", &warn); err != nil || strings.Join(got, ",") != strings.Join(compiled, ",") {
		t.Fatalf("fetch reads %q, compile reads %q (%v)", got, compiled, err)
	}
}

// Feed ids come from sources.json, which an operator edits by hand.
func TestCacheNameRefusesAPath(t *testing.T) {
	for _, bad := range []string{"", "..", ".", "../net.env", "a/b", "a\x00b", strings.Repeat("a", 65), "a b"} {
		if _, ok := cacheName(bad); ok {
			t.Errorf("%q accepted as a cache file name", bad)
		}
	}
	for _, good := range []string{"urlhaus", "spamhaus-drop", "a.b_c", "A1"} {
		if n, ok := cacheName(good); !ok || n != good+".list" {
			t.Errorf("%q rejected", good)
		}
	}
}

func TestPruneCacheKeepsWhatTheSpecStillNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(cacheDir(dir), 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"keep.list", "gone.list", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(cacheDir(dir), n), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	pruneCache(dir, map[string]bool{"keep": true})
	for _, n := range []string{"keep.list", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(cacheDir(dir), n)); err != nil {
			t.Errorf("%s removed", n)
		}
	}
	if _, err := os.Stat(filepath.Join(cacheDir(dir), "gone.list")); err == nil {
		t.Error("a feed no longer in sources.json kept its copy")
	}
}

// A disabled feed keeps its copy. When it is enabled again, it must not
// start from nothing: that would be the silent shrink again, by a different route.
func TestDisabledFeedKeepsItsCopy(t *testing.T) {
	body := "a.example\n"
	var boom error
	f, out := staleDir(t, &body, &boom, nil)
	if _, _, _, err := f.Run(); err != nil {
		t.Fatal(err)
	}
	spec := `{"user_agent":"pf-test","timeout_sec":2,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://feed.test/d","enabled":false}]}`
	if err := os.WriteFile(filepath.Join(f.PolicyDir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = f.Run()
	if _, err := os.Stat(filepath.Join(out, "feeds", "d.list")); err != nil {
		t.Fatal("a disabled feed lost its copy")
	}
}

func TestNeverBlockIPsDropsFeedAddresses(t *testing.T) {
	dir := t.TempDir()
	for n, body := range map[string]string{
		"never_block.ips":           "1.1.1.0/24\n",
		"never_block.domains":       "",
		"house_never_block.domains": "",
		"sources.json":              `{"feeds":[{"id":"i","kind":"ips","url":"https://feed.test/i"}]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) {
		return "1.1.1.7\n9.9.9.9\n9.9.9.9\n", nil
	}}
	report, nIPs, _, err := f.Run()
	if err != nil || nIPs != 1 {
		t.Fatalf("Run: %d ips, %v, %q", nIPs, err, report)
	}
	if got := testsupport.ReadFile(t, filepath.Join(out, "blacklist.ips")); got != "9.9.9.9\n" {
		t.Fatalf("blacklist.ips = %q", got)
	}
	if want := []string{"OK i: 1 ips"}; strings.Join(report, "|") != strings.Join(want, "|") {
		t.Fatalf("report = %q, want %q", report, want)
	}
}

// FreshFor serves a feed from a copy that is younger than FreshFor, with
// no download. All other copies get the usual download: an old copy, a
// copy with a time in the future, a copy that does not parse, a copy of a
// feed with a different URL, and each copy when FreshFor is zero.
func TestFreshCopySkipsTheDownload(t *testing.T) {
	base := time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		fresh    time.Duration
		at       time.Duration // clock of the second run, after the copy
		damage   bool          // the copy loses its stamp
		otherURL bool          // the feed points at a new URL
		reuse    bool
	}{
		{name: "young copy", fresh: 30 * time.Minute, at: 10 * time.Minute, reuse: true},
		{name: "old copy", fresh: 30 * time.Minute, at: 30 * time.Minute},
		{name: "copy from the future", fresh: 30 * time.Minute, at: -time.Minute},
		{name: "damaged copy", fresh: 30 * time.Minute, at: time.Minute, damage: true},
		{name: "new URL", fresh: 30 * time.Minute, at: time.Minute, otherURL: true},
		{name: "zero", at: time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := "a.example\nb.example\n"
			var boom error
			clock := base
			f, out := staleDir(t, &body, &boom, func() time.Time { return clock })
			if _, _, n, err := f.Run(); err != nil || n != 2 {
				t.Fatalf("first run: %d domains, %v", n, err)
			}
			copyPath := filepath.Join(out, "feeds", "d.list")
			if c.damage {
				if err := os.WriteFile(copyPath, []byte("a.example\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if c.otherURL {
				spec := `{"user_agent":"pf-test","timeout_sec":2,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://feed.test/new"}]}`
				if err := os.WriteFile(filepath.Join(f.PolicyDir, "sources.json"), []byte(spec), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chtimes(copyPath, base, base); err != nil {
				t.Fatal(err)
			}
			gets := 0
			get := f.Get
			f.Get = func(u, ua string, d time.Duration) (string, error) {
				gets++
				return get(u, ua, d)
			}
			f.FreshFor = c.fresh
			clock = base.Add(c.at)
			body = "c.example\n"
			report, _, n, err := f.Run()
			if err != nil {
				t.Fatal(err, report)
			}
			line := strings.Join(report, "\n")
			list := testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains"))
			if c.reuse {
				if gets != 0 || n != 2 || list != "a.example\nb.example\n" {
					t.Fatalf("%d downloads, %d domains %q, want the copy and no download; report %q", gets, n, list, line)
				}
				if !strings.Contains(line, "OK d: 2 domains (last good 10m ago: younger than 30m0s, not downloaded again)") {
					t.Fatalf("report %q", line)
				}
				if st, err := os.Stat(copyPath); err != nil || !st.ModTime().Equal(base) {
					t.Fatalf("the reuse wrote the copy again: %v %v", st.ModTime(), err)
				}
				return
			}
			if gets != 1 || n != 1 || list != "c.example\n" {
				t.Fatalf("%d downloads, %d domains %q, want one download of the new list; report %q", gets, n, list, line)
			}
			if strings.Contains(line, "not downloaded again") {
				t.Fatalf("report %q", line)
			}
		})
	}
}
