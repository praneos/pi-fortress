package fetch

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// shrinkSetup runs one fetch of a feed "a" with 1000 names. The test
// changes the answer through the returned pointer.
func shrinkSetup(t *testing.T) (*Fetcher, *string, string) {
	t.Helper()
	dir := t.TempDir()
	spec := `{"feeds": [{"id": "a", "kind": "domains", "format": "plain", "url": "https://a.test/"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	var full strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&full, "n%d.example\n", i)
	}
	body := full.String()
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) { return body, nil }}
	if report, _, n, err := f.Run(); err != nil || n != 1000 {
		t.Fatalf("first run: %d domains, %v\n%s", n, err, strings.Join(report, "\n"))
	}
	return f, &body, out
}

func shrinkFeed() Feed {
	return Feed{ID: "a", Kind: "domains", Format: "plain", URL: "https://a.test/"}
}

// A feed that had 1000 names answers with one. The run keeps the 1000
// names, keeps the last good copy, and reports the feed as stale.
func TestShrunkenAnswerKeepsTheLastGoodCopy(t *testing.T) {
	f, body, out := shrinkSetup(t)
	*body = "x.example\n"
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(report, "\n")
	if n != 1000 {
		t.Errorf("a 1-line answer replaced 1000 names: %d domains published", n)
	}
	if !strings.Contains(joined, "STALE a:") {
		t.Errorf("the run reports the shrunken feed as fresh:\n%s", joined)
	}
	if items, _, ok := readCache(out, shrinkFeed()); !ok || len(items) != 1000 {
		t.Errorf("the last good copy was overwritten: %d items, ok %v", len(items), ok)
	}
}

// A feed can really shrink. Once the last good copy is older than three
// days, the run accepts the smaller answer.
func TestShrunkenAnswerIsAcceptedOnceTheCopyIsOld(t *testing.T) {
	f, body, _ := shrinkSetup(t)
	*body = "x.example\n"
	f.Now = func() time.Time { return time.Now().Add(73 * time.Hour) }
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("after 73h the shrunken answer is still refused: %d domains\n%s", n, strings.Join(report, "\n"))
	}
}

// The check applies only to a feed that had at least 100 entries. A small
// feed can lose half of them on a normal day.
func TestSmallFeedMayShrink(t *testing.T) {
	dir := t.TempDir()
	spec := `{"feeds": [{"id": "a", "kind": "domains", "format": "plain", "url": "https://a.test/"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	body := "a.example\nb.example\nc.example\nd.example\n"
	f := &Fetcher{PolicyDir: dir, OutDir: filepath.Join(dir, "generated"), Get: func(string, string, time.Duration) (string, error) { return body, nil }}
	if _, _, _, err := f.Run(); err != nil {
		t.Fatal(err)
	}
	body = "a.example\n"
	if report, _, n, err := f.Run(); err != nil || n != 1 {
		t.Fatalf("a 4-name feed that drops to 1 was refused: %d, %v\n%s", n, err, strings.Join(report, "\n"))
	}
}

// The cap is shared between the feeds. When the first feed in
// sources.json answers with as many names as the cap, the names of the
// second feed still reach the list.
func TestCapIsSharedBetweenFeeds(t *testing.T) {
	dir := t.TempDir()
	spec := `{"max_domains": 3, "feeds": [
    {"id": "a", "kind": "domains", "format": "plain", "url": "https://a.test/"},
    {"id": "b", "kind": "domains", "format": "plain", "url": "https://b.test/"}
  ]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(url, _ string, _ time.Duration) (string, error) {
		if url == "https://a.test/" {
			return "a1.example\na2.example\na3.example\n", nil
		}
		return "b1.example\n", nil
	}}
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "blacklist.domains"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(raw))
	if !slices.Contains(got, "b1.example") {
		t.Errorf("feed a took all of the cap from feed b: %v\n%s", got, strings.Join(report, "\n"))
	}
	if n != 3 {
		t.Errorf("%d domains, want the cap of 3", n)
	}
	if !strings.Contains(strings.Join(report, "\n"), "TRUNCATED domains to 3 (had 4)") {
		t.Errorf("no TRUNCATED line:\n%s", strings.Join(report, "\n"))
	}
}

// A feed with more entries than the cap is read only to one entry past the
// cap. The list and the report are as before, and the last good copy holds
// only the entries that were read.
func TestFeedParseStopsAtTheCap(t *testing.T) {
	dir := t.TempDir()
	spec := `{"max_domains": 5, "feeds": [{"id": "a", "kind": "domains", "format": "plain", "url": "https://a.test/"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&body, "n%d.example\nn%d.example\n", i, i)
	}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) { return body.String(), nil }}
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(report, "\n")
	if n != 5 {
		t.Errorf("%d domains, want the cap of 5\n%s", n, joined)
	}
	if !strings.Contains(joined, "OK a: 6 domains (more than the cap of 5; the rest not read)") || !strings.Contains(joined, "TRUNCATED domains to 5 (had more than 6)") {
		t.Errorf("the report does not tell that the feed was cut:\n%s", joined)
	}
	if raw, err := os.ReadFile(filepath.Join(out, "blacklist.domains")); err != nil || string(raw) != "n0.example\nn1.example\nn2.example\nn3.example\nn4.example\n" {
		t.Errorf("list %q, %v", raw, err)
	}
	if items, _, ok := readCache(out, Feed{ID: "a", Kind: "domains", Format: "plain", URL: "https://a.test/"}); !ok || len(items) != 6 {
		t.Errorf("last good copy: %d items, ok %v; want the 6 that were read", len(items), ok)
	}
}

// When never_block removes entries of a feed that was cut, the list can fit
// under the cap. The report still tells that entries were not read.
func TestCutFeedIsReportedWhenNeverBlockMakesItFit(t *testing.T) {
	dir := t.TempDir()
	spec := `{"max_domains": 2, "feeds": [{"id": "a", "kind": "domains", "format": "plain", "url": "https://a.test/"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "never_block.domains"), []byte("keep.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	body := "keep.example\na.example\nb.example\nc.example\n"
	f := &Fetcher{PolicyDir: dir, OutDir: filepath.Join(dir, "generated"), Get: func(string, string, time.Duration) (string, error) { return body, nil }}
	report, _, n, err := f.Run()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(report, "\n")
	if n != 2 || !strings.Contains(joined, "TRUNCATED domains to 2 (had more than 2)") {
		t.Errorf("%d domains; the report does not tell that the feed was cut:\n%s", n, joined)
	}
}
