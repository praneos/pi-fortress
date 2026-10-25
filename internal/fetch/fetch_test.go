package fetch

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"pi-fortress/internal/policycompile"
	"pi-fortress/internal/testsupport"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// lab treats 127.0.0.1 as public, so httptest servers pass the dial
// check. Each other address still goes through the real check.
func lab(ts *httptest.Server) *client {
	return &client{
		public: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") || publicAddr(a) },
		tls:    ts.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

func TestParsePlainAndSpamhaus(t *testing.T) {
	got := ParsePlain("# c\nexample.com\n*.evil.test extra\nfoo.local\n", "domains")
	if strings.Join(got, ",") != "example.com,evil.test" {
		t.Fatal(got)
	}
	ips := ParsePlain("1.2.3.4\n10.1.1.1\n", "ips")
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatal(ips)
	}
	sh := ParseSpamhaus("; comment\n1.2.3.0/24 ; DROP\n")
	if len(sh) != 1 || sh[0] != "1.2.3.0/24" {
		t.Fatal(sh)
	}
}

func TestFetchMockFeeds(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "pf-test" {
			t.Errorf("ua %s", r.UserAgent())
		}
		switch r.URL.Path {
		case "/domains":
			fmt.Fprint(w, "bad.example\nkeep.test\ngoogle.com\n")
		case "/ips":
			fmt.Fprint(w, "; spamhaus\n9.9.9.9\n10.0.0.0/8\n")
		case "/fail":
			http.Error(w, "nope", 500)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "never_block.domains"), []byte("google.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "never_block.ips"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	spec := fmt.Sprintf(`{
  "user_agent": "pf-test",
  "timeout_sec": 2,
  "max_ips": 20000,
  "max_domains": 50000,
  "feeds": [
    {"id": "d", "kind": "domains", "format": "plain", "url": %q},
    {"id": "s", "kind": "ips", "format": "spamhaus", "url": %q},
    {"id": "x", "kind": "ips", "format": "plain", "url": %q}
  ]
}`, ts.URL+"/domains", ts.URL+"/ips", ts.URL+"/fail")
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	_ = os.MkdirAll(out, 0755)
	_ = os.WriteFile(filepath.Join(out, "blacklist.domains"), []byte("stale.example\n"), 0644)
	f := &Fetcher{PolicyDir: dir, OutDir: out, web: lab(ts)}
	report, nIPs, nDoms, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	if strings.Contains(testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains")), "stale.example") {
		t.Fatal("partial failure did not replace the previous list")
	}
	if !strings.Contains(testsupport.ReadFile(t, filepath.Join(out, "fetch.report")), "FAIL x:") {
		t.Fatal("fetch.report missing the failure")
	}
	if left, _ := filepath.Glob(filepath.Join(out, ".fetch-*")); len(left) != 0 {
		t.Fatal("temp dir left behind", left)
	}
	joined := strings.Join(report, "\n")
	if !strings.Contains(joined, "OK d:") || !strings.Contains(joined, "OK s:") || !strings.Contains(joined, "FAIL x:") {
		t.Fatal(report)
	}
	if nDoms != 2 {
		t.Fatalf("domains %d", nDoms)
	}
	if nIPs != 1 {
		t.Fatalf("ips %d", nIPs)
	}
	doms, _ := os.ReadFile(filepath.Join(out, "blacklist.domains"))
	if strings.Contains(string(doms), "google.com") {
		t.Fatal(string(doms))
	}
	if !strings.Contains(string(doms), "keep.test") {
		t.Fatal(string(doms))
	}
	sample, _ := os.ReadFile(filepath.Join(out, "sample.domain"))
	if strings.TrimSpace(string(sample)) != "bad.example" {
		t.Fatal(string(sample))
	}
	ips, _ := os.ReadFile(filepath.Join(out, "blacklist.ips"))
	if strings.Contains(string(ips), "10.0.0.0") {
		t.Fatal(string(ips))
	}
	if !strings.Contains(string(ips), "9.9.9.9") {
		t.Fatal(string(ips))
	}
}

func TestAllFeedsFailKeepsGenerated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(`{"feeds":[{"id":"x","kind":"ips","format":"plain","url":"https://127.0.0.1:1/nope"},{"id":"y","kind":"domains","format":"plain","url":"https://127.0.0.1:1/nope"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	_ = os.MkdirAll(out, 0755)
	prev := map[string]string{"blacklist.ips": "9.9.9.9\n", "blacklist.domains": "old.example\n", "house.domains": "ads.example\n", "sample.domain": "old.example\n", "fetch.report": "OK x: 1 ips\n"}
	for name, text := range prev {
		_ = os.WriteFile(filepath.Join(out, name), []byte(text), 0644)
	}
	f := Defaults(dir, out)
	f.Get = func(url, ua string, timeout time.Duration) (string, error) {
		return "", fmt.Errorf("down")
	}
	report, _, _, err := f.Run()
	if err == nil || !strings.Contains(strings.Join(report, "\n"), "FAIL y: down") {
		t.Fatal("want fail", report)
	}
	for name, text := range prev {
		got := testsupport.ReadFile(t, filepath.Join(out, name))
		if name == "fetch.report" {
			if !strings.Contains(got, "FAIL y: down") {
				t.Fatalf("report not rewritten on total failure: %q", got)
			}
			continue
		}
		if got != text {
			t.Fatalf("%s changed on total failure: %q", name, got)
		}
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != len(prev) {
		t.Fatal("stray files in generated after total failure", entries)
	}
}

func TestTruncationReported(t *testing.T) {
	dir := t.TempDir()
	spec := `{"max_ips": 1, "max_domains": 2, "feeds": [
    {"id": "d", "kind": "domains", "format": "plain", "url": "https://d.test/"},
    {"id": "i", "kind": "ips", "format": "plain", "url": "https://i.test/"},
    {"id": "h", "kind": "domains", "format": "plain", "segment": "house", "url": "https://h.test/"}
  ]}`
	_ = os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644)
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(url, _ string, _ time.Duration) (string, error) {
		switch url {
		case "https://d.test/":
			return "a.example\nb.example\nc.example\n", nil
		case "https://i.test/":
			return "1.1.1.1\n9.9.9.9\n", nil
		}
		return "x.example\n", nil
	}}
	report, nIPs, nDoms, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	joined := strings.Join(report, "\n")
	for _, want := range []string{"TRUNCATED domains to 2 (had 3)", "TRUNCATED ips to 1 (had 2)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "TRUNCATED house") || nIPs != 1 || nDoms != 2 {
		t.Fatal(joined, nIPs, nDoms)
	}
	if rep := testsupport.ReadFile(t, filepath.Join(out, "fetch.report")); !strings.Contains(rep, "TRUNCATED domains to 2 (had 3)") {
		t.Fatal(rep)
	}
	if got := testsupport.ReadFile(t, filepath.Join(out, "blacklist.domains")); got != "a.example\nb.example\n" {
		t.Fatalf("%q", got)
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": false, "10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"192.0.2.1": false, "100.64.0.1": false, "0.0.0.0": false, "198.18.0.1": false, "224.0.0.1": false,
		"::1": false, "fe80::1": false, "fc00::1": false, "::ffff:127.0.0.1": false, "::ffff:10.0.0.1": false,
		"1.1.1.1": true, "8.0.0.1": true, "9.9.9.9": true, "2606:4700::1111": true, "::ffff:9.9.9.9": true,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v want %v", addr, got, want)
		}
	}
}

// A feed host can publish a ULA or a private address beside its public
// ones. One such address failed the whole feed on each run. Now dial skips
// it, and dials only an address that passed the check. The host fails
// only when no address passes.
func TestDialSkipsAnAddressThatIsNotPublic(t *testing.T) {
	var answer []netip.Addr
	var dialled []string
	c := &client{
		public: publicAddr,
		lookup: func(context.Context, string) ([]netip.Addr, error) { return answer, nil },
		dialTo: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			if addr != "9.9.9.9:443" {
				return nil, fmt.Errorf("%s: refused", addr)
			}
			conn, peer := net.Pipe()
			peer.Close()
			return conn, nil
		},
	}
	addrs := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}

	answer = addrs("fd00::1", "::ffff:10.0.0.1", "1.1.1.1", "192.168.1.1", "9.9.9.9")
	conn, err := c.dial(context.Background(), "tcp", "feed.test:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if want := "1.1.1.1:443,9.9.9.9:443"; strings.Join(dialled, ",") != want {
		t.Fatalf("dialled %q, want %q", dialled, want)
	}

	dialled = nil
	answer = addrs("fd00::1", "10.0.0.1")
	if _, err := c.dial(context.Background(), "tcp", "feed.test:443"); err == nil || err.Error() != "feed.test resolves to fd00::1: not public" {
		t.Fatalf("dial: %v", err)
	}
	if len(dialled) != 0 {
		t.Fatalf("dialled %q", dialled)
	}
}

func TestRedirects(t *testing.T) {
	var hits atomic.Int32
	var target *httptest.Server
	target = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/feed":
			fmt.Fprint(w, "bad.example\n")
		case "/to-feed":
			http.Redirect(w, r, target.URL+"/feed", http.StatusFound)
		case "/to-loop":
			http.Redirect(w, r, "https://127.0.0.2:1/feed", http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, "http://127.0.0.1:1/feed", http.StatusFound)
		case "/hop":
			n := r.URL.Query().Get("n")
			http.Redirect(w, r, target.URL+"/hop?n="+n+"x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(target.Close)
	c := lab(target)
	pg, err := c.get(target.URL+"/to-feed", "t", time.Second)
	if err != nil || pg.body != "bad.example\n" || pg.final != target.URL+"/feed" {
		t.Fatalf("%+v %v", pg, err)
	}
	for path, want := range map[string]string{"/to-loop": "not public", "/to-http": "only https", "/hop?n=": "more than 3 redirects"} {
		if _, err := c.get(target.URL+path, "t", time.Second); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v, want %q", path, err, want)
		}
	}
	before := hits.Load()
	if _, err := c.get("http://127.0.0.1:1/feed", "t", time.Second); err == nil || !strings.Contains(err.Error(), "only https") {
		t.Fatal(err)
	}
	strict := &client{public: publicAddr, tls: c.tls}
	if _, err := strict.get(target.URL+"/feed", "t", time.Second); err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatal(err)
	}
	if hits.Load() != before {
		t.Fatal("a refused initial URL still reached the server")
	}

	dir := t.TempDir()
	spec := fmt.Sprintf(`{"feeds": [{"id": "d", "kind": "domains", "format": "plain", "url": %q}]}`, target.URL+"/to-feed")
	_ = os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644)
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, web: c}
	report, _, nDoms, err := f.Run()
	if err != nil || nDoms != 1 {
		t.Fatal(err, report)
	}
	if rep := testsupport.ReadFile(t, filepath.Join(out, "fetch.report")); !strings.Contains(rep, "REDIRECT d: "+target.URL+"/feed") {
		t.Fatal(rep)
	}
}

func TestHouseSegmentFeedsAndHostsFormat(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/shared":
			fmt.Fprint(w, "untrusted.example\n")
		case "/ads":
			fmt.Fprint(w, "# HaGeZi\n*.ads.example\ntracker.example\nads.google.com\nfamily.example\n")
		case "/hosts":
			fmt.Fprint(w, "# hosts\n0.0.0.0 0.0.0.0\n0.0.0.0 telemetry.example\n127.0.0.1 localhost\n::1 ip6-localhost\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "never_block.domains"), []byte("google.com\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "never_block.ips"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(dir, "house_never_block.domains"), []byte("family.example\n"), 0644)
	spec := fmt.Sprintf(`{"feeds": [
    {"id": "shared", "kind": "domains", "format": "plain", "url": %q},
    {"id": "ads", "kind": "domains", "format": "plain", "segment": "house", "url": %q},
    {"id": "hosts", "kind": "domains", "format": "hosts", "segment": "house", "url": %q},
    {"id": "badkind", "kind": "ips", "format": "plain", "segment": "house", "url": %q}
  ]}`, ts.URL+"/shared", ts.URL+"/ads", ts.URL+"/hosts", ts.URL+"/shared")
	_ = os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644)
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, web: lab(ts)}
	report, _, nDoms, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	joined := strings.Join(report, "\n")
	// ads.google.com survives: the shared never_block (google.com) is for
	// the agent. family.example goes: the house never_block is for the
	// house.
	if !strings.Contains(joined, "OK ads: 3 house domains") || !strings.Contains(joined, "OK hosts: 1 house domains") || !strings.Contains(joined, "SKIP badkind") {
		t.Fatal(joined)
	}
	if nDoms != 1 {
		t.Fatalf("shared domains %d", nDoms)
	}
	shared, _ := os.ReadFile(filepath.Join(out, "blacklist.domains"))
	house, _ := os.ReadFile(filepath.Join(out, "house.domains"))
	if strings.Contains(string(shared), "ads.example") || strings.Contains(string(shared), "telemetry.example") {
		t.Fatalf("house feed leaked into the shared list:\n%s", shared)
	}
	for _, want := range []string{"ads.example\n", "tracker.example\n", "telemetry.example\n", "ads.google.com\n"} {
		if !strings.Contains(string(house), want) {
			t.Fatalf("house list missing %q:\n%s", want, house)
		}
	}
	if strings.Contains(string(house), "family.example") || strings.Contains(string(house), "localhost") || strings.Contains(string(house), "0.0.0.0") {
		t.Fatalf("house list carries house_never_block or hosts noise:\n%s", house)
	}
}

func TestDisabledFeedSkipped(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "bad.example\n")
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	spec := fmt.Sprintf(`{"feeds": [
    {"id": "on", "kind": "domains", "format": "plain", "url": %q},
    {"id": "off", "kind": "domains", "format": "plain", "enabled": false, "url": %q},
    {"id": "explicit", "kind": "domains", "format": "plain", "enabled": true, "url": %q}
  ]}`, ts.URL, ts.URL, ts.URL)
	_ = os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644)
	f := &Fetcher{PolicyDir: dir, OutDir: filepath.Join(dir, "generated"), web: lab(ts)}
	report, _, nDoms, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	joined := strings.Join(report, "\n")
	if !strings.Contains(joined, "SKIP off: disabled") || !strings.Contains(joined, "OK on: 1") || !strings.Contains(joined, "OK explicit: 1") || nDoms != 1 {
		t.Fatal(joined, nDoms)
	}
}

// io.LimitReader stops at the cap and says nothing. So the
// first 8 MiB of an oversized feed used to look like a whole feed.
func TestOversizedFeedIsRefused(t *testing.T) {
	line := "a-very-long-name-to-fill-the-body.example\n"
	big := strings.Repeat(line, (maxBody/len(line))+2)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			fmt.Fprint(w, "ok.example\n")
			return
		}
		fmt.Fprint(w, big)
	}))
	t.Cleanup(ts.Close)
	c := lab(ts)
	if _, err := c.get(ts.URL+"/big", "t", 30*time.Second); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an over-cap feed was accepted: %v", err)
	}
	if pg, err := c.get(ts.URL+"/small", "t", 30*time.Second); err != nil || pg.body != "ok.example\n" {
		t.Fatalf("an ordinary feed was refused: %q %v", pg.body, err)
	}
}

// The copy is keyed on the feed id alone. So a change to the URL or
// kind of a feed, and then a failure, served the tokens of a different
// source under the new interpretation.
func TestCacheIsBoundToTheFeedIdentity(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "generated")
	body := "a.example\nb.example\n"
	fail := false
	write := func(url string) {
		spec := fmt.Sprintf(`{"feeds":[{"id":"d","kind":"domains","format":"plain","url":%q}]}`, url)
		if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
			t.Fatal(err)
		}
	}
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) {
		if fail {
			return "", fmt.Errorf("HTTP 503")
		}
		return body, nil
	}}
	write("https://one.test/d")
	if _, _, n, err := f.Run(); err != nil || n != 2 {
		t.Fatalf("seed run: %d %v", n, err)
	}
	write("https://two.test/d")
	fail = true
	report, _, _, err := f.Run()
	if err == nil {
		t.Fatalf("a copy of a different source was served for the new URL: %v", report)
	}
	if !strings.Contains(strings.Join(report, "\n"), "FAIL d:") {
		t.Fatal(report)
	}
}

// A house-only success plus one uncached shared failure was
// called "all feeds failed", so the house list was discarded.
func TestHouseOnlySuccessStillPublishes(t *testing.T) {
	dir := t.TempDir()
	spec := `{"feeds":[
	  {"id":"ads","kind":"domains","format":"plain","segment":"house","url":"https://ads.test/"},
	  {"id":"shared","kind":"domains","format":"plain","url":"https://shared.test/"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(url, _ string, _ time.Duration) (string, error) {
		if url == "https://ads.test/" {
			return "tracker.example\n", nil
		}
		return "", fmt.Errorf("down")
	}}
	report, _, _, err := f.Run()
	if err != nil {
		t.Fatalf("a house-only success was discarded: %v %v", err, report)
	}
	if got := testsupport.ReadFile(t, filepath.Join(out, "house.domains")); got != "tracker.example\n" {
		t.Fatalf("house list %q", got)
	}
}

// A run that cannot save its last-good copy still reported OK. So
// the fallback that the next outage relies on was never there.
func TestCacheWriteFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	spec := `{"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generated")
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	// An ordinary file where the copies go: each write into it fails.
	if err := os.WriteFile(cacheDir(out), []byte("not a directory\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) {
		return "a.example\n", nil
	}}
	report, _, _, err := f.Run()
	if err != nil {
		t.Fatal(err, report)
	}
	if !strings.Contains(strings.Join(report, "\n"), "WARN d:") {
		t.Fatalf("a failed copy was not reported: %v", report)
	}
}

// sources.json is type-checked, not schema-checked. So a negative
// cap panicked at items[:max], and a misspelled selector or format
// silently changed what the feed means.
func TestSourcesSchemaIsRefused(t *testing.T) {
	cases := map[string]string{
		"negative max_ips":     `{"max_ips":-1,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
		"negative max_domains": `{"max_domains":-1,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
		"negative timeout":     `{"timeout_sec":-1,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
		"duplicate id":         `{"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://a.test/"},{"id":"d","kind":"domains","format":"plain","url":"https://b.test/"}]}`,
		"id names a path":      `{"feeds":[{"id":"../net.env","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
		"unknown kind":         `{"feeds":[{"id":"d","kind":"names","format":"plain","url":"https://d.test/"}]}`,
		"unknown format":       `{"feeds":[{"id":"d","kind":"domains","format":"plane","url":"https://d.test/"}]}`,
		"unknown segment":      `{"feeds":[{"id":"d","kind":"domains","format":"plain","segment":"hoose","url":"https://d.test/"}]}`,
		"spamhaus domains":     `{"feeds":[{"id":"d","kind":"domains","format":"spamhaus","url":"https://d.test/"}]}`,
		"hosts ips":            `{"feeds":[{"id":"d","kind":"ips","format":"hosts","url":"https://d.test/"}]}`,
		"no url":               `{"feeds":[{"id":"d","kind":"domains","format":"plain","url":""}]}`,
		"min_ip_prefix 4":      `{"min_ip_prefix":4,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
		"min_ip_prefix 33":     `{"min_ip_prefix":33,"feeds":[{"id":"d","kind":"domains","format":"plain","url":"https://d.test/"}]}`,
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "generated")
			f := &Fetcher{PolicyDir: dir, OutDir: out, Get: func(string, string, time.Duration) (string, error) {
				return "a.example\n", nil
			}}
			if _, _, _, err := f.Run(); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("a refused sources.json still wrote generated files")
			}
		})
	}
}

// A hosts file that a sources.json gives no format reads as plain. The
// first field of each line is then the address, and the feed blocked
// 0.0.0.0 in place of its names.
func TestParsePlainKeepsTheNameAfterAnAddress(t *testing.T) {
	got := ParsePlain("0.0.0.0 ads.example\n127.0.0.1 track.example extra.example\n:: six.example\n0.0.0.0\n0.0.0.0 0.0.0.0\n1.2.3.4 mapped.example\n1.2.3.4\nplain.example\n", "domains")
	if want := "ads.example,track.example,six.example,plain.example"; strings.Join(got, ",") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, ","), want)
	}
	if ips := ParsePlain("0.0.0.0 ads.example\n", "ips"); len(ips) != 0 {
		t.Fatalf("ips feed took %q", ips)
	}
}

// The code looked only at f[1]. So each alias after the first name
// stayed unblocked, and a numeric first alias dropped the full record.
func TestParseHostsKeepsEveryAlias(t *testing.T) {
	got := ParseHosts("0.0.0.0 one.example two.example # trailing\n0.0.0.0 0.0.0.0 three.example\n127.0.0.1 localhost\n")
	want := "one.example,two.example,three.example"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, ","), want)
	}
}

// A wildcard or a trailing dot does not make an address into a name.
func TestParseHostsDropsAddressWithWildcardOrDot(t *testing.T) {
	got := ParseHosts("0.0.0.0 *.0.0.0.0 0.0.0.0. *.1.2.3.4. four.example\n")
	if want := "four.example"; strings.Join(got, ",") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, ","), want)
	}
}

// The partial run (one feed answers, one is dead) is the case that the
// audit entry must describe, and Run reports it as success. The count is
// the only place for the number outside fetch.report itself.
func TestCountWarningsReadsTheReport(t *testing.T) {
	report := []string{
		"OK d: 9 domains",
		"FAIL x: https://127.0.0.1:1/x: only https",
		"STALE s: 3 ips (last good 2d1h ago: HTTP 503)",
		"TRUNCATED domains to 2 (had 3)",
		"REDIRECT d: http://example.test/feed",
		"sample ip",
		"",
	}
	fails, stale, truncated := CountWarnings(report)
	if fails != 1 || stale != 1 || truncated != 1 {
		t.Fatalf("fails %d, stale %d, truncated %d", fails, stale, truncated)
	}
	if fails, stale, truncated := CountWarnings([]string{"OK d: 9 domains"}); fails != 0 || stale != 0 || truncated != 0 {
		t.Fatalf("clean report counted: %d, %d, %d", fails, stale, truncated)
	}
}

// A house feed with role vpn goes in its own list, never in the house
// sinkhole. So HOUSE_BLOCK_VPN=off can drop it and keep the ad feeds. The
// role is refused anywhere except a house domains feed.
func TestHouseVPNRoleFeedIsItsOwnList(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ads":
			fmt.Fprint(w, "tracker.example\n")
		case "/vpn":
			fmt.Fprint(w, "vpn.example\nfamily-vpn.example\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "house_never_block.domains"), []byte("family-vpn.example\n"), 0644)
	write := func(spec string) {
		_ = os.WriteFile(filepath.Join(dir, "sources.json"), []byte(spec), 0644)
	}
	write(fmt.Sprintf(`{"feeds": [
    {"id": "ads", "kind": "domains", "format": "plain", "segment": "house", "url": %q},
    {"id": "vpn", "kind": "domains", "format": "plain", "segment": "house", "role": "vpn", "url": %q}
  ]}`, ts.URL+"/ads", ts.URL+"/vpn"))
	out := filepath.Join(dir, "generated")
	f := &Fetcher{PolicyDir: dir, OutDir: out, web: lab(ts)}
	if report, _, _, err := f.Run(); err != nil {
		t.Fatal(err, report)
	}
	house, _ := os.ReadFile(filepath.Join(out, "house.domains"))
	vpn, err := os.ReadFile(filepath.Join(dir, policycompile.HouseVPNFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(house) != "tracker.example\n" {
		t.Fatalf("house sinkhole:\n%s", house)
	}
	if string(vpn) != "vpn.example\n" {
		t.Fatalf("vpn list (house_never_block applies too):\n%s", vpn)
	}
	fm, _ := os.ReadFile(filepath.Join(out, FeedsMap))
	if !strings.Contains(string(fm), "vpn.example\tvpn\n") {
		t.Fatalf("feeds.map does not label the vpn list:\n%s", fm)
	}
	for _, bad := range []string{
		`{"id": "x", "kind": "domains", "format": "plain", "role": "vpn", "url": "https://a.example/x"}`,
		`{"id": "x", "kind": "domains", "format": "plain", "segment": "house", "role": "ads", "url": "https://a.example/x"}`,
	} {
		write(`{"feeds": [` + bad + `]}`)
		if _, _, _, err := f.Run(); err == nil || !strings.Contains(err.Error(), "the only role is vpn") {
			t.Fatalf("role accepted in %s: %v", bad, err)
		}
	}
}
