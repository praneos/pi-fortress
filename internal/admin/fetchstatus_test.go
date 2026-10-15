package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statusCfg(t *testing.T, report string, age time.Duration) *Config {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	c := &Config{PolicyDir: dir, Now: func() time.Time { return now }}
	if report == "" {
		return c
	}
	gen := filepath.Join(dir, "generated")
	if err := os.MkdirAll(gen, 0755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(gen, "fetch.report")
	if err := os.WriteFile(p, []byte(report), 0644); err != nil {
		t.Fatal(err)
	}
	when := now.Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return c
}

// A report full of OK lines reads the same whether the code wrote it an
// hour ago or in March. The mtime is the half that says which.
func TestFetchStatusDatesTheReport(t *testing.T) {
	c := statusCfg(t, "OK d: 12 domains\nOK s: 4 ips\n", 3*time.Hour)
	st := c.FetchStatus()
	if !st.Ran || st.Age != 3*time.Hour || st.Fail != 0 || st.Stale != 0 {
		t.Fatalf("%+v", st)
	}
	if w := st.Warning(); w != "" {
		t.Fatalf("a fresh clean fetch warns: %q", w)
	}
	if len(st.Lines) != 2 {
		t.Fatalf("lines %v", st.Lines)
	}
}

func TestFetchStatusWarnings(t *testing.T) {
	cases := []struct {
		name   string
		report string
		age    time.Duration
		want   string
	}{
		{"never fetched", "", 0, "never fetched"},
		{"stale copy served", "STALE d: 9 domains (last good 2d1h ago: HTTP 503)\n", time.Hour, "1 serving the last good copy"},
		{"outright failure", "FAIL d: dial: no route to host\n", time.Hour, "1 failed with nothing to fall back on"},
		{"both", "FAIL d: x\nSTALE s: 3 ips (last good 1h0m ago: y)\n", time.Hour, "1 failed, 1 serving the last good copy"},
		// Three missed daily runs in a row is a dead timer, not a feed that
		// answered badly. The two need different sentences.
		{"timer not running", "OK d: 12 domains\n", 5 * 24 * time.Hour, "the refresh timer is not running"},
		{"clean and recent", "OK d: 12 domains\n", 2 * time.Hour, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := statusCfg(t, tc.report, tc.age).FetchStatus().Warning()
			if tc.want == "" {
				if got != "" {
					t.Fatalf("warned %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("warning %q does not say %q", got, tc.want)
			}
		})
	}
}

// A run just below the threshold must not warn. If it does, the banner is
// on permanently, and nobody reads it.
func TestFetchStatusThreshold(t *testing.T) {
	if w := statusCfg(t, "OK d: 1 domains\n", StaleAfter-time.Minute).FetchStatus().Warning(); w != "" {
		t.Fatalf("warned inside the window: %q", w)
	}
	if w := statusCfg(t, "OK d: 1 domains\n", StaleAfter+time.Minute).FetchStatus().Warning(); w == "" {
		t.Fatal("did not warn past the window")
	}
}

// FetchReport is what the Feeds screen used before the status existed.
func TestFetchReportStillReturnsTheLines(t *testing.T) {
	c := statusCfg(t, "OK d: 1 domains\n\nFAIL s: x\n", time.Hour)
	got := c.FetchReport()
	if len(got) != 2 || got[0] != "OK d: 1 domains" || got[1] != "FAIL s: x" {
		t.Fatalf("%v", got)
	}
}
