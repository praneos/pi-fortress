package www

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res.StatusCode, string(body)
}

func TestClaimFlow(t *testing.T) {
	s, ts := testServer(t)
	claims := ClaimsDir(s.Dir)
	if err := os.MkdirAll(claims, 0770); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(claims, "A1B2C3D4E5F67890", []string{"CLAUDE_OAT", "CLAUDE_ORT"})
	if err != nil || len(c.Code) != 8 || strings.ContainsAny(c.Code, "01OI") || time.Until(c.Expires) > ClaimTTL {
		t.Fatal(c, err)
	}
	if fi, _ := os.Stat(filepath.Join(claims, c.Code+".json")); fi.Mode().Perm() != 0640 {
		t.Fatal(fi.Mode())
	}
	code, body := get(t, ts.URL+"/claim/"+strings.ToLower(c.Code))
	if code != 200 || !strings.Contains(body, "curl -fsS \"http://$PI/setup.sh\" -o \"$S\"") || strings.Contains(body, "| sudo bash") || !strings.Contains(body, "pf_a1b2c3d4e5f67890_CLAUDE_OAT") || !strings.Contains(body, ".credentials.json") || !strings.Contains(body, "export CLAUDE_ORT='pf_a1b2c3d4e5f67890_CLAUDE_ORT'") || strings.Contains(body, "sk-ant") {
		t.Fatalf("%d\n%s", code, body)
	}
	_, notFound := get(t, ts.URL+"/claim/ZZZZZZZZ")
	if code2, again := get(t, ts.URL+"/claim/"+c.Code); code2 != 404 || again != notFound {
		t.Fatalf("second redeem: %d %q vs %q", code2, again, notFound)
	}
	// The redeem made a marker and left the claim of root as it was.
	if _, err := os.Stat(filepath.Join(RedeemedDir(claims), c.Code+".redeemed")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(claims, c.Code+".json")); err != nil {
		t.Fatal(err)
	}
	old, _ := IssueClaim(claims, "a1b2c3d4e5f67890", []string{"GITHUB_TOKEN"})
	raw, _ := os.ReadFile(filepath.Join(claims, old.Code+".json"))
	raw = []byte(strings.Replace(string(raw), `"expires":"`+old.Expires.Format(time.RFC3339Nano), `"expires":"2000-01-01T00:00:00Z`, 1))
	_ = os.WriteFile(filepath.Join(claims, old.Code+".json"), raw, 0640)
	if code, _ := get(t, ts.URL+"/claim/"+old.Code); code != 404 {
		t.Fatal(code)
	}
	if _, body := get(t, ts.URL+"/setup.sh"); !strings.Contains(body, "pi-fortress setup") {
		t.Fatal(body)
	}
	evs := ReadLedger(claims)
	if len(evs) != 2 || evs[0].Ev != "redeemed" || evs[0].Slot != "a1b2c3d4e5f67890" || evs[0].IP == "" || evs[1].Ev != "setup" || evs[1].Path != "/setup.sh" {
		t.Fatalf("%+v", evs)
	}
	if err := AppendEvent(claims, Event{Ev: "issued", Code: "ABCDEF", Slot: "x", UID: 0}); err != nil || len(ReadLedger(claims)) != 3 {
		t.Fatal(err)
	}
}

func TestClaimLimiterAndSweep(t *testing.T) {
	s, ts := testServer(t)
	claims := ClaimsDir(s.Dir)
	_ = os.MkdirAll(claims, 0770)
	last := 0
	for range limitPerMin + 1 {
		last, _ = get(t, ts.URL+"/claim/ABCDEF")
	}
	if last != 429 {
		t.Fatal(last)
	}
	_ = os.MkdirAll(RedeemedDir(claims), 0770)
	// OLD1 is an old claim with its marker. Both go, the claim first. LIVE1
	// is a claim that is not old, with an old marker. The marker stays while
	// the claim is there, so the code stays spent. FRESH1 is not redeemed.
	old, oldMark := filepath.Join(claims, "OLD111.json"), markerPath(claims, "OLD111")
	live, liveMark := filepath.Join(claims, "LIVE11.json"), markerPath(claims, "LIVE11")
	fresh := filepath.Join(claims, "FRESH1.json")
	legacy := filepath.Join(claims, "STALE1.redeemed")
	ago := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{old, oldMark, live, liveMark, fresh, legacy} {
		_ = os.WriteFile(p, []byte("{}"), 0640)
		if p != live && p != fresh {
			_ = os.Chtimes(p, ago, ago)
		}
	}
	Sweep(claims)
	for _, p := range []string{old, oldMark, legacy} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("old file %s kept", p)
		}
	}
	for _, p := range []string{live, liveMark, fresh} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("file %s removed", p)
		}
	}
	if _, err := RedeemClaim(claims, "../etc"); err != ErrNoClaim {
		t.Fatal("bad code accepted")
	}
}

func TestClaimScriptGit(t *testing.T) {
	gh := ClaimScript("10.77.0.1", Claim{Slot: "a1b2c3d4e5f67890", Kinds: []string{"GITHUB_TOKEN"}, GitHosts: []string{"github.com", "bad host'"}, SetupSHA256: strings.Repeat("cd", 32), CASHA256: strings.Repeat("ab", 32)})
	if !strings.Contains(gh, "\nhttps://x-access-token:pf_a1b2c3d4e5f67890_GITHUB_TOKEN@github.com\nPFEOF\n") || !strings.Contains(gh, "credential.helper store") || strings.Contains(gh, "bad host") {
		t.Fatal(gh)
	}
	claude := ClaimScript("10.77.0.1", Claim{Slot: "a1b2c3d4e5f67890", Kinds: []string{"CLAUDE_OAT", "CLAUDE_ORT"}, GitHosts: []string{"github.com"}, SetupSHA256: strings.Repeat("cd", 32), CASHA256: strings.Repeat("ab", 32)})
	if strings.Contains(claude, "git-credentials") {
		t.Fatal(claude)
	}
}

// Run the git half for real: fresh, re-run, beside lines of other hosts,
// under a helper that a different user set, and with no git at all.
func TestClaimGitUnderSh(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	script := "set -e\n" + gitCredentials("a1b2c3d4e5f67890", []string{"api.github.com", "github.com"})
	ours := "https://x-access-token:pf_a1b2c3d4e5f67890_GITHUB_TOKEN@api.github.com\nhttps://x-access-token:pf_a1b2c3d4e5f67890_GITHUB_TOKEN@github.com\n"
	env := func(home, path string) []string {
		return []string{"HOME=" + home, "PATH=" + path, "GIT_CONFIG_NOSYSTEM=1", "XDG_CONFIG_HOME=" + filepath.Join(home, ".config")}
	}
	run := func(home, path string) string {
		t.Helper()
		cmd := exec.Command(sh, "-c", script)
		cmd.Env = env(home, path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	helpers := func(home string) string {
		cmd := exec.Command("git", "config", "--global", "--get-all", "credential.helper")
		cmd.Env = env(home, os.Getenv("PATH"))
		out, _ := cmd.Output()
		return string(out)
	}
	creds := func(home string) string {
		t.Helper()
		p := filepath.Join(home, ".git-credentials")
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("mode %o", fi.Mode().Perm())
		}
		raw, _ := os.ReadFile(p)
		return string(raw)
	}
	path := os.Getenv("PATH")

	fresh := t.TempDir()
	run(fresh, path)
	run(fresh, path)
	if got := creds(fresh); got != ours {
		t.Fatalf("fresh:\n%s", got)
	}
	if got := helpers(fresh); got != "store\n" {
		t.Fatalf("helper %q", got)
	}

	mixed := t.TempDir()
	other := "https://u:p@gitlab.com\nhttps://old:tok@github.com\nhttps://a:b@github.company.com\n"
	if err := os.WriteFile(filepath.Join(mixed, ".git-credentials"), []byte(other), 0644); err != nil {
		t.Fatal(err)
	}
	run(mixed, path)
	if got, want := creds(mixed), "https://u:p@gitlab.com\nhttps://a:b@github.company.com\n"+ours; got != want {
		t.Fatalf("mixed:\n%s", got)
	}

	foreign := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreign, ".gitconfig"), []byte("[credential]\n\thelper = cache\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if out := run(foreign, path); !strings.Contains(out, "git config --global --replace-all credential.helper store") {
		t.Fatal(out)
	}
	if got := helpers(foreign); got != "cache\n" {
		t.Fatalf("foreign helper overridden: %q", got)
	}

	nogit := t.TempDir()
	if out := run(nogit, t.TempDir()); !strings.Contains(out, "git not found") {
		t.Fatal(out)
	}
	if _, err := os.Stat(filepath.Join(nogit, ".git-credentials")); err == nil {
		t.Fatal("credentials written without git")
	}
}

// The redeem side is a DynamicUser. Its only shared credential with the
// root process that issues claims is the group of the claims directory. So
// a claim file must go in that group. www cannot read a root:root file, and
// then the full enrolment path gives 404.
func TestClaimFileCarriesTheDirectoryGroup(t *testing.T) {
	s, _ := testServer(t)
	dir := ClaimsDir(s.Dir)
	if err := os.MkdirAll(dir, 0770); err != nil {
		t.Fatal(err)
	}
	var dst syscall.Stat_t
	if err := syscall.Stat(dir, &dst); err != nil {
		t.Fatal(err)
	}
	c, err := IssueClaim(dir, "a1b2c3d4e5f67890", []string{"GITHUB_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, c.Code+".json"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Gid != dst.Gid {
		t.Fatalf("claim gid %d, directory gid %d: www cannot read it", st.Gid, dst.Gid)
	}
	if perm := fi.Mode().Perm(); perm&0040 == 0 {
		t.Fatalf("claim mode %o is not group readable", perm)
	}
}

// The table of the limiter is state that an unauthenticated caller grows:
// one key per source address, kept for the life of the process. It never
// evicted. So a scan of a /16 left 65k entries, and nothing ever removed
// them. This is the same shape as the ledger growth, in memory instead of
// on disk.
func TestLimiterTableIsBounded(t *testing.T) {
	var l limiter
	for i := 0; i < hitsMax+500; i++ {
		if !l.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)) {
			t.Fatalf("a first request from a new address was refused at %d", i)
		}
	}
	if len(l.hits) > hitsMax {
		t.Fatalf("the table grew to %d, past the %d bound", len(l.hits), hitsMax)
	}
	// Bounded is not the same as useless. This limiter exists to stop one
	// address in a loop, and a sweep must not forget that address. Its window
	// has not passed, so nothing above can have dropped it.
	for i := 0; i < limitPerMin; i++ {
		if !l.allow("10.77.0.10") {
			t.Fatalf("request %d from one address was refused early", i)
		}
	}
	if l.allow("10.77.0.10") {
		t.Fatal("the limiter forgot an address inside its own window")
	}
}

// tryClaim asks s for code as if from address ip, and gives the status.
func tryClaim(s *Server, ip, code string) int {
	r := httptest.NewRequest(http.MethodGet, "/claim/"+code, nil)
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	s.serve(w, r)
	return w.Code
}

// The anti-spoof rule admits each address of the agent segment. So a root
// agent can add an alias for each free address and get limitPerMin tries
// for each alias. All sources together get segmentPerMin tries a minute.
func TestClaimSegmentSharesOneLimit(t *testing.T) {
	s, _ := testServer(t)
	_ = os.MkdirAll(ClaimsDir(s.Dir), 0770)
	if segmentPerMin <= limitPerMin {
		t.Fatalf("segment cap %d is not above the per-source cap %d", segmentPerMin, limitPerMin)
	}
	// One address in a loop spends its own budget, not the budget of the
	// segment. A try that the per-source limit refuses does not count.
	for range 5 * limitPerMin {
		tryClaim(s, "10.77.0.10", "ABCDEFGH")
	}
	for i := limitPerMin; i < segmentPerMin; i++ {
		if got := tryClaim(s, fmt.Sprintf("10.77.0.%d", 20+i), "ABCDEFGH"); got != http.StatusNotFound {
			t.Fatalf("try %d from a new address got %d, want 404", i, got)
		}
	}
	for _, ip := range []string{"10.77.0.200", "10.77.0.201"} {
		if got := tryClaim(s, ip, "ABCDEFGH"); got != http.StatusTooManyRequests {
			t.Fatalf("try from %s past the segment cap got %d, want 429", ip, got)
		}
	}
}

// A try that the segment cap refuses does not spend a try of its source.
// Before, the source paid for it too. Thus the operator was still refused
// after the segment had space again.
func TestSegmentRefusalKeepsTheSourceTries(t *testing.T) {
	s, _ := testServer(t)
	_ = os.MkdirAll(ClaimsDir(s.Dir), 0770)
	for i := range segmentPerMin {
		if got := tryClaim(s, fmt.Sprintf("10.77.0.%d", 20+i/limitPerMin), "ABCDEFGH"); got != http.StatusNotFound {
			t.Fatalf("try %d to fill the segment got %d, want 404", i, got)
		}
	}
	for range limitPerMin {
		if got := tryClaim(s, "10.77.0.50", "ABCDEFGH"); got != http.StatusTooManyRequests {
			t.Fatalf("try past the segment cap got %d, want 429", got)
		}
	}
	// The minute of the segment ends.
	s.seg.mu.Lock()
	s.seg.at = nil
	s.seg.mu.Unlock()
	if got := tryClaim(s, "10.77.0.50", "ABCDEFGH"); got != http.StatusNotFound {
		t.Fatalf("the source lost its tries to the segment cap: got %d, want 404", got)
	}
}
