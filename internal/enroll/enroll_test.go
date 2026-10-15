package enroll

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/secrets"
)

func TestRedactAndMintGuard(t *testing.T) {
	live := "sk-ant-oat01-abcdefghijXXXX"
	got := RedactLive(live, 16, 4)
	if !strings.HasPrefix(got, "sk-ant-oat01-") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "len=") {
		t.Fatal(got)
	}
	if strings.Contains(got, "abcdefghijXXXX") {
		t.Fatal(got)
	}
	oat := OATPrefix + strings.Repeat("a", 40)
	errs := ClaudeMintErrors(oat, oat)
	foundOrt := false
	foundSame := false
	for _, e := range errs {
		if strings.Contains(e, "ort01") {
			foundOrt = true
		}
		if strings.Contains(e, "same string") {
			foundSame = true
		}
	}
	if !foundOrt {
		t.Fatal(errs)
	}
	if !foundSame {
		t.Fatal(errs)
	}
	good := ClaudeMintErrors(OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40))
	if len(good) != 0 {
		t.Fatal(good)
	}
}

func TestAgentPaste(t *testing.T) {
	text := AgentPaste("a1b2c3d4e5f67890", []string{"CLAUDE_OAT", "CLAUDE_ORT"})
	if !strings.Contains(text, "pf_a1b2c3d4e5f67890_CLAUDE_OAT") {
		t.Fatal(text)
	}
	if !strings.Contains(text, "pf_a1b2c3d4e5f67890_CLAUDE_ORT") {
		t.Fatal(text)
	}
	if strings.Contains(text, "sk-ant-") {
		t.Fatal(text)
	}
	if !strings.Contains(text, `"claudeAiOauth"`) {
		t.Fatal(text)
	}
	gh := AgentPaste("bbbbbbbbbbbbbbbb", []string{"GITHUB_TOKEN"})
	if !strings.Contains(gh, "export GITHUB_TOKEN=") {
		t.Fatal(gh)
	}
	if !strings.Contains(gh, "pf_bbbbbbbbbbbbbbbb_GITHUB_TOKEN") {
		t.Fatal(gh)
	}
	dest := filepath.Join(t.TempDir(), "creds.json")
	if err := WriteAgentPaste("a1b2c3d4e5f67890", []string{"CLAUDE_OAT", "CLAUDE_ORT"}, dest); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "pf_a1b2c3d4e5f67890_CLAUDE_OAT") {
		t.Fatal(string(blob))
	}
	if strings.Contains(string(blob), "sk-ant-") {
		t.Fatal(string(blob))
	}
}

func TestEnrollCLI(t *testing.T) {
	tmp := t.TempDir()
	secretsPath := filepath.Join(tmp, "secrets.env")
	if err := os.WriteFile(secretsPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(tmp, "agent-env.sh")
	out, rc := runCLI("--secrets", secretsPath, "mint", "--kind", "GITHUB_TOKEN", "--value", "lab", "--out", outPath)
	if rc != 0 {
		t.Fatalf("mint rc=%d out=%s", rc, out)
	}
	st := secrets.Open(secretsPath)
	live, err := st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatal(live)
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "export GITHUB_TOKEN=") {
		t.Fatal(string(written))
	}
	if strings.Contains(string(written), "lab") {
		t.Fatal(string(written))
	}

	oat := OATPrefix + strings.Repeat("a", 40)
	out, rc = runCLI("--secrets", secretsPath, "mint", "--kind", "CLAUDE", "--oat", oat, "--ort", oat)
	if rc != 2 {
		t.Fatalf("want rc 2 got %d out=%s", rc, out)
	}

	out, rc = runCLI("--secrets", secretsPath, "list")
	if rc != 0 {
		t.Fatalf("list rc=%d out=%s", rc, out)
	}
	if strings.Contains(out, "lab") {
		t.Fatal(out)
	}

	if err := os.WriteFile(secretsPath, []byte("CLAUDE_OAT=x\nCLAUDE_ORT=y\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, rc = runCLI("--secrets", secretsPath, "migrate")
	if rc != 0 {
		t.Fatalf("migrate rc=%d out=%s", rc, out)
	}
	st = secrets.Open(secretsPath)
	live, err = st.LiveMap()
	if err != nil {
		t.Fatal(err)
	}
	for k := range live {
		if _, _, ok := secrets.ParseEnvKey(k); !ok {
			t.Fatal(k)
		}
	}

	if err := os.WriteFile(secretsPath, []byte(
		"c40b7db27d0f22de_CLAUDE_OAT="+OATPrefix+strings.Repeat("a", 40)+"\n"+
			"c40b7db27d0f22de_CLAUDE_ORT="+OATPrefix+strings.Repeat("a", 40)+"\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	out, rc = runCLI("--secrets", secretsPath, "peek", "--slot", "c40b7db27d0f22de")
	if rc != 0 {
		t.Fatalf("peek rc=%d out=%s", rc, out)
	}
	if !strings.Contains(out, "WARN") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "sk-ant-o…") || strings.Contains(out, "sk-ant-oat01-aaaa") {
		t.Fatal("peek shows more than 8 head characters:", out)
	}

	out, rc = runCLI("--secrets", secretsPath, "delete", "--slot", "c40b7db27d0f22de")
	if rc != 0 || !strings.Contains(out, "deleted slot=c40b7db27d0f22de") {
		t.Fatalf("delete rc=%d out=%s", rc, out)
	}
}

func runCLI(args ...string) (string, int) {
	var stdout, stderr strings.Builder
	rc := Main(args, &stdout, &stderr)
	return stdout.String() + stderr.String(), rc
}

func TestMintStdinAndPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	_ = os.WriteFile(path, nil, 0600)
	oat, ort := OATPrefix+strings.Repeat("a", 40), ORTPrefix+strings.Repeat("b", 40)
	var out, errb strings.Builder
	if code := MainIO([]string{"--secrets", path, "mint", "--kind", "CLAUDE", "--stdin"}, strings.NewReader(oat+"\n"+ort+"\n"), &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	slot := ""
	for line := range strings.SplitSeq(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "slot="); ok {
			slot = v
		}
	}
	raw, _ := os.ReadFile(path)
	if slot == "" || !strings.Contains(string(raw), slot+"_CLAUDE_ORT="+ort) || strings.Contains(out.String(), ort) {
		t.Fatalf("slot=%q\n%s\n%s", slot, raw, out.String())
	}
	if code := MainIO([]string{"--secrets", path, "mint", "--kind", "CLAUDE", "--stdin"}, strings.NewReader(oat+"\n"), &out, &errb); code == 0 {
		t.Fatal("one line accepted")
	}
	st := secrets.Open(path)
	if err := st.Disable(slot); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := MainIO([]string{"--secrets", path, "purge", "--older-than", "7d"}, nil, &out, &errb); code != 0 || out.String() != "" {
		t.Fatal(code, out.String())
	}
	if code := MainIO([]string{"--secrets", path, "purge", "--older-than", "0d"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "purged slot="+slot) {
		t.Fatal(code, out.String())
	}
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), slot) {
		t.Fatal(string(raw))
	}
	if code := MainIO([]string{"--secrets", path, "purge", "--older-than", "week"}, nil, &out, &errb); code != 2 {
		t.Fatal(code)
	}
}

// apply.sh runs `pf enroll migrate` and `pf enroll purge` on each
// apply, with no terminal attached. Neither may stop to prompt for a
// passphrase, and neither may fail, because pf apply must work against
// a sealed store. The segments, DNS, routing and the ruleset do not
// depend on the credential store, and must come back without a human.
func TestApplyVerbsDoNotBlockOnASealedStore(t *testing.T) {
	path, before := sealedStore(t)
	for _, args := range [][]string{
		{"--secrets", path, "migrate"},
		{"--secrets", path, "purge", "--older-than", "7d"},
		{"--secrets", path, "list"},
		{"--secrets", path, "state"},
	} {
		var out, errb bytes.Buffer
		// An empty stdin, so a verb that tried to read one would get EOF,
		// and would not hang. The prompt reads /dev/tty and would fail
		// outright here, which is also a failure that this catches.
		if code := MainIO(args, strings.NewReader(""), &out, &errb); code != 0 {
			t.Fatalf("%v: exit %d: %s %s", args, code, out.String(), errb.String())
		}
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("the store was rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// The first boot of the appliance mints the canary with no special verb.
func TestMintCanaryKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	_ = os.WriteFile(path, nil, 0600)
	var out, errb strings.Builder
	live := "canary-live-0123456789"
	if code := MainIO([]string{"--secrets", path, "mint", "--kind", "CANARY", "--value", live, "--out", filepath.Join(t.TempDir(), "paste")}, nil, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	slot := ""
	for line := range strings.SplitSeq(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "slot="); ok {
			slot = v
		}
	}
	raw, _ := os.ReadFile(path)
	if slot == "" || !strings.Contains(string(raw), slot+"_CANARY="+live) {
		t.Fatalf("slot=%q\n%s", slot, raw)
	}
	if !strings.Contains(out.String(), "export CANARY='"+secrets.Placeholder(slot, "CANARY")+"'") || strings.Contains(out.String(), live) {
		t.Fatal(out.String())
	}
}

// --expires is optional at mint. The default is DefaultExpiry, and
// --expires none gives no deadline. enroll list shows the deadline after
// it is set. renew is the one way to move or clear a deadline after that.
func TestMintExpiresAndRenew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	live := "canary-live-0123456789"
	out, rc := runCLI("--secrets", path, "mint", "--kind", "CANARY", "--value", live, "--expires", "30d")
	if rc != 0 {
		t.Fatal(rc, out)
	}
	slot := ""
	wantExpires := ""
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(line, "slot="); ok {
			slot = v
		}
		if v, ok := strings.CutPrefix(line, "expires="); ok {
			wantExpires = v
		}
	}
	if slot == "" || wantExpires == "" {
		t.Fatalf("slot=%q expires=%q\n%s", slot, wantExpires, out)
	}

	out, rc = runCLI("--secrets", path, "list")
	if rc != 0 || !strings.Contains(out, wantExpires) {
		t.Fatalf("list did not show expiry %q:\n%s", wantExpires, out)
	}

	// A slot minted with no --expires gets DefaultExpiry. --expires none
	// writes the row that an old build wrote, with no deadline.
	out, rc = runCLI("--secrets", path, "mint", "--kind", "GITHUB_TOKEN", "--value", "ghp_"+strings.Repeat("b", 36))
	if rc != 0 {
		t.Fatal(rc, out)
	}
	def := time.Now().Add(90 * 24 * time.Hour)
	var got time.Time
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(line, "expires="); ok {
			got, _ = time.Parse(time.RFC3339, v)
		}
	}
	if d := got.Sub(def); d < -time.Minute || d > time.Minute {
		t.Fatalf("default mint expires %v, want about %v:\n%s", got, def, out)
	}
	out, rc = runCLI("--secrets", path, "mint", "--kind", "GITHUB_TOKEN", "--value", "ghp_"+strings.Repeat("a", 36), "--expires", "none")
	if rc != 0 || strings.Contains(out, "expires=") {
		t.Fatal(rc, out)
	}
	other := ""
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(line, "slot="); ok {
			other = v
		}
	}
	out, rc = runCLI("--secrets", path, "list")
	if rc != 0 {
		t.Fatal(rc, out)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, other+"  ") && !strings.HasSuffix(strings.TrimRight(line, "\n"), "  -") {
			t.Fatalf("unexpired slot shows a deadline: %q", line)
		}
	}

	// renew moves the deadline.
	out, rc = runCLI("--secrets", path, "renew", "--slot", slot, "--expires", "1h")
	if rc != 0 || !strings.Contains(out, "expires=") {
		t.Fatal(rc, out)
	}
	renewed := strings.TrimSpace(strings.TrimPrefix(strings.Split(out, "expires=")[1], "\n"))
	if renewed == wantExpires {
		t.Fatal("renew did not move the deadline")
	}

	// renew --expires none clears it.
	out, rc = runCLI("--secrets", path, "renew", "--slot", slot, "--expires", "none")
	if rc != 0 || !strings.Contains(out, "expires=none") {
		t.Fatal(rc, out)
	}
	out, rc = runCLI("--secrets", path, "list")
	if rc != 0 {
		t.Fatal(rc, out)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, slot+"  ") && !strings.HasSuffix(strings.TrimRight(line, "\n"), "  -") {
			t.Fatalf("cleared slot still shows a deadline: %q", line)
		}
	}

	// A malformed slot or a missing --expires is a usage error, not a
	// silent no-op.
	if _, rc := runCLI("--secrets", path, "renew", "--slot", "nope", "--expires", "1h"); rc != 2 {
		t.Fatal("bad slot accepted")
	}
	if _, rc := runCLI("--secrets", path, "renew", "--slot", slot); rc != 2 {
		t.Fatal("missing --expires accepted")
	}
}

func TestDeleteSlotList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	a, b, c := "0aad5baef7bb7b91", "a8489de475acaf89", "9f86cb6a66817baf"
	if err := os.WriteFile(path, []byte(
		a+"_GITHUB_TOKEN=x\n"+b+"_GITHUB_TOKEN=y\n"+c+"_GITHUB_TOKEN=z\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	if out, rc := runCLI("--secrets", path, "delete", "--slot", a+",nothex"); rc != 2 || !strings.Contains(out, "invalid slot") {
		t.Fatalf("bad id rc=%d out=%s", rc, out)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), a) {
		t.Fatal("a list with a bad id deleted the good one")
	}
	out, rc := runCLI("--secrets", path, "delete", "--slot", " "+strings.ToUpper(a)+", "+b+",,deadbeefdeadbeef")
	if rc != 1 || !strings.Contains(out, "deleted slot="+a+" kinds=GITHUB") ||
		!strings.Contains(out, "deleted slot="+b) || !strings.Contains(out, "slot not found: deadbeefdeadbeef") {
		t.Fatalf("list rc=%d out=%s", rc, out)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), a) || strings.Contains(string(raw), b) || !strings.Contains(string(raw), c) {
		t.Fatalf("secrets after delete:\n%s", raw)
	}
	if out, rc := runCLI("--secrets", path, "delete", "--slot", " , "); rc != 2 || !strings.Contains(out, "usage") {
		t.Fatalf("empty rc=%d out=%s", rc, out)
	}
}

func TestRedactLiveShowsAlmostNothingOfAShortValue(t *testing.T) {
	for _, v := range []string{"a", "abc", "abcdefg", "abcdefgh", "ghp_shortsecret12"} {
		got := RedactLive(v, 16, 4)
		shown, _, _ := strings.Cut(got, "…")
		if len(shown) > 2 || (len(v) < 8 && shown != "") {
			t.Errorf("RedactLive(%q) = %q: shows %q", v, got, shown)
		}
		if !strings.Contains(got, "len="+strconv.Itoa(len(v))) {
			t.Errorf("RedactLive(%q) = %q: no length", v, got)
		}
	}
}
