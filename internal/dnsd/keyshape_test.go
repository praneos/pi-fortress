package dnsd

import (
	"bytes"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/tokenrules"
)

// shippedRules is the policy that the Pi runs. Thus the test tries a rule
// added there on query names, and nobody must remember to add it here.
const shippedRules = "../../vm/policy/key_prefixes.rules"

func mustKeyShapes(t *testing.T) *keyShapes {
	t.Helper()
	k, err := loadKeyShapes(shippedRules)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Keys long enough to need more than one label are split the way a
// careless exfil splits them, at 63.
func splitLabels(s string) string {
	var parts []string
	for len(s) > 63 {
		parts, s = append(parts, s[:63]), s[63:]
	}
	return strings.Join(append(parts, s), ".")
}

// The heads of the prefilter are lower case. The rules match either case.
// match lowers the name before it looks for them.
func TestLiteralHead(t *testing.T) {
	for expr, want := range map[string]string{
		`\bghp_[A-Za-z0-9]{36}\b`:             "ghp_",
		`\bsk-ant-oat01-[A-Za-z0-9_-]{20,}\b`: "sk-ant-oat01-",
		`\bAKIA[A-Z0-9]{16}\b`:                "akia",
		`[A-Z]{3}x`:                           "",
		`(?i)abc`:                             "abc",
	} {
		if got := (tokenrules.Rule{Name: "t", Expr: expr}).Head(); got != want {
			t.Errorf("%s: %q, want %q", expr, got, want)
		}
	}
}

// A rule with no literal head disables the prefilter for every name. The
// load tells this one time and names the rule. The shipped rules give no
// message.
func TestHeadlessRuleIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	mustKeyShapes(t)
	if strings.Contains(buf.String(), "no literal head") {
		t.Fatalf("shipped rules logged: %s", buf.String())
	}
	rules := filepath.Join(t.TempDir(), "k.rules")
	if err := os.WriteFile(rules, []byte("github_classic \\bghp_[A-Za-z0-9]{36}\\b\nheadless [A-Z]{4}x[0-9]{8}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	k, err := loadKeyShapes(rules)
	if err != nil {
		t.Fatal(err)
	}
	if k.prefixes != nil {
		t.Fatalf("prefilter still on: %q", k.prefixes)
	}
	if out := buf.String(); strings.Count(out, "no literal head") != 1 || !strings.Contains(out, "key rule headless has no literal head") {
		t.Fatalf("log %q", out)
	}
	if got := k.match("ABCDx12345678.evil.example"); got != "headless" {
		t.Fatalf("headless rule did not match: %q", got)
	}
}

// DNS is case-insensitive, so the receiver folds a flipped key back. A
// key in any case is refused, and so is a placeholder in any case.
func TestKeyShapeMatchAnyCase(t *testing.T) {
	k := mustKeyShapes(t)
	a := strings.Repeat("a", 40)
	for name, want := range map[string]string{
		"akia" + strings.Repeat("x", 16) + ".evil.example":  "aws_akia",
		"AkIa" + strings.Repeat("Q7", 8) + ".evil.example":  "aws_akia",
		"GHP_" + a[:36] + ".evil.example":                   "github_classic",
		"Ghp_" + a[:36] + ".evil.example":                   "github_classic",
		"Sk-AnT-oAt01-" + a + ".evil.example":               "anthropic_oat",
		splitLabels("SK-ANT-API03-"+a+a+a[:13]+"aa") + ".x": "anthropic",
	} {
		if got := k.match(name); got != want {
			t.Errorf("%.40s...: %q, want %q", name, got, want)
		}
	}
	if got := k.match("PF_0123456789ABCDEF_CLAUDE_OAT.evil.example"); got != "placeholder" {
		t.Errorf("an upper-cased placeholder spelling matched %q", got)
	}
}

func TestKeyShapeMatch(t *testing.T) {
	k := mustKeyShapes(t)
	a := func(n int) string { return strings.Repeat("A", n) }
	api03 := "sk-ant-api03-" + a(93) + "AA"
	hits := map[string]string{
		"ghp_" + a(36) + ".evil.example":               "github_classic",
		"AKIA" + a(16) + ".evil.example":               "aws_akia",
		"x.sk-ant-oat01-" + a(40) + ".evil.example":    "anthropic_oat",
		splitLabels(api03) + ".evil.example":           "anthropic",
		splitLabels("sk-ant-oat01-"+a(80)) + ".e.test": "anthropic_oat",
		"pf_0123456789abcdef_CLAUDE_OAT.evil.example":  "placeholder",
		// A fixed-length rule needs the key to end where the string ends.
		// In each run, the key ends there, whatever follows it in the name.
		"ghp_" + a(20) + "." + a(16) + ".evil.example": "github_classic",
	}
	for name, want := range hits {
		if got := k.match(name); got != want {
			t.Errorf("%.40s...: %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{
		"github.com", "api.anthropic.com", "sk-learn.example.org",
		"my-company-artifacts-prod-us-east-1.s3.amazonaws.com",
		"r3---sn-abc123def456.googlevideo.com", "pf_open.example", "",
		// Real names whose last label completes a shape once the dot is
		// gone: the TLD is never part of a run.
		"asiakuecheerlangen.de", "www.asiakuecheerlangen.de.",
	} {
		if got := k.match(name); got != "" {
			t.Errorf("%q matched %q", name, got)
		}
	}
}

func TestKeyShapeLogName(t *testing.T) {
	k := mustKeyShapes(t)
	key := "ghp_" + strings.Repeat("A", 36)
	if got := k.logName(key + ".tun.evil.example"); got != "evil.example" {
		t.Fatalf("logName %q", got)
	}
	if got := k.logName("x." + key + ".example"); got != "" {
		t.Fatalf("a key in the zone itself kept %q", got)
	}
}

// The full path: the name is refused, never forwarded and never cached.
// The log has the zone and the rule but not the name. This is true for
// each query type, and for each policy path that would otherwise take the
// name.
func TestKeyShapedNameRefused(t *testing.T) {
	h := newHarness(t, []string{"sinkholed.example"}, map[string][4]byte{"ok.example": {1, 2, 3, 4}}, 300)
	h.srv.segs[0].keys.Store(mustKeyShapes(t))
	key := "sk-ant-oat01-" + strings.Repeat("A", 40)
	for _, tc := range []struct {
		name string
		qt   dnsmessage.Type
	}{
		{key + ".evil.example", dnsmessage.TypeA},
		{key + ".evil.example", dnsmessage.TypeTXT},
		{key + ".evil.example", dnsmessage.TypeAAAA},
		{key + ".sinkholed.example", dnsmessage.TypeA},
	} {
		hdr, ans := h.ask(t, tc.name, tc.qt)
		if hdr.RCode != dnsmessage.RCodeRefused || len(ans) != 0 {
			t.Fatalf("%v %s: rcode %v answers %d", tc.qt, tc.name[len(key):], hdr.RCode, len(ans))
		}
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
	raw, err := os.ReadFile(h.log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "AAAAAAAAAA") {
		t.Fatalf("the key reached the log:\n%s", raw)
	}
	rows := h.logLines(t)
	if len(rows) != 4 {
		t.Fatalf("rows %+v", rows)
	}
	for _, r := range rows {
		if r.Act != dnslog.ActRefused || r.Rule != "anthropic_oat" || (r.Name != "evil.example" && r.Name != "sinkholed.example") {
			t.Fatalf("row %+v", r)
		}
	}
	// And an ordinary name still resolves.
	if _, ans := h.ask(t, "ok.example", dnsmessage.TypeA); firstA(t, ans) != "1.2.3.4" {
		t.Fatalf("ok.example: %+v", ans)
	}
}

// A named rules file that does not load stops the daemon, as in the
// broker. The operator asked for the check.
func TestKeyRulesMissingIsAnError(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.conf")
	if err := os.WriteFile(sink, nil, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		NFTTable: "inet fortress", NFT: &fakeNFT{},
		Segments: []Segment{{
			Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: "127.0.0.1:1", SinkholeFiles: []string{sink},
			NFTSet: "resolved_v4", KeyRulesPath: filepath.Join(dir, "missing.rules"),
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "key rules") {
		t.Fatalf("err %v", err)
	}
}

// Before, every run left out the last label. Thus a key that was the last
// label, or continued into it, was forwarded and logged whole. Now the
// match always tries the last label alone, because no real TLD has the
// shape of a key. A run can include the last label unless it has the
// shape of a TLD. Thus a real name whose TLD completes a shape still gets
// an answer (asiakuecheerlangen.de in TestKeyShapeMatch).
func TestKeyShapeInTheLastLabel(t *testing.T) {
	k := mustKeyShapes(t)
	a := strings.Repeat("A", 36)
	for name, want := range map[string]string{
		"x.ghp_" + a:                    "github_classic",
		"ghp_" + a:                      "github_classic",
		"tun.ghp_" + a[:30] + ".AAAAA1": "github_classic",
		"ghp_" + a[:34] + ".a1":         "github_classic",
		"tun.AKIA" + strings.Repeat("Q7", 7) + ".7Q": "aws_akia",
	} {
		if got := k.match(name); got != want {
			t.Errorf("%.48s: %q, want %q", name, got, want)
		}
		if got := k.logName(name); strings.Contains(got, "AAAAAAAAAA") || strings.Contains(got, "Q7Q7") {
			t.Errorf("%.48s: logName kept the key: %q", name, got)
		}
	}
	for _, name := range []string{
		"asiakuecheerlangen.de", "www.example.xn--p1ai", "github.com", "my-service-prod.example.travelersinsurance",
	} {
		if got := k.match(name); got != "" {
			t.Errorf("%q matched %q", name, got)
		}
	}
}

// Through the server: a key in the last label is refused, never
// forwarded, and the log keeps no part of it.
func TestKeyShapeInTheLastLabelIsRefused(t *testing.T) {
	h := newHarness(t, nil, nil, 300)
	h.srv.segs[0].keys.Store(mustKeyShapes(t))
	name := "x.ghp_" + strings.Repeat("A", 36)
	if hdr, _ := h.ask(t, name, dnsmessage.TypeA); hdr.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("rcode %v, want REFUSED", hdr.RCode)
	}
	if n := h.up.asked.Load(); n != 0 {
		t.Fatalf("upstream asked %d times", n)
	}
	rows := h.logLines(t)
	if len(rows) != 1 || rows[0].Rule != "github_classic" || rows[0].Name != "" {
		t.Fatalf("rows %+v", rows)
	}
}

// shortLabels splits s into labels of n bytes.
func shortLabels(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts, s = append(parts, s[:n]), s[n:]
	}
	return strings.Join(append(parts, s), ".")
}

// A key is refused when it is split across any number of labels. A rule
// that must end at the end of the key (the AWS ids in lower case, the
// placeholder) still matches when the key ends at a label boundary and a
// label of letters follows.
func TestKeyShapeSplitIntoShortLabels(t *testing.T) {
	k := mustKeyShapes(t)
	akia := "akia" + strings.Repeat("q7", 8)
	for name, want := range map[string]string{
		shortLabels("ghp_"+strings.Repeat("A", 36), 3) + ".evil.example":        "github_classic",
		"x." + shortLabels("ghp_"+strings.Repeat("A", 36), 1) + ".evil.example": "github_classic",
		shortLabels("sk-ant-oat01-"+strings.Repeat("a", 40), 4) + ".e.example":  "anthropic_oat",
		"x." + shortLabels("sk-"+strings.Repeat("a", 48), 2) + ".e.example":     "openai_legacy",
		shortLabels(akia, 1) + ".evil.example":                                  "aws_akia",
		"tun." + shortLabels(akia, 2) + ".evil.example":                         "aws_akia",
		"x-" + shortLabels(akia, 2) + ".evil.example":                           "aws_akia",
		shortLabels("pf_0123456789abcdef_CLAUDE_OAT", 2) + ".evil.example":      "placeholder",
	} {
		if got := k.match(name); got != want {
			t.Errorf("%.48s: %q, want %q", name, got, want)
		}
		if got := k.logName(name); got != "evil.example" && got != "e.example" {
			t.Errorf("%.48s: logName %q", name, got)
		}
	}
	for _, name := range []string{
		strings.Repeat("ab.", 60) + "sk-x.example.com",
		strings.Repeat("sk-.", 60) + "example.com",
		"tun" + shortLabels(akia, 2) + ".evil.example",
		shortLabels("ghp_"+strings.Repeat("A", 35), 1) + ".-.evil.example",
	} {
		if got := k.match(name); got != "" {
			t.Errorf("%.48s matched %q", name, got)
		}
	}
}
