package keyshape

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/fence"
)

func TestRule(t *testing.T) {
	re := regexp.MustCompile(`(?P<gh>ghp_[A-Za-z0-9]{36})|AKIA[A-Z0-9]{16}`)
	ph := "pf_0123456789abcdef_CLAUDE_OAT"
	key := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		re      *regexp.Regexp
		s, want string
	}{
		{re, key, "gh"},
		{re, "AKIA" + strings.Repeat("Q", 16), "key"},
		{re, "example", ""},
		{re, ph, "placeholder"},
		{nil, ph, "placeholder"},
		{nil, key, ""},
	} {
		if got := Rule(tc.re, tc.s); got != tc.want {
			t.Errorf("Rule(%v, %q) = %q, want %q", tc.re != nil, tc.s, got, tc.want)
		}
	}
}

func TestTail(t *testing.T) {
	for in, want := range map[string]string{
		"a.b.evil.example": "evil.example",
		"evil.example":     "evil.example",
		"example":          "example",
		"www.www.":         "www.",
		"":                 "",
	} {
		if got := Tail(in); got != want {
			t.Errorf("Tail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeads(t *testing.T) {
	rules := []fence.Rule{{Name: "a", Expr: `\bAKIA[A-Z0-9]{16}\b`}, {Name: "g", Expr: `ghp_[A-Za-z0-9]{36,}`}}
	heads, headless := Heads(rules)
	if headless != "" || !slices.Equal(heads, []string{"pf_", "akia", "ghp_"}) {
		t.Fatalf("heads %q, headless %q", heads, headless)
	}
	heads, headless = Heads(append(rules, fence.Rule{Name: "h", Expr: `[A-Z]{4}x`}, fence.Rule{Name: "i", Expr: `[0-9]x`}))
	if heads != nil || headless != "h" {
		t.Fatalf("heads %q, headless %q", heads, headless)
	}
}

// Without a head in the name, Match runs no rule, even one that would
// match. nil heads runs each rule on each name.
func TestMatchPrefilter(t *testing.T) {
	re := regexp.MustCompile(`(?P<x>[A-Z]{4}x[0-9]{8})`)
	name := "ABCDx12345678.evil.example"
	if got := Match(re, []string{"pf_", "ghp_"}, name); got != "" {
		t.Fatalf("prefiltered: %q", got)
	}
	if got := Match(re, nil, name); got != "x" {
		t.Fatalf("no prefilter: %q", got)
	}
	if got := Match(re, nil, ""); got != "" {
		t.Fatalf("empty name: %q", got)
	}
}

// eachRun is the definition that Match must meet: some run of labels, of
// any length and with its dots removed, matches a rule. The last label
// joins a run only when it does not have the shape of a TLD, and it is
// always tried alone.
func eachRun(all *regexp.Regexp, name string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	n := len(labels)
	if n > 1 && tldShaped(labels[n-1]) {
		if Rule(all, labels[n-1]) != "" {
			return true
		}
		n--
	}
	for i := range n {
		for j := i; j < n; j++ {
			if Rule(all, strings.Join(labels[i:j+1], "")) != "" {
				return true
			}
		}
	}
	return false
}

func shippedRules(t testing.TB) (*regexp.Regexp, []string) {
	t.Helper()
	tr, err := fence.LoadTokenRules("../../vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	heads, headless := Heads(tr.Rules)
	if headless != "" {
		t.Fatalf("headless rule %s", headless)
	}
	return tr.All(), heads
}

// randomName joins parts of keys and other text, and puts dots at random
// places. Thus most names are near a key, and some are a key.
func randomName(r *rand.Rand) string {
	parts := []string{
		"ghp_", "AKIA", "akia", "asia", "sk-", "sk-ant-oat01-", "AIza", "npm_", "pf_",
		"0123456789abcdef", "_CLAUDE_OAT", "_github", "q7Q7", "AAAAAAAAAAAA", "aaaa",
		"x", "-", "_", "%41", `\x41`, "evil", "example", "de", "xn--p1ai", "1",
		"ab", "12345678", "ABC9x",
	}
	var b strings.Builder
	for range 1 + r.IntN(12) {
		b.WriteString(parts[r.IntN(len(parts))])
		if r.IntN(3) == 0 {
			b.WriteByte('.')
		}
	}
	s := b.String()
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		out.WriteByte(s[i])
		if r.IntN(6) == 0 {
			out.WriteByte('.')
		}
	}
	return out.String()
}

// Match finds a key exactly when one run of labels holds it, with or
// without the prefilter.
func TestMatchSameAsEachRun(t *testing.T) {
	all, heads := shippedRules(t)
	r := rand.New(rand.NewPCG(1, 2))
	hits := 0
	for range 600 {
		name := randomName(r)
		want := eachRun(all, name)
		if want {
			hits++
		}
		if got := Match(all, heads, name) != ""; got != want {
			t.Fatalf("Match(%q) = %v, each run says %v", name, got, want)
		}
		if got := Match(all, nil, name) != ""; got != want {
			t.Fatalf("Match(%q) with no prefilter = %v, each run says %v", name, got, want)
		}
	}
	if hits < 40 {
		t.Fatalf("only %d of the names hold a key", hits)
	}
}

// The same holds for rules with no lead and a closing \b, a rule that
// must end at the end of the text, and a rule with no literal head.
func TestMatchSameAsEachRunOtherRules(t *testing.T) {
	for _, rules := range []string{
		"gx ghp_[A-Za-z0-9]{8}\\b\nend \\bab[0-9]{4}$\nlead \\bakia[0-9]{4}\n",
		"gx ghp_[A-Za-z0-9]{8}\\b\nheadless [A-Z]{3}9x[0-9]{4}\n",
	} {
		path := filepath.Join(t.TempDir(), "k.rules")
		if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
			t.Fatal(err)
		}
		tr, err := fence.LoadTokenRules(path)
		if err != nil {
			t.Fatal(err)
		}
		all := tr.All()
		heads, _ := Heads(tr.Rules)
		r := rand.New(rand.NewPCG(3, 4))
		hits := 0
		for range 600 {
			name := randomName(r)
			want := eachRun(all, name)
			if want {
				hits++
			}
			if got := Match(all, heads, name) != ""; got != want {
				t.Fatalf("%q: Match(%q) = %v, each run says %v", rules, name, got, want)
			}
		}
		if hits < 8 {
			t.Fatalf("%q: only %d of the names hold a key", rules, hits)
		}
	}
}

func FuzzMatchSameAsEachRun(f *testing.F) {
	all, heads := shippedRules(f)
	f.Add("a.k.i.a.q.7.q.7.q.7.q.7.q.7.q.7.q.7.q.7.evil.example")
	f.Add("x-ak.ia.q7.q7.q7.q7.q7.q7.q7.q7.evil")
	f.Add("pf._0.12.34.56.78.9a.bc.de.f_.CL.AU.DE._O.AT.evil.example")
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 300 {
			return
		}
		want := eachRun(all, name)
		if got := Match(all, heads, name) != ""; got != want {
			t.Fatalf("Match(%q) = %v, each run says %v", name, got, want)
		}
		if got := Match(all, nil, name) != ""; got != want {
			t.Fatalf("Match(%q) with no prefilter = %v, each run says %v", name, got, want)
		}
	})
}

// The derived forms of the shipped rules: the rules with a closing \b are
// the AWS ids in any case, and the lead of a rule is short and has a limit.
func TestFormsOfShippedRules(t *testing.T) {
	all, _ := shippedRules(t)
	f := formsOf(all)
	if f.ends == nil || Rule(f.ends, "akia"+strings.Repeat("q7", 8)) != "aws_akia" || Rule(f.ends, "ghp_"+strings.Repeat("A", 36)) != "" {
		t.Fatalf("ends %v", f.ends)
	}
	if f.lead < len(`A`) || f.lead > 64 {
		t.Fatalf("lead %d", f.lead)
	}
	if Rule(f.anch, "x"+"ghp_"+strings.Repeat("A", 36)) != "" || Rule(f.anch, "ghp_"+strings.Repeat("A", 36)) != "github_classic" {
		t.Fatal("anch is not anchored at the start")
	}
}
