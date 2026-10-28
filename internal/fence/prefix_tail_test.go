package fence

import (
	"bytes"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
	"pi-fortress/internal/tokenrules"
)

// keyShape makes a token for one key_prefixes.rules row, at its minimum
// length plus extra body bytes. The bodies are made here and never written
// out as literals. Thus the leak check of the tree has no key to find.
type keyShape struct {
	rule string
	make func(extra int) string
}

// fill is n bytes that cycle through alphabet. It is repetitive, so no tail
// of a token can hide among other text, and secretscan reads nothing as random.
func fill(alphabet string, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(alphabet, n/len(alphabet)+1)[:n]
}

func simpleShape(rule, prefix, alphabet string, min int) keyShape {
	return keyShape{rule, func(extra int) string { return prefix + fill(alphabet, min+extra) }}
}

const (
	alnum   = "aB3xZ9"
	alnumUD = "aB3_x-Z9"
	alnumU  = "aB3_xZ9"
	upperD  = "AB3XZ9"
	letters = "aBxZ"
)

func keyShapes() []keyShape {
	return []keyShape{
		simpleShape("github_classic", "ghp_", alnum, 36),
		{"github_fine", func(extra int) string {
			return "github_pat_" + fill(alnum, 22) + "_" + fill(alnum, 59+extra)
		}},
		simpleShape("github_oauth", "gho_", alnum, 36),
		simpleShape("github_user", "ghu_", alnum, 36),
		simpleShape("github_server", "ghs_", alnum, 36),
		simpleShape("github_refresh", "ghr_", alnum, 36),
		{"anthropic", func(extra int) string {
			return "sk-ant-api03-" + fill(alnumUD, 93) + "AA" + fill(alnumUD, extra)
		}},
		simpleShape("anthropic_admin", "sk-ant-admin01-", alnumUD, 20),
		simpleShape("anthropic_oat", "sk-ant-oat01-", alnumUD, 20),
		simpleShape("anthropic_ort", "sk-ant-ort01-", alnumUD, 20),
		simpleShape("openai_legacy", "sk-", alnum, 48),
		simpleShape("openai_proj", "sk-proj-", alnumUD, 40),
		simpleShape("openai_svcacct", "sk-svcacct-", alnumUD, 40),
		simpleShape("openai_admin", "sk-admin-", alnumUD, 40),
		simpleShape("openai_none", "sk-None-", alnumUD, 40),
		simpleShape("xai", "xai-", alnumU, 60),
		simpleShape("aws_akia", "AKIA", upperD, 16),
		simpleShape("aws_asia", "ASIA", upperD, 16),
		simpleShape("google_api", "AIza", alnumUD, 35),
		simpleShape("huggingface", "hf_", letters, 34),
		simpleShape("npm", "npm_", alnum, 36),
		simpleShape("stripe_live", "sk_live_", alnum, 24),
		simpleShape("gitlab_pat", "glpat-", alnumUD, 20),
	}
}

// Each rule in the shipped file has a shape here. Thus a rule added later
// without a shape fails this test, and does not go untested.
func TestKeyShapesCoverEveryRule(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range keyShapes() {
		have[s.rule] = true
	}
	for _, r := range rules.Rules {
		if !have[r.Name] {
			t.Errorf("rule %s has no shape in keyShapes", r.Name)
		}
	}
}

// A rule ended in \b after a fixed-length body. Thus a key one word byte
// longer than the rule expected -- a longer issue of the same token, a key
// glued to the next word, one byte appended -- matched no rule and went
// out whole. Now a rule takes the characters of the key to their natural
// end. The fence strips the full token and leaves no tail of it: at the
// minimum length, one longer, many longer, and before punctuation, in a
// JSON body, a query and a header value.
func TestPrefixRuleStripsTheWholeToken(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	pol := loadPol(t)
	run := func(t *testing.T, raw, tok string) string {
		t.Helper()
		req := parseReq(t, raw)
		if _, err := Decide(Ctx{SNI: "example.com", Rules: rules}, req, pol, labSlots()); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	for _, s := range keyShapes() {
		for _, extra := range []int{0, 1, 2, 57} {
			tok := s.make(extra)
			tail := tok[len(tok)-6:]
			body := func(b string) string {
				return "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b
			}
			cases := map[string]string{
				"json":   body(`{"k":"` + tok + `","n":1}`),
				"query":  "GET /x?k=" + tok + "&b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
				"header": "GET /x HTTP/1.1\r\nHost: example.com\r\nX-Note: a " + tok + "; b\r\n\r\n",
			}
			for _, p := range []string{".", ",", ";", ")", "'", "\"", "!", "?", ":"} {
				cases["punct "+p] = body("see " + tok + p + " end")
			}
			for name, raw := range cases {
				t.Run(s.rule+"+"+strconv.Itoa(extra)+" "+name, func(t *testing.T) {
					out := run(t, raw, tok)
					if strings.Contains(out, tail) || strings.Contains(out, tok[:len(tok)/2]) || !strings.Contains(out, StripRepl) {
						t.Fatalf("not wholly stripped:\n%q", out)
					}
				})
			}
		}
	}
}

// One byte short of the minimum is not a key. The fence does not change an
// ordinary word that shares a prefix, at any length that the rule cannot reach.
func TestPrefixRuleLeavesShortRunsAlone(t *testing.T) {
	rules, err := tokenrules.LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	ts := tokensFor(rules.All())
	var short []string
	for _, s := range keyShapes() {
		switch s.rule {
		case "github_fine":
			short = append(short, "github_pat_"+fill(alnum, 21)+"_"+fill(alnum, 59), "github_pat_"+fill(alnum, 22)+"_"+fill(alnum, 58))
		case "anthropic":
			short = append(short, "sk-ant-api03-"+fill(alnumUD, 92)+"AA", "sk-ant-api03-"+fill(alnumUD, 200))
		default:
			short = append(short, s.make(-1))
		}
	}
	short = append(short,
		"xai-grok-4", "sk-proj-settings", "sk-admin-panel", "the xai-sdk_python package",
		"ghp_token", "AKIA_ROLE", "Asia/Kolkata", "AsiaPacific", "hf_hub_download", "npm_config_registry",
		"task-"+fill(alnum, 64), "Malaysia"+fill(upperD, 20),
	)
	for _, s := range short {
		b := []byte(`{"k":"` + s + `"} ` + s + "\n")
		if out := ts.replace(b, stripRepl); !bytes.Equal(out, b) {
			t.Errorf("%q was stripped: %q", s, out)
		}
	}
}

// The stream decides at each read boundary how much it can emit. A token
// that now continues past the old fixed length of a rule must come out the
// same as on the buffered path, for all read splits.
func TestStreamStripsLongerTokensLikeBuffered(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	rng := rand.New(rand.NewPCG(11, 12))
	for _, s := range keyShapes() {
		for _, extra := range []int{0, 1, 300} {
			tok := s.make(extra)
			inner := strings.Repeat("z", 2000) + ` {"k":"` + tok + `"} ` + tok + ". " + strings.Repeat("q", 2000)
			want, got, werr, gerr := bothPaths(t, ctx, pol, inner, rng)
			if werr != nil || gerr != nil {
				t.Fatalf("%s+%d: %v / %v", s.rule, extra, werr, gerr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s+%d: stream and buffered disagree:\n%q\n%q", s.rule, extra, got, want)
			}
			if bytes.Contains(want, []byte(tok[len(tok)-6:])) {
				t.Fatalf("%s+%d: a tail of the token went out: %q", s.rule, extra, want)
			}
		}
	}
}

// The report for each shape uses its own rule and no other. sk-ant-admin01-
// shares sk-ant- with the user key and the OAuth tokens, and sk- with the
// OpenAI rules. The fence must not take it for any of them.
func TestEachShapeIsItsOwnRule(t *testing.T) {
	ts := tokensFor(loadShippedRules(t).All())
	for _, s := range keyShapes() {
		for _, extra := range []int{0, 40} {
			if got := ts.rules([]byte(" " + s.make(extra) + " ")); len(got) != 1 || got[0] != s.rule {
				t.Errorf("%s+%d: rules %v", s.rule, extra, got)
			}
		}
	}
}
