package fence

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/testsupport"
)

// boundedRules keep a boundary before their prefix. `sk-`, `AIza` and
// `npm_` occur inside ordinary words and identifiers (task-, flask-admin-,
// base64, pnpm_). Thus, if a letter or digit comes immediately before the
// prefix, the rule does not match there. The prefix of each other rule is distinctive enough to
// match at any start position.
var boundedRules = map[string]bool{
	"openai_legacy": true, "openai_proj": true, "openai_svcacct": true, "openai_admin": true,
	"openai_none": true, "google_api": true, "stripe_live": true, "npm": true,
}

func loadShippedRules(t *testing.T) *TokenRules {
	t.Helper()
	rules, err := LoadTokenRules(filepath.Join(testsupport.RepoRoot(t), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// decideOut runs raw to a foreign host and returns the target and body
// that would go out.
func decideOut(t *testing.T, rules *TokenRules, raw string) (string, string) {
	t.Helper()
	req := parseReq(t, raw)
	if _, err := Decide(Ctx{SNI: "example.com", Rules: rules}, req, loadPol(t), labSlots()); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return req.Target, string(body)
}

func postBody(ct, b string) string {
	return "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Type: " + ct + "\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b
}

// The leading \b of a rule needed a non-word byte before the prefix. In a
// JSON string, a token at the start of a line follows the escape \n. In a
// query, it follows %20 or %0A. The byte before it is a letter or a digit,
// so the boundary failed and the key went out whole. Now the fence strips
// the token and leaves the escape before it exactly as it was. Thus the
// JSON still parses and the URL is still well formed.
func TestTokenAfterAnEscapeIsStripped(t *testing.T) {
	rules := loadShippedRules(t)
	for _, s := range keyShapes() {
		for _, extra := range []int{0, 3} {
			tok := s.make(extra)
			for _, esc := range []string{`\n`, `\t`, `\r`, `\"`, `\\`, `\u000a`, `\b`, `\f`} {
				t.Run(s.rule+" json "+esc, func(t *testing.T) {
					in := `{"k":"line` + esc + tok + `","n":1}`
					_, out := decideOut(t, rules, postBody("application/json", in))
					if want := `{"k":"line` + esc + StripRepl + `","n":1}`; out != want {
						t.Fatalf("got  %q\nwant %q", out, want)
					}
					if !json.Valid([]byte(out)) {
						t.Fatalf("not JSON any more: %q", out)
					}
				})
			}
			for _, enc := range []string{"%20", "%3D", "%0A", "%0a", "+"} {
				t.Run(s.rule+" query "+enc, func(t *testing.T) {
					target, _ := decideOut(t, rules, "GET /x?q=a"+enc+tok+"&b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
					if want := "/x?q=a" + enc + StripRepl + "&b=1"; target != want {
						t.Fatalf("got  %q\nwant %q", target, want)
					}
				})
				t.Run(s.rule+" form "+enc, func(t *testing.T) {
					_, out := decideOut(t, rules, postBody("application/x-www-form-urlencoded", "a=1&k=x"+enc+tok+"&z=2"))
					if want := "a=1&k=x" + enc + StripRepl + "&z=2"; out != want {
						t.Fatalf("got  %q\nwant %q", out, want)
					}
				})
			}
		}
	}
}

// A distinctive prefix glued to letters or digits is still the key: the
// glue stays and the fence strips the token. The prefix of a bounded rule
// glued to a word is a word, and the fence does not change it.
func TestTokenGluedToAWord(t *testing.T) {
	rules := loadShippedRules(t)
	for _, s := range keyShapes() {
		tok := s.make(2)
		for _, glue := range []string{"xyz", "123", "_"} {
			_, out := decideOut(t, rules, postBody("text/plain", "see "+glue+tok+" end"))
			want := "see " + glue + StripRepl + " end"
			if boundedRules[s.rule] {
				want = "see " + glue + tok + " end"
			}
			if out != want {
				t.Errorf("%s glued to %q:\ngot  %q\nwant %q", s.rule, glue, out, want)
			}
		}
	}
}

// The stream judges the context before a token across read boundaries.
// The escape can be emitted some reads earlier. The stream must strip
// exactly what the buffered path strips, and keep the escape.
func TestStreamStripsAfterAnEscapeLikeBuffered(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	rng := rand.New(rand.NewPCG(21, 22))
	for _, s := range keyShapes() {
		tok := s.make(5)
		var sb strings.Builder
		sb.WriteString(strings.Repeat("z", 1500))
		for _, c := range []string{`\n`, `\t`, `\r`, `\"`, `\\`, `\u000a`, "%20", "%3D", "%0A", "+", "xyz", " "} {
			sb.WriteString(`{"k":"a` + c + tok + `"} `)
		}
		sb.WriteString(strings.Repeat("q", 1500))
		inner := sb.String()
		for range 4 {
			want, got, werr, gerr := bothPaths(t, ctx, pol, inner, rng)
			if werr != nil || gerr != nil {
				t.Fatalf("%s: %v / %v", s.rule, werr, gerr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: stream and buffered disagree:\n%q\n%q", s.rule, got, want)
			}
			// Only the glued copy of a bounded rule's token stays, whole.
			left := bytes.ReplaceAll(want, []byte("xyz"+tok), nil)
			if n := bytes.Count(want, []byte("xyz"+tok)); boundedRules[s.rule] != (n == 1) || bytes.Contains(left, []byte(tok[len(tok)-6:])) {
				t.Fatalf("%s: %d glued copies kept, or a tail left: %q", s.rule, n, want)
			}
			for _, c := range []string{`a\n`, `a\u000a`, "a%0A", "a+"} {
				if !bytes.Contains(want, []byte(c+StripRepl)) {
					t.Fatalf("%s: %q before the token was not kept: %q", s.rule, c, want)
				}
			}
		}
	}
}

// AWS key ids are upper case. In upper case, the rule takes the key to its
// natural end at any start position. In all other cases, only the exact
// length counts. Thus the rule still catches a case-flipped key, but an
// identifier or a domain name in mixed or lower case that starts with asia
// or akia is not a key.
func TestAWSRulesAndCase(t *testing.T) {
	ts := tokensFor(loadShippedRules(t).All())
	key := "AKIA" + fill(upperD, 16)
	for _, c := range []struct{ pre, tok, post string }{
		{"", key, ""}, {"", key + fill(upperD, 9), " "}, {"(", "ASIA" + fill(upperD, 30), ")"},
		{"x=", key, "&y"}, {"", strings.ToLower(key), ""}, {"", "AkIa" + strings.ToLower(fill(upperD, 16)), "."},
		{`\n`, strings.ToLower(key), `"`}, {"glued", key, ""},
	} {
		in := c.pre + c.tok + c.post
		if out := string(ts.replace([]byte(in), stripRepl)); out != c.pre+StripRepl+c.post {
			t.Errorf("%q: %q", in, out)
		}
	}
	for _, s := range []string{
		"AsiaPacificSoutheastRegion", "asiapacificcommunications", "trustAsiaSHA384Intermediate",
		"asianfoodnetworkrecipes", "akiapolaawlongnamehere", "Asia/Kolkata",
		strings.ToLower(key) + "x",
	} {
		if out := ts.replace([]byte(s), stripRepl); string(out) != s {
			t.Errorf("%q was stripped: %q", s, out)
		}
	}
}
