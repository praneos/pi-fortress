package fence

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"pi-fortress/internal/corepolicy"
)

var ErrNoRules = errors.New("fence: key_prefixes.rules has no rules")

// A rule line is "name regexp [KIND]". The kind, when present, names the
// secrets kind that the rule detects. Thus a core host that injects that
// kind does not get a request to strip it.
type Rule struct{ Name, Expr, Kind string }

type TokenRules struct {
	Rules  []Rule
	all    *regexp.Regexp
	mu     sync.Mutex
	except map[string]*regexp.Regexp
}

// A missing or empty rules file is a hard error. The broker refuses to
// start. It does not run with a token regex that knows only one prefix.
func LoadTokenRules(path string) (*TokenRules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fence: %w", err)
	}
	tr := &TokenRules{except: map[string]*regexp.Regexp{}}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fs := strings.Fields(strings.TrimSpace(line))
		if len(fs) < 2 {
			continue
		}
		r := Rule{Name: fs[0], Expr: fs[1]}
		if len(fs) > 2 {
			r.Kind = fs[2]
		}
		tr.Rules = append(tr.Rules, r)
	}
	// A scan can stop early. An overlong line causes this. The scan then
	// keeps only the part of the file that it read. The rules that it did
	// not reach are the rules that would strip what they name. Nothing
	// downstream can tell a short ruleset from a full one, so no degraded
	// mode is possible. This code refuses a fence that strips less than
	// the operator wrote, exactly as it refuses the empty file below.
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("fence: %s: %w", path, err)
	}
	if len(tr.Rules) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoRules, path)
	}
	if tr.all, err = compile(tr.Rules, nil); err != nil {
		return nil, err
	}
	return tr, nil
}

func LoadTokenRE(path string) (*regexp.Regexp, error) {
	tr, err := LoadTokenRules(path)
	if err != nil {
		return nil, err
	}
	return tr.All(), nil
}

func (t *TokenRules) All() *regexp.Regexp { return t.all }

// Streamable refuses a rule with no literal prefix. Without a prefix, the
// stream scan cannot tell where a match can start. Then a body longer than
// maxHold goes out with only one window of hold behind it. The broker calls
// this at start. pf dns does not, because there a rule with no prefix
// costs speed, not a check.
func (t *TokenRules) Streamable() error {
	for _, r := range t.Rules {
		re, err := compile([]Rule{r}, nil)
		if err != nil {
			return err
		}
		if _, _, _, ok := prefixInfo(re.String()); !ok {
			return fmt.Errorf("fence: rule %s has no literal prefix; the stream scan needs one (example: ghp_[A-Za-z0-9]{36})", r.Name)
		}
	}
	return nil
}

// Except returns the rules whose kind is not in kinds, or nil when none
// remain. It caches the result per kind set. A core host sees the same set each time.
func (t *TokenRules) Except(kinds []string) *regexp.Regexp {
	// This uses KindAllowed, not a tag compare. Reason: a host with the
	// policy line "*" carries all kinds except CANARY, and the literal tag
	// match left all the named rules in its strip set. The streamed path
	// then stripped the credential that the fence had just injected. The
	// buffered path, which injects after it strips, kept it.
	skip := map[string]bool{}
	for _, r := range t.Rules {
		if r.Kind != "" && corepolicy.KindAllowed(r.Kind, kinds) {
			skip[r.Kind] = true
		}
	}
	key := append([]string(nil), kinds...)
	sort.Strings(key)
	ck := strings.Join(key, ",")
	t.mu.Lock()
	defer t.mu.Unlock()
	if re, ok := t.except[ck]; ok {
		return re
	}
	re, _ := compile(t.Rules, skip)
	t.except[ck] = re
	return re
}

func compile(rules []Rule, skip map[string]bool) (*regexp.Regexp, error) {
	var parts []string
	for _, r := range rules {
		if r.Kind != "" && skip[r.Kind] {
			continue
		}
		expr, lead, err := foldLead(r.Expr)
		if err != nil {
			return nil, fmt.Errorf("fence: rule %s: %w", r.Name, err)
		}
		part := "(?P<" + r.Name + ">" + expr + ")"
		if lead {
			part = "(?:" + leadExpr + ")" + part
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return regexp.Compile(strings.Join(parts, "|"))
}

// leadExpr is what the leading \b of a rule becomes: the start of the
// text, a non-word byte, or the end of an escape before a token. These
// escapes are \n \t \r \b \f, \xXX and \uXXXX (in a JSON or C string), or
// %XX in a URL. Each of those ends in a letter or a digit. Thus a plain \b
// failed after it, and a key at the start of a JSON line, or after %20 in
// a query, went out whole. leadExpr is outside the named group of the
// rule: the match includes it so the regexp can judge it, but the strip
// (tokenSet.span of the group) does not, and the escape stays unchanged.
// leadMax is its longest match: how far before a prefix the prefilter
// window must reach.
const (
	leadExpr = `\A|[^0-9A-Za-z_]|\\[bfnrt]|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}`
	leadMax  = 6
)

// leadCanon is leadExpr as it prints after parse and simplification. The
// prefilter uses this form to recognise it inside the compiled set.
var leadCanon = func() string {
	re, err := syntax.Parse(leadExpr, syntax.Perl)
	if err != nil {
		panic(err)
	}
	return re.Simplify().String()
}()

func isLead(re *syntax.Regexp) bool {
	return re.Op == syntax.OpAlternate && re.String() == leadCanon
}

// foldLead is foldASCII, but it also removes a leading \b from the rule and
// reports it, so compile can put leadExpr in its place.
func foldLead(expr string) (string, bool, error) {
	re, err := syntax.Parse(expr, syntax.Perl|syntax.FoldCase)
	if err != nil {
		return "", false, err
	}
	re = asciiFold(re)
	if re.Op == syntax.OpConcat && len(re.Sub) > 1 && re.Sub[0].Op == syntax.OpWordBoundary {
		rest := &syntax.Regexp{Op: syntax.OpConcat, Sub: re.Sub[1:]}
		if len(rest.Sub) == 1 {
			rest = rest.Sub[0]
		}
		return rest.String(), true, nil
	}
	return re.String(), false, nil
}

// Head is the fixed text at the start of each match of the rule, in lower
// case because the rules match either case. It is "" when the rule has none.
func (r Rule) Head() string {
	expr, err := foldASCII(r.Expr)
	if err != nil {
		return ""
	}
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return ""
	}
	p, _, _ := branchPrefix(re.Simplify())
	return strings.ToLower(string(p))
}

// foldASCII makes a rule match its letters in either ASCII case. DNS
// names are case-insensitive. Thus akia..., Ghp_... or Sk-ant-api03-... in
// a query label gets to the server of the zone as sent, and the receiver
// folds it back. The same flip got a key past the strip rules on HTTP.
// Each consumer (the fence, pf dns, the fake-IP SNI check of the broker)
// compiles through here, so they all fold the same way.
//
// Why not (?i): Go folds Unicode, so (?i)k also matches the Kelvin sign
// and (?i)s matches the long s. A key spelled with those is an encoding,
// not a case flip. It would also put multi-byte runes into the rules. That
// disables the length prefilter of the fence and splits it from the full
// regexp. Thus this code parses the rule folded and then removes those two
// runes: letters become [Xx], and a class loses U+017F and U+212A.
func foldASCII(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl|syntax.FoldCase)
	if err != nil {
		return "", err
	}
	return asciiFold(re).String(), nil
}

func asciiFold(re *syntax.Regexp) *syntax.Regexp {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase == 0 {
			return re
		}
		subs := make([]*syntax.Regexp, 0, len(re.Rune))
		for _, r := range re.Rune {
			lo, up := unicode.ToLower(r), unicode.ToUpper(r)
			switch {
			case r < utf8.RuneSelf && lo != up:
				subs = append(subs, &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{up, up, lo, lo}})
			case unicode.SimpleFold(r) == r:
				subs = append(subs, &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{r}, Flags: re.Flags &^ syntax.FoldCase})
			default:
				subs = append(subs, &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{r}, Flags: re.Flags})
			}
		}
		if len(subs) == 1 {
			return subs[0]
		}
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
	case syntax.OpCharClass:
		re.Rune = dropRune(dropRune(re.Rune, 0x17F), 0x212A)
		return re
	}
	for i, sub := range re.Sub {
		re.Sub[i] = asciiFold(sub)
	}
	return re
}

// dropRune removes r from a class's sorted [lo, hi] pairs.
func dropRune(ranges []rune, r rune) []rune {
	out := make([]rune, 0, len(ranges)+2)
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if r < lo || r > hi {
			out = append(out, lo, hi)
			continue
		}
		if lo < r {
			out = append(out, lo, r-1)
		}
		if r < hi {
			out = append(out, r+1, hi)
		}
	}
	return out
}
