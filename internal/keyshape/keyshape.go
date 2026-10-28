// Package keyshape finds a key or a placeholder of the gateway in a DNS
// name. pf dns refuses such a name before it forwards it. pf observe runs
// the same check on the rows of a plain segment and alerts. The engine and
// the broker use Match on the SNI of each connection, and the broker uses
// Tail for its log row. One copy of the
// code makes sure that each of them sees the same names.
package keyshape

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode/utf8"

	"pi-fortress/internal/secrets"
	"pi-fortress/internal/tokenrules"
)

// Heads returns the literal heads of rules, "pf_" included, for the
// prefilter of Match. Each head is lower case, because the rules match
// either case. Match lowers the name before it looks for a head. A rule
// with no literal head cannot be prefiltered. For that rule, Heads returns
// nil heads and the name of the rule.
func Heads(rules []tokenrules.Rule) (heads []string, headless string) {
	heads = []string{"pf_"}
	for _, r := range rules {
		p := r.Head()
		if p == "" {
			return nil, r.Name
		}
		heads = append(heads, p)
	}
	return heads, ""
}

// Match reports the rule for a key in a DNS name. It reports
// "placeholder" for a placeholder of the gateway, or "" for neither. Match
// tries each run of consecutive labels, of any length, with its dots
// removed. Thus a key split across any number of labels is whole again. A
// name that holds none of heads costs one pass and no regexp. nil heads
// disables the prefilter.
func Match(all *regexp.Regexp, heads []string, name string) string {
	if name == "" {
		return ""
	}
	// first is the earliest head in the name with no dots. No match ends
	// at or before it.
	first := 0
	if heads != nil {
		// Lowered for the prefilter only. The rules fold case themselves.
		// The placeholder check folds case itself.
		nodots := strings.ReplaceAll(name, ".", "")
		flat := strings.ToLower(nodots)
		hit := false
		for _, p := range heads {
			if strings.Contains(flat, p) {
				hit = true
				break
			}
		}
		if !hit {
			return ""
		}
		// A lower case of a different length moves the offsets.
		if len(flat) == len(nodots) {
			first = len(flat)
			for _, p := range heads {
				if i := strings.Index(flat, p); i >= 0 && i < first {
					first = i
				}
			}
		}
	}
	return runsMatch(strings.Split(strings.TrimSuffix(name, "."), "."), all, heads, first)
}

// runsMatch returns the first rule that a run of labels matches. A run is
// a part of j, the labels with no dots, from a label start to a label end.
// A name can have 127 labels, so runsMatch does not try each run. These
// passes find the same matches:
//
//  1. j. A match that does not touch the start or the end of its run is
//     also a match in j. The pass starts at a label start before the first
//     head, as far back as the longest lead of a rule.
//  2. j from each label start that has a head, with all anchored at the
//     start. A match that needs the start of its run (the lead \A of a
//     rule) starts there, with the head of its rule.
//  3. j to each label end after the first head, with the rules that
//     examine the byte after a match (a closing \b), and the placeholder
//     check. Only a match that ends at the run end can need that end.
//  4. Each pair of a label start from pass 2 and a later label end, with
//     the rules of pass 3, anchored at the start. This is for a match that
//     needs both.
//
// The last label is the location of the TLD. A run can include the last
// label only when that label does not have the shape of a TLD. Reason: a
// real name must still resolve when its TLD completes a shape after the
// dot is removed (asiakuecheerlangen.de is "asia" and 16 letters). Also,
// a sender who selects the last label selects one that no registry
// delegated. runsMatch always tries the last label alone. No TLD is long
// enough to be a key. Before, a key that was the last label was forwarded
// and logged whole.
func runsMatch(labels []string, all *regexp.Regexp, heads []string, first int) string {
	n := len(labels)
	if n > 1 && tldShaped(labels[n-1]) {
		if r := Rule(all, labels[n-1]); r != "" {
			return r
		}
		labels = labels[:n-1]
	}
	j := strings.Join(labels, "")
	f := formsOf(all)
	// A DNS name has at most 127 labels. Thus the two lists stay on the
	// stack for each real name.
	var startBuf, endBuf [128]int
	starts, ends := startBuf[:0], endBuf[:0]
	off, last, from := 0, 0, 0
	for _, l := range labels {
		off += len(l)
		if off == 0 || off == len(j) || off == last {
			continue
		}
		last = off
		if f.lead >= 0 && off <= first-f.lead {
			from = off
		}
		if off > first {
			ends = append(ends, off)
		}
		if headAt(j[off:], heads) {
			starts = append(starts, off)
		}
	}
	if r := Rule(all, j[from:]); r != "" {
		return r
	}
	if f.anch != nil {
		for _, s := range starts {
			if r := Rule(f.anch, j[s:]); r != "" {
				return r
			}
		}
	}
	for _, e := range ends {
		if r := Rule(f.ends, j[from:e]); r != "" {
			return r
		}
		if f.endsAnch == nil {
			continue
		}
		for _, s := range starts {
			if s >= e {
				break
			}
			if r := Rule(f.endsAnch, j[s:e]); r != "" {
				return r
			}
		}
	}
	return ""
}

// headAt reports whether s starts with one of heads, in either ASCII case.
// The rules fold only ASCII case. A head with other bytes always counts,
// so that a fold of a different length cannot hide it. With nil heads,
// each label is a start.
func headAt(s string, heads []string) bool {
	if heads == nil {
		return true
	}
	for _, h := range heads {
		if len(s) >= len(h) && strings.EqualFold(s[:len(h)], h) {
			return true
		}
		for i := 0; i < len(h); i++ {
			if h[i] >= 0x80 {
				return true
			}
		}
	}
	return false
}

// forms are the regexps that runsMatch derives from one rule set: all
// anchored at the start (anch), the rules that examine the byte after a
// match (ends), and ends anchored at the start (endsAnch). A nil ends
// means that no rule does that. Then only the placeholder check runs in
// pass 3. lead is the most bytes that a rule can match before its head,
// or -1 for no limit.
type forms struct {
	anch, ends, endsAnch *regexp.Regexp
	lead                 int
}

var (
	formCache sync.Map
	noForms   = forms{lead: -1}
)

// formsOf derives and caches the forms of all. A rule set is loaded once
// and used for each name. If a form does not compile, formsOf uses all in
// its place. That is slower but finds the same keys.
func formsOf(all *regexp.Regexp) *forms {
	if all == nil {
		return &noForms
	}
	if v, ok := formCache.Load(all); ok {
		return v.(*forms)
	}
	f := &forms{anch: all, ends: all, endsAnch: all, lead: -1}
	if re, err := regexp.Compile(`\A(?:` + all.String() + `)`); err == nil {
		f.anch, f.endsAnch = re, re
	}
	if expr, lead, ok := endRules(all.String()); ok {
		f.lead = lead
		if expr == "" {
			f.ends, f.endsAnch = nil, nil
		} else if re, err := regexp.Compile(expr); err == nil {
			if a, err := regexp.Compile(`\A(?:` + expr + `)`); err == nil {
				f.ends, f.endsAnch = re, a
			}
		}
	}
	v, _ := formCache.LoadOrStore(all, f)
	return v.(*forms)
}

// endRules returns the branches of expr (one branch for each rule) that
// contain an assertion on the text after it. It also returns the most
// bytes that a branch can match before its named group, where the head
// is, or -1 for no limit. It reports false if expr does not parse.
func endRules(expr string) (string, int, bool) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", -1, false
	}
	branches := []*syntax.Regexp{re}
	if re.Op == syntax.OpAlternate {
		branches = re.Sub
	}
	var out []string
	lead := 0
	for _, b := range branches {
		if endAssert(b) {
			out = append(out, b.String())
		}
		if n := beforeGroup(b); n < 0 || lead < 0 {
			lead = -1
		} else {
			lead = max(lead, n)
		}
	}
	return strings.Join(out, "|"), lead, true
}

// beforeGroup is the most bytes that re can match before its first
// capture group, or -1 for no limit or no group.
func beforeGroup(re *syntax.Regexp) int {
	if re.Op == syntax.OpCapture {
		return 0
	}
	if re.Op != syntax.OpConcat {
		return -1
	}
	n := 0
	for _, s := range re.Sub {
		if s.Op == syntax.OpCapture {
			return n
		}
		m := maxLen(s)
		if m < 0 {
			return -1
		}
		n += m
	}
	return -1
}

// maxLen is the most bytes that re can match, or -1 for no limit. Each
// rune counts as utf8.UTFMax bytes.
func maxLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		return utf8.UTFMax * len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxLen(re.Sub[0])
	case syntax.OpRepeat:
		m := maxLen(re.Sub[0])
		if re.Max < 0 || m < 0 {
			return -1
		}
		return m * re.Max
	case syntax.OpConcat, syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			m := maxLen(s)
			if m < 0 {
				return -1
			}
			if re.Op == syntax.OpConcat {
				n += m
			} else {
				n = max(n, m)
			}
		}
		return n
	}
	return -1
}

func endAssert(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpEndText, syntax.OpEndLine:
		return true
	}
	for _, s := range re.Sub {
		if endAssert(s) {
			return true
		}
	}
	return false
}

// tldShaped reports whether a label is one that a registry could have
// delegated: letters only and no longer than the longest TLD (24, the
// xn-- form of an IDN), or an IDN.
func tldShaped(l string) bool {
	if strings.HasPrefix(strings.ToLower(l), "xn--") {
		return true
	}
	if len(l) < 2 || len(l) > 24 {
		return false
	}
	for i := 0; i < len(l); i++ {
		if c := l[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// Rule names the rule of all that matches s, "placeholder" for a
// placeholder of the gateway in any letter case, or "" for neither. It reports "key" for a
// match in a group with no name. A nil all checks for placeholders only.
func Rule(all *regexp.Regexp, s string) string {
	if strings.IndexByte(s, '_') >= 0 && len(secrets.FindPlaceholderSpans([]byte(s))) > 0 {
		return "placeholder"
	}
	if all == nil {
		return ""
	}
	m := all.FindStringSubmatchIndex(s)
	if m == nil {
		return ""
	}
	for g, n := range all.SubexpNames() {
		if n != "" && m[2*g] >= 0 {
			return n
		}
	}
	return "key"
}

// Tail is the last two labels of name, the zone that an attacker had to
// register. A log row can show it in place of a name that carried a key.
// The caller must check Tail for a key too.
func Tail(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) > 2 {
		labels = labels[len(labels)-2:]
	}
	return strings.Join(labels, ".")
}
