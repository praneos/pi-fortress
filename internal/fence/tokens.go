package fence

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/tokenrules"
)

// tokenSet puts a literal prefilter in front of a token-prefix regexp.
// Each rule in key_prefixes.rules starts with a fixed literal (ghp_, AKIA,
// sk-ant-oat01-), matched in either case (foldASCII). A memchr for one
// byte of it is SIMD. The regexp is an NFA without backtracking, but slow.
// Run the regexp only when a literal is present. If a branch has no
// literal prefix, the prefilter is disabled and the regexp always runs.
type tokenSet struct {
	re        *regexp.Regexp
	prefixes  [][]byte
	complete  bool
	maxPrefix int
	// fold says that the rules match their prefixes in either ASCII case
	// (foldASCII). Thus prefixes are lower case, and the search is folded.
	fold bool
	// minLen is the shortest match that any branch can make. bounded says
	// that each branch is written from tokenClass only. Together they turn
	// a prefix hit that cannot complete — "ghp_short", "AKIA!" — into a few
	// byte comparisons, not an NFA pass over a 4 KiB window. A rules file
	// that goes outside the class loses the check. It does not lose a
	// match.
	minLen  int
	bounded bool
	// lead says, for each prefix, that a rule that starts with it has a lead
	// (tokenrules.leadExpr). Thus its window starts tokenrules.LeadMax
	// bytes early, so the lead sees the escape.
	lead []bool
}

var tokenCache sync.Map

func tokensFor(re *regexp.Regexp) *tokenSet {
	if re == nil {
		return nil
	}
	if v, ok := tokenCache.Load(re); ok {
		return v.(*tokenSet)
	}
	ts := &tokenSet{re: re}
	var all [][]byte
	var lead []bool
	all, lead, ts.fold, ts.complete = tokenrules.PrefixInfo(re.String())
	ts.minLen, ts.bounded = matchBounds(re.String())
	for _, p := range all {
		if len(p) > ts.maxPrefix {
			ts.maxPrefix = len(p)
		}
	}
	ts.prefixes = dropCovered(all)
	ts.lead = leadsFor(ts.prefixes, all, lead)
	v, _ := tokenCache.LoadOrStore(re, ts)
	return v.(*tokenSet)
}

func literalPrefixes(expr string) ([][]byte, bool, bool) {
	out, _, fold, ok := tokenrules.PrefixInfo(expr)
	return out, fold, ok
}

// leadsFor says, for each searched prefix, whether a rule for which it opens
// a window has a lead. Such a rule is any branch whose prefix starts with it.
func leadsFor(searched, all [][]byte, lead []bool) []bool {
	out := make([]bool, len(searched))
	for i, p := range searched {
		for j, q := range all {
			if lead[j] && bytes.HasPrefix(q, p) {
				out[i] = true
			}
		}
	}
	return out
}

// dropCovered keeps one search per start. A prefix that starts with a
// different prefix in the set (sk-ant-api03- after sk-) opens a window only
// where the shorter one already did. Thus a second search for it gives the
// same hits for one more pass over the body. maxPrefix is set before this,
// because the split-prefix margin of the stream is about the longest
// literal that a rule needs, not the longest one in the search.
func dropCovered(ps [][]byte) [][]byte {
	sorted := append([][]byte(nil), ps...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i]) < len(sorted[j]) })
	var out [][]byte
next:
	for _, p := range sorted {
		for _, q := range out {
			if bytes.HasPrefix(p, q) {
				continue next
			}
		}
		out = append(out, p)
	}
	return out
}

// indexFold is httpwire.Index with ASCII case folded. needle is lower
// case. It scans for one byte of the needle in both cases and examines
// each hit. Thus a byte with no case (a digit, '_', '-') is the cheapest
// anchor: one memchr, not two.
func indexFold(src, needle []byte) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	if len(src) < n {
		return -1
	}
	k := foldAnchor(needle)
	lo := needle[k]
	up := lo
	if 'a' <= lo && lo <= 'z' {
		up = lo - 'a' + 'A'
	}
	// Byte k of a match sits in [k, end).
	end := len(src) - n + k + 1
	nl, nu := -1, -1
	for i := k; i < end; {
		if nl < i {
			nl = nextByte(src, i, end, lo)
		}
		if up == lo {
			nu = nl
		} else if nu < i {
			nu = nextByte(src, i, end, up)
		}
		p := min(nl, nu)
		if p >= end {
			return -1
		}
		if equalFoldASCII(src[p-k:p-k+n], needle) {
			return p - k
		}
		i = p + 1
	}
	return -1
}

func nextByte(src []byte, i, end int, c byte) int {
	if j := bytes.IndexByte(src[i:end], c); j >= 0 {
		return i + j
	}
	return end
}

func equalFoldASCII(b, lower []byte) bool {
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// foldAnchor picks the byte that indexFold scans for: a byte with no case,
// or else the letter that is most rare in ordinary text.
func foldAnchor(needle []byte) int {
	const letters = "etaoinsrhldcumfpgwybvkxjqz" // most to least frequent
	best, bestScore := 0, 1<<30
	for i, c := range needle {
		s := 2
		switch {
		case c == '-':
			s = 3
		case 'a' <= c && c <= 'z':
			s = 4 + 26 - strings.IndexByte(letters, c)
		}
		if s < bestScore {
			best, bestScore = i, s
		}
	}
	return best
}

// index is the prefix search the set was built for.
func (t *tokenSet) index(b, p []byte) int {
	if t.fold {
		return indexFold(b, p)
	}
	return httpwire.Index(b, p)
}

func inTokenClass(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '.'
}

func classWithin(r *syntax.Regexp) bool {
	for i := 0; i+1 < len(r.Rune); i += 2 {
		lo, hi := r.Rune[i], r.Rune[i+1]
		if lo < 0 || hi > 0x7f {
			return false
		}
		for c := lo; c <= hi; c++ {
			if !inTokenClass(byte(c)) {
				return false
			}
		}
	}
	return true
}

// bounds is the shortest string this node can match, and whether every
// byte it can match is in tokenClass.
func bounds(r *syntax.Regexp) (int, bool) {
	// The lead is judged on the bytes before the prefix. span and the window
	// supply those bytes. The lead adds nothing to the length of a match.
	if tokenrules.IsLead(r) {
		return 0, true
	}
	switch r.Op {
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine:
		return 0, true
	case syntax.OpLiteral:
		for _, c := range r.Rune {
			if c > 0x7f || !inTokenClass(byte(c)) {
				return len(r.Rune), false
			}
		}
		return len(r.Rune), true
	case syntax.OpCharClass:
		return 1, classWithin(r)
	case syntax.OpCapture:
		return bounds(r.Sub[0])
	case syntax.OpConcat:
		n, ok := 0, true
		for _, sub := range r.Sub {
			sn, sok := bounds(sub)
			n, ok = n+sn, ok && sok
		}
		return n, ok
	case syntax.OpAlternate:
		n, ok := -1, true
		for _, sub := range r.Sub {
			sn, sok := bounds(sub)
			if n < 0 || sn < n {
				n = sn
			}
			ok = ok && sok
		}
		return max(n, 0), ok
	case syntax.OpStar, syntax.OpQuest:
		_, ok := bounds(r.Sub[0])
		return 0, ok
	case syntax.OpPlus:
		return bounds(r.Sub[0])
	case syntax.OpRepeat:
		n, ok := bounds(r.Sub[0])
		return n * r.Min, ok
	}
	return 0, false
}

func matchBounds(expr string) (int, bool) {
	r, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return 0, false
	}
	n, ok := bounds(r.Simplify())
	return n, ok && n > 0
}

// window is the limit on how far past a literal prefix the regexp runs. No
// credential is a kilobyte long. A hit inside the window is complete, and
// the byte after it is present. Thus a trailing \b is judged on real text,
// not on the end of the window. The window starts one byte before the
// prefix, or tokenrules.LeadMax bytes before it for a rule with a lead.
// Thus the lead sees the escape before the prefix.
const window = 4096

// candidates returns sorted, merged [start,end) regions around every
// literal prefix hit, or nil,false when the prefilter is disabled.
func (t *tokenSet) candidates(b []byte) ([][2]int, bool) {
	if !t.complete {
		return nil, false
	}
	var wins [][2]int
	for i, p := range t.prefixes {
		back := 1
		if t.lead[i] {
			back = tokenrules.LeadMax
		}
		for k := 0; k < len(b); {
			j := t.index(b[k:], p)
			if j < 0 {
				break
			}
			s := k + j
			if hi, ok := t.span(b, s); ok {
				wins = append(wins, [2]int{max(s-back, 0), hi})
			}
			k = s + 1
		}
	}
	if len(wins) == 0 {
		return nil, true
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i][0] < wins[j][0] })
	var out [][2]int
	for _, w := range wins {
		if n := len(out); n > 0 && w[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], w[1])
			continue
		}
		out = append(out, w)
	}
	return out, true
}

// span is the slice that the NFA runs over for a prefix hit at s. Each rule
// is written from tokenClass, so a match that starts at s cannot go past
// the run of those bytes. The window ends one byte after the run. This
// gives the trailing \b real text to judge, and keeps the NFA off the
// kilobytes of ordinary body that used to follow each hit. ok is false
// when the run is too short for the shortest branch to complete —
// "ghp_short", "AKIA!". There, a body full of near-misses stops costing
// anything. A run that reaches the end of b stays, for any length: the
// remainder can still be in transit.
func (t *tokenSet) span(b []byte, s int) (int, bool) {
	lim := min(s+window, len(b))
	if !t.bounded {
		return lim, true
	}
	i := s
	for i < lim && inTokenClass(b[i]) {
		i++
	}
	if i-s < t.minLen && i < len(b) {
		return 0, false
	}
	return min(i+1, len(b)), true
}

// hit is the ok of span. It does not need the end of the run, so it stops
// after minLen bytes and does not walk a long run to the window edge.
func (t *tokenSet) hit(b []byte, s int) bool {
	if !t.bounded {
		return true
	}
	lim := min(s+window, len(b), s+t.minLen)
	i := s
	for i < lim && inTokenClass(b[i]) {
		i++
	}
	return i-s >= t.minLen || i == len(b)
}

// lasting says that the hit at s stays a hit when bytes come after b: its
// run already has minLen bytes. A hit with a shorter run that reaches the
// end of b can still end short.
func (t *tokenSet) lasting(b []byte, s int) bool {
	if !t.bounded {
		return true
	}
	if t.minLen > window || len(b)-s < t.minLen {
		return false
	}
	for _, c := range b[s : s+t.minLen] {
		if !inTokenClass(c) {
			return false
		}
	}
	return true
}

// matches returns FindAllSubmatchIndex over b, computed only inside
// candidate windows when the prefilter is complete.
func (t *tokenSet) matches(b []byte) [][]int {
	if t == nil {
		return nil
	}
	wins, ok := t.candidates(b)
	if !ok {
		return t.re.FindAllSubmatchIndex(b, -1)
	}
	var out [][]int
	for _, w := range wins {
		for _, m := range t.re.FindAllSubmatchIndex(b[w[0]:w[1]], -1) {
			for i := range m {
				if m[i] >= 0 {
					m[i] += w[0]
				}
			}
			out = append(out, m)
		}
	}
	return out
}

func (t *tokenSet) match(b []byte) bool {
	if t == nil {
		return false
	}
	wins, ok := t.candidates(b)
	if !ok {
		return t.re.Match(b)
	}
	for _, w := range wins {
		if t.re.Match(b[w[0]:w[1]]) {
			return true
		}
	}
	return false
}

func (t *tokenSet) replace(b []byte, repl []byte) []byte {
	ms := t.matches(b)
	if len(ms) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	pos := 0
	for _, m := range ms {
		lo, hi := t.token(m)
		out = append(out, b[pos:lo]...)
		out = append(out, repl...)
		pos = hi
	}
	return append(out, b[pos:]...)
}

// token is the part of match m that is the key: the named group of the
// rule. It does not include the lead (tokenrules.leadExpr) that a bounded
// rule matched before its prefix. A regexp with no named group is all token.
func (t *tokenSet) token(m []int) (int, int) {
	names := t.re.SubexpNames()
	for i := 1; 2*i+1 < len(m) && i < len(names); i++ {
		if m[2*i] >= 0 && names[i] != "" {
			return m[2*i], m[2*i+1]
		}
	}
	return m[0], m[1]
}

// ruleName names the rule one match belongs to.
func (t *tokenSet) ruleName(m []int) string {
	names := t.re.SubexpNames()
	for i := 1; 2*i+1 < len(m) && i < len(names); i++ {
		if m[2*i] >= 0 && names[i] != "" {
			return names[i]
		}
	}
	return "token"
}

// rules names the rule each match in b belongs to, in order.
func (t *tokenSet) rules(b []byte) []string {
	ms := t.matches(b)
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, t.ruleName(m))
	}
	return out
}

// firstPrefixFrom is the earliest literal-prefix hit at or after lo, or
// -1. The stream uses it to find the point after which a token can still
// be in transit. A search of only the tail keeps the cost independent of
// how much body is already buffered.
func (t *tokenSet) firstPrefixFrom(b []byte, lo int) int {
	best := -1
	for _, p := range t.prefixes {
		for k := lo; k < len(b); {
			j := t.index(b[k:], p)
			if j < 0 {
				break
			}
			s := k + j
			if t.hit(b, s) {
				if best < 0 || s < best {
					best = s
				}
				break
			}
			k = s + 1
		}
	}
	return best
}
