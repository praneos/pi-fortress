package tokenrules

import (
	"bytes"
	"regexp/syntax"
)

// PrefixInfo returns the literal prefix of each branch of expr, then for
// each branch whether it starts with the lead of a rule (leadExpr), then
// whether any prefix matches either ASCII case, then whether each branch
// has a prefix. A lead needs the bytes before the prefix.
func PrefixInfo(expr string) ([][]byte, []bool, bool, bool) {
	r, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, nil, false, false
	}
	r = r.Simplify()
	branches := []*syntax.Regexp{r}
	if r.Op == syntax.OpAlternate {
		branches = r.Sub
	}
	var out [][]byte
	var lead []bool
	fold := false
	for _, br := range branches {
		p, f, ok := branchPrefix(br)
		if !ok || len(p) == 0 {
			return nil, nil, false, false
		}
		out = append(out, p)
		lead = append(lead, br.Op == syntax.OpConcat && len(br.Sub) > 1 && IsLead(br.Sub[0]))
		fold = fold || f
	}
	// One fold search for the full set. A folded search for an exact prefix
	// finds a superset. This costs a candidate, never a match.
	if fold {
		for i, p := range out {
			out[i] = bytes.ToLower(p)
		}
	}
	return out, lead, fold, true
}

// branchPrefix is the literal at the start of the match of a branch, and
// whether any of it matches either ASCII case: a (?i) literal, or a [Kk]
// class. foldASCII uses this class for the two letters whose Unicode fold
// goes past ASCII.
func branchPrefix(r *syntax.Regexp) ([]byte, bool, bool) {
	for r.Op == syntax.OpCapture {
		r = r.Sub[0]
	}
	// The lead of a rule (leadExpr) comes before its prefix and is not part
	// of it. The literal is what follows.
	if r.Op == syntax.OpConcat && len(r.Sub) > 1 && IsLead(r.Sub[0]) {
		if len(r.Sub) == 2 {
			return branchPrefix(r.Sub[1])
		}
		return branchPrefix(&syntax.Regexp{Op: syntax.OpConcat, Sub: r.Sub[1:]})
	}
	subs := []*syntax.Regexp{r}
	if r.Op == syntax.OpConcat {
		subs = r.Sub
	}
	var lit []byte
	fold := false
	for _, s := range subs {
		switch s.Op {
		case syntax.OpWordBoundary, syntax.OpBeginText, syntax.OpBeginLine, syntax.OpEmptyMatch:
			continue
		case syntax.OpLiteral:
			if s.Flags&syntax.FoldCase != 0 {
				if !asciiRunes(s.Rune) {
					return lit, fold, len(lit) > 0
				}
				fold = true
			}
			lit = append(lit, string(s.Rune)...)
			continue
		case syntax.OpCharClass:
			if c, ok := casePair(s.Rune); ok {
				lit = append(lit, c)
				fold = true
				continue
			}
		}
		break
	}
	return lit, fold, len(lit) > 0
}

func asciiRunes(rs []rune) bool {
	for _, r := range rs {
		if r >= 0x80 {
			return false
		}
	}
	return true
}

// casePair reports a class that is one ASCII letter in both cases, [Kk],
// as that letter in lower case.
func casePair(rs []rune) (byte, bool) {
	if len(rs) != 4 || rs[0] != rs[1] || rs[2] != rs[3] {
		return 0, false
	}
	up, lo := rs[0], rs[2]
	if up < 'A' || up > 'Z' || lo != up+'a'-'A' {
		return 0, false
	}
	return byte(lo), true
}
