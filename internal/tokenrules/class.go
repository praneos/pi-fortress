package tokenrules

import "regexp/syntax"

// InTokenClass reports whether c is a token byte: an ASCII letter, a digit,
// '_', '-' or '.'. The fence ends the strip of a long token at the end of
// its run of token bytes. Thus a rule must match only these bytes
// (Streamable).
func InTokenClass(c byte) bool {
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
			if !InTokenClass(byte(c)) {
				return false
			}
		}
	}
	return true
}

// bounds is the shortest string this node can match, and whether every
// byte it can match is in the token class. An operator that it does not
// know gives false.
func bounds(r *syntax.Regexp) (int, bool) {
	// The lead is judged on the bytes before the prefix. span and the window
	// supply those bytes. The lead adds nothing to the length of a match.
	if IsLead(r) {
		return 0, true
	}
	switch r.Op {
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine:
		return 0, true
	case syntax.OpLiteral:
		for _, c := range r.Rune {
			if c > 0x7f || !InTokenClass(byte(c)) {
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

// MatchBounds gives the shortest match of expr, and whether each byte
// that expr can match is in the token class (InTokenClass). ok is false
// for an expr that does not parse or that can match the empty string.
func MatchBounds(expr string) (minLen int, ok bool) {
	r, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return 0, false
	}
	n, ok := bounds(r.Simplify())
	return n, ok && n > 0
}
