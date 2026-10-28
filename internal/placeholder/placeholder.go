// Package placeholder finds the placeholders of the gateway in bytes. A
// placeholder is pf_<16 hex>_<kind>. The package imports nothing from this
// repo, so a daemon that only looks for placeholders in a name or a body
// does not link the credential store.
package placeholder

import (
	"bytes"
	"strings"
)

const phPrefix = "pf_"

// IsPlaceholder reports whether v is one whole exact placeholder and
// nothing else. A prefix test would also accept a live value that only
// starts with "pf_" as a placeholder.
func IsPlaceholder(v string) bool {
	b := []byte(v)
	sp := FindPlaceholderSpans(b)
	return len(sp) == 1 && sp[0] == [2]int{0, len(v)} && PlaceholderExact(b, sp[0])
}

// FindPlaceholderSpans returns [start,end) of each placeholder in b, in
// any letter case. It matches pf_<16 hex>_<kind>: the prefix in any case,
// and the kind is a letter and then a maximal run of [A-Za-z0-9_]. The
// slot ID is the secret part. An origin can change the case back, or
// remove a letter that the agent added. Thus a span is also each such
// variant of a placeholder. The fence substitutes only an exact span
// (PlaceholderExact). It refuses each other span as it refuses a
// placeholder in a forbidden place. No regexp: one index for each
// candidate.
func FindPlaceholderSpans(b []byte) [][2]int {
	var out [][2]int
	for i := 0; i < len(b); {
		j := indexPrefix(b[i:])
		if j < 0 {
			break
		}
		s := i + j
		if e, ok := placeholderEnd(b, s); ok {
			out = append(out, [2]int{s, e})
			i = e
		} else {
			i = s + 1
		}
	}
	return out
}

// PlaceholderExact reports whether the span is a placeholder as the
// gateway writes it: the prefix "pf_" and a kind of [A-Z0-9_] only. The
// slot hex can be in either case. Only an exact span gets a live value.
func PlaceholderExact(b []byte, span [2]int) bool {
	if string(b[span[0]:span[0]+len(phPrefix)]) != phPrefix {
		return false
	}
	for _, c := range b[span[0]+len(phPrefix)+17 : span[1]] {
		if c >= 'a' && c <= 'z' {
			return false
		}
	}
	return true
}

// TrailingPlaceholders returns the start of the placeholder that ends
// exactly at len(b), or len(b) when no placeholder ends there. Each byte
// of a span is in [A-Za-z0-9_], and the kind run is maximal. Thus a span
// that ends at len(b) is in the last run of such bytes. It is the first
// span in that run, because it takes the run to its end. Two spans are
// never adjacent: a span ends before a byte outside the run, and a span
// starts with p or P.
func TrailingPlaceholders(b []byte) int {
	r := len(b)
	for r > 0 && isWord(b[r-1]) {
		r--
	}
	if sp := FindPlaceholderSpans(b[r:]); len(sp) > 0 && r+sp[0][1] == len(b) {
		return r + sp[0][0]
	}
	return len(b)
}

// PlaceholderHold reports how many trailing bytes of b may still belong
// to a placeholder whose end has not arrived: from the earliest pf_
// candidate (any case) that b cannot settle, or a partial prefix exactly
// at the end. A streamed scan may emit all bytes before them. What it
// emits can never be the head of a placeholder that the next read
// completes.
func PlaceholderHold(b []byte) int {
	for i := 0; i < len(b); {
		j := indexPrefix(b[i:])
		if j < 0 {
			break
		}
		s := i + j
		if placeholderOpen(b, s) {
			return len(b) - s
		}
		i = s + 1
	}
	for k := min(len(phPrefix)-1, len(b)); k > 0; k-- {
		if hasPrefixFold(b[len(b)-k:], phPrefix[:k]) {
			return k
		}
	}
	return 0
}

// placeholderOpen says whether the candidate at s is still undecided:
// each byte so far fits the shape, and b ends before the byte that
// would settle it. placeholderEnd is the closed form of the same rule.
func placeholderOpen(b []byte, s int) bool {
	p := s + len(phPrefix)
	for k := 0; k < 17; k++ {
		if p+k >= len(b) {
			return true
		}
		if k < 16 && !isHex(b[p+k]) || k == 16 && b[p+k] != '_' {
			return false
		}
	}
	k := p + 17
	if k >= len(b) {
		return true
	}
	if !isLetter(b[k]) {
		return false
	}
	e := k + 1
	for e < len(b) && isWord(b[e]) {
		e++
	}
	return e == len(b)
}

func placeholderEnd(b []byte, s int) (int, bool) {
	p := s + len(phPrefix)
	if p+18 > len(b) {
		return 0, false
	}
	for k := 0; k < 16; k++ {
		if !isHex(b[p+k]) {
			return 0, false
		}
	}
	if b[p+16] != '_' {
		return 0, false
	}
	k := p + 17
	if !isLetter(b[k]) {
		return 0, false
	}
	e := k + 1
	for e < len(b) && isWord(b[e]) {
		e++
	}
	return e, true
}

// indexPrefix returns the index of the first "pf_" in b, in any letter
// case, or -1.
func indexPrefix(b []byte) int {
	for i := 0; ; {
		j := bytes.IndexByte(b[i:], '_')
		if j < 0 {
			return -1
		}
		u := i + j
		if u >= 2 && hasPrefixFold(b[u-2:u], "pf") {
			return u - 2
		}
		i = u + 1
	}
}

// hasPrefixFold reports whether b starts with the lower-case ASCII
// string p, in any letter case.
func hasPrefixFold(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != p[i] {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func isWord(c byte) bool {
	return isLetter(c) || (c >= '0' && c <= '9') || c == '_'
}

// PlaceholderParts splits the placeholder at span into its slot ID,
// lowercased as the store holds it, and its kind as written.
func PlaceholderParts(b []byte, span [2]int) (slot, kind string) {
	slot = strings.ToLower(string(b[span[0]+len(phPrefix) : span[0]+len(phPrefix)+16]))
	kind = string(b[span[0]+len(phPrefix)+17 : span[1]])
	return slot, kind
}
