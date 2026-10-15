// Package secretscan finds credentials that must not be in the tree or in a
// release binary. It is the leak check of the release gate. It also runs in
// each `go test ./...`. Thus the scan finds a key at the commit that adds it,
// not at the release that would publish it.
//
// A pattern match is a finding only when its body looks random. The tree has
// many key-shaped fixtures: the all-A canary, ghp_ABCDEF..., a planted leak
// in the export test. The string table of a Go binary puts the token
// prefixes that the fence knows side by side. That reads as
// "sk-ant-oat01-sk-ant-ort01-refresh_token...". People would disable a rule
// that flagged those within a week. They would not disable a rule that asks
// if the body can be a real key.
package secretscan

import (
	"math"
	"regexp"
)

// A rule is a credential shape: the full match, and the part of it that
// is the secret.
type rule struct {
	name string
	re   *regexp.Regexp
	// min is the shortest body that a real key has.
	min int
}

var rules = []rule{
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)`), 64},
	{"anthropic", regexp.MustCompile(`sk-ant-[a-z]+[0-9]{2}-([A-Za-z0-9_-]+)`), 40},
	{"openai", regexp.MustCompile(`\bsk-(?:proj-)?([A-Za-z0-9_-]{40,})`), 40},
	{"xai", regexp.MustCompile(`\bxai-([A-Za-z0-9]{40,})`), 40},
	{"github", regexp.MustCompile(`\bgh[pousr]_([A-Za-z0-9]{36,})`), 36},
	{"aws", regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`), 20},
	{"wireguard", regexp.MustCompile(`PrivateKey\s*=\s*([A-Za-z0-9+/]{42,43}=)`), 43},
	{"slack", regexp.MustCompile(`\bxox[baprs]-([A-Za-z0-9-]{20,})`), 20},
}

// Hit is one finding. Secret is shortened for the report. A scanner that
// prints the key that it found leaks it a second time, into CI logs.
type Hit struct {
	Rule   string
	Offset int
	Secret string
}

// Scan returns each match in b with a body that can be a real credential.
func Scan(b []byte) []Hit {
	var out []Hit
	for _, r := range rules {
		for _, m := range r.re.FindAllSubmatchIndex(b, -1) {
			body := compact(b[m[2]:m[3]])
			if len(body) < r.min || !random(body) {
				continue
			}
			out = append(out, Hit{Rule: r.name, Offset: m[0], Secret: string(body[:6]) + "..."})
		}
	}
	return out
}

func compact(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			out = append(out, c)
		}
	}
	return out
}

// random tells that the body is not a fixture: more than a few different
// characters, not mostly an ascending run like ABCDEF..., and an entropy
// for each character of at least log2(n) - 1.4 over its first n <= 64. A
// short sample cannot get to the full entropy of the alphabet. Thus the
// floor changes with n. Over 20000 random letters-and-digits bodies, the
// 0.01st percentile is 4.08 at n=36 (floor 3.77) and 4.72 at n=64 (floor
// 4.60). Identifiers joined together, as in the string table of a binary,
// measured 4.06 at n=64.
func random(body []byte) bool {
	if len(body) > 64 {
		body = body[:64]
	}
	seen := map[byte]int{}
	run := 0
	for i, c := range body {
		seen[c]++
		if i > 0 && c == body[i-1]+1 {
			run++
		}
	}
	if len(seen) <= 4 || run*2 >= len(body) {
		return false
	}
	h := 0.0
	for _, n := range seen {
		p := float64(n) / float64(len(body))
		h -= p * math.Log2(p)
	}
	return h >= math.Log2(float64(len(body)))-1.4
}
