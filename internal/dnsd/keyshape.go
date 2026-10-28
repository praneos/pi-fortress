package dnsd

import (
	"log"
	"regexp"

	"pi-fortress/internal/keyshape"
	"pi-fortress/internal/tokenrules"
)

// keyShapes applies key_prefixes.rules of the fence to query names. The
// fence strips a live-looking key from all that it forwards over HTTP.
// But a name that the resolver forwards reaches the authoritative server
// of the zone at the end of the name. Nothing on that path was ever
// scanned. An agent told to look up <key>.evil.example sends the key there
// in the clear. The resolver refuses a name with a key before it forwards,
// caches or logs the name. Name forwarding is the one channel that the
// resolver pin leaves open.
//
// This check matches the key shapes in the name as written, as the fence
// does for HTTP. A key that is encoded first (base32, hex, reversed) is a
// different string and does not match. The tunnel alert in observe covers
// names of that kind.
type keyShapes struct {
	all *regexp.Regexp
	// prefixes are the literal heads of the rules, "pf_" included. A name
	// that holds none of them costs one pass and no regexp.
	prefixes []string
}

func loadKeyShapes(path string) (*keyShapes, error) {
	tr, err := tokenrules.LoadTokenRules(path)
	if err != nil {
		return nil, err
	}
	heads, headless := keyshape.Heads(tr.Rules)
	if headless != "" {
		// Every name must go to the regexp. A message is better than a silent
		// miss. One line at load tells why the hot path of the resolver became
		// more costly. Thus a rule edit cannot add a cost to every query
		// without a notice.
		log.Printf("pf dns: key rule %s has no literal head; every query name now runs the full key regexp", headless)
	}
	return &keyShapes{all: tr.All(), prefixes: heads}, nil
}

// match reports the rule for a key in a query name (keyshape.Match).
func (k *keyShapes) match(name string) string {
	if k == nil {
		return ""
	}
	return keyshape.Match(k.all, k.prefixes, name)
}

// logName is the part of a refused name that the query log can show: the
// zone that the name went to, and nothing to the left of it, where the key
// was. A log that kept the name would hold the value that the refusal kept
// off the wire. The zone is the last two labels. An attacker had to
// register that zone. If the key is also in those labels, logName keeps
// nothing.
func (k *keyShapes) logName(name string) string {
	tail := keyshape.Tail(name)
	if k.match(tail) != "" {
		return ""
	}
	return tail
}
