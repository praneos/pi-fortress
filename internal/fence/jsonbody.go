package fence

import (
	"bytes"
	"encoding/json"
	"strings"

	"pi-fortress/internal/httpwire"
)

// jsonRounds is the number of times the scan unescapes a JSON string that
// holds JSON text with escapes of its own. A tool call often sends its
// arguments as a JSON string inside a JSON body. Thus one round is not
// enough.
const jsonRounds = 4

// isJSONBody says that the origin reads the body as JSON: a Content-Type
// with a JSON media type, or bytes that parse as JSON.
func isJSONBody(req *httpwire.Request, body []byte) bool {
	for _, v := range req.Values("Content-Type") {
		mt, _, _ := strings.Cut(v, ";")
		if strings.Contains(strings.ToLower(mt), "json") {
			return true
		}
	}
	return json.Valid(body)
}

// noteJSONBody scans the JSON strings of a body after the unescape, because
// the origin decodes them. A placeholder or a live value written with
// escapes (\u0070, \/) does not show in the raw bytes. The scan runs over
// the body after the raw strip. Thus a literal match strips as before, and
// only an escaped match refuses: a placeholder as in noteEncodedBody, a
// live value or token-prefix match as CauseEncodedBodyToken. The fence
// never substitutes into a decoded string. A body with no backslash has no
// escape, and costs one byte search. The unescaped text can be rounds times
// the body, so each string takes its bytes from bud first. After a
// refusal, the scan stops, and the caller answers busy.
func (s *scanner) noteJSONBody(req *httpwire.Request, body []byte, bud *scanBudget) {
	if bytes.IndexByte(body, '\\') < 0 || !isJSONBody(req, body) {
		return
	}
	if dec := jsonEscaped(s.strip(body), jsonRounds, nil, bud); len(dec) > 0 && !bud.spent {
		s.noteEncodedBody(dec)
	}
}

// jsonEscaped appends to out the decoded text of each JSON string in b, key
// or value, that holds an escape. A newline ends each string. A newline is
// not a token byte, so no match can join two strings. Decoded text that
// holds a backslash gets the same pass again, for at most rounds passes in
// all. The decode uses the standard rules of encoding/json. A string that
// does not decode is skipped: a JSON parser rejects it. The work is linear
// in the body size for each round. Each decoded string takes its length
// from bud before it goes into out. When bud refuses, jsonEscaped stops.
func jsonEscaped(b []byte, rounds int, out []byte, bud *scanBudget) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		esc := false
		j := i + 1
		for ; j < len(b) && b[j] != '"'; j++ {
			if b[j] == '\\' {
				esc = true
				j++
			}
		}
		if j >= len(b) {
			break
		}
		lit := b[i : j+1]
		i = j
		var s string
		if !esc || json.Unmarshal(lit, &s) != nil {
			continue
		}
		if !bud.take(int64(len(s)) + 1) {
			return out
		}
		out = append(append(out, s...), '\n')
		if rounds > 1 && strings.IndexByte(s, '\\') >= 0 {
			out = jsonEscaped([]byte(s), rounds-1, out, bud)
		}
	}
	return out
}
