package broker

import (
	"bytes"
	"strings"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/placeholder"
	"pi-fortress/internal/secrets"
)

func scrubPairs(slots map[string]secrets.Slot) ([][2][]byte, []string) {
	var pairs [][2][]byte
	var keys []string
	for _, sl := range slots {
		if sl.Live == "" || placeholder.IsPlaceholder(sl.Live) {
			continue
		}
		pairs = append(pairs, [2][]byte{[]byte(sl.Live), []byte(sl.Dummy)})
		keys = append(keys, secrets.EnvKey(sl.ID, sl.Kind))
	}
	return pairs, keys
}

// rewriteHeaders changes each live value in the reason phrase and in
// response field values to its placeholder, one pass per header. It names
// the slots that it hit. The broker cannot rewrite a field name, because
// the name gives the field its meaning. Thus a live value or a placeholder
// (in any letter case) in a name gives ErrLiveName, and the caller refuses
// the response. The hit also names that slot, so that the caller logs it.
// For a placeholder, the hit is the slot and kind that it names.
func rewriteHeaders(resp *httpwire.Response, slots map[string]secrets.Slot) ([]string, error) {
	pairs, keys := scrubPairs(slots)
	var hit []string
	for _, f := range resp.Fields {
		name := []byte(f.Name)
		for _, sp := range placeholder.FindPlaceholderSpans(name) {
			hit = append(hit, secrets.EnvKey(placeholder.PlaceholderParts(name, sp)))
		}
		for j, p := range pairs {
			if bytes.Contains(name, p[0]) {
				hit = append(hit, keys[j])
			}
		}
	}
	if len(hit) > 0 {
		return hit, ErrLiveName
	}
	if len(pairs) == 0 {
		return nil, nil
	}
	counts := make([]int, len(pairs))
	// changed adds each slot that the last pass hit and resets the counts.
	changed := func() bool {
		did := false
		for j, c := range counts {
			if c > 0 {
				did = true
				hit = append(hit, keys[j])
				counts[j] = 0
			}
		}
		return did
	}
	if code, reason, ok := strings.Cut(resp.Status, " "); ok {
		nr := httpwire.ReplaceAll(nil, []byte(reason), pairs, counts)
		if changed() {
			resp.SetStatus(code + " " + string(nr))
		}
	}
	for i, f := range resp.Fields {
		nv := httpwire.ReplaceAll(nil, []byte(f.Value), pairs, counts)
		if changed() {
			resp.SetIndex(i, string(nv))
		}
	}
	return hit, nil
}

func rewriteResponse(resp *httpwire.Response, slots map[string]secrets.Slot) ([]string, error) {
	hit, err := rewriteHeaders(resp, slots)
	if err != nil {
		return hit, err
	}
	pairs, keys := scrubPairs(slots)
	if len(pairs) == 0 || len(resp.Body) == 0 {
		return hit, nil
	}
	counts := make([]int, len(pairs))
	body := httpwire.ReplaceAll(make([]byte, 0, len(resp.Body)), resp.Body, pairs, counts)
	for j, c := range counts {
		if c > 0 {
			hit = append(hit, keys[j])
		}
	}
	resp.Body = body
	return hit, nil
}
