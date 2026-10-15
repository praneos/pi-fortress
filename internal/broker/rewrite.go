package broker

import (
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

func scrubPairs(slots map[string]secrets.Slot) ([][2][]byte, []string) {
	var pairs [][2][]byte
	var keys []string
	for _, sl := range slots {
		if sl.Live == "" || secrets.IsPlaceholder(sl.Live) {
			continue
		}
		pairs = append(pairs, [2][]byte{[]byte(sl.Live), []byte(sl.Dummy)})
		keys = append(keys, secrets.EnvKey(sl.ID, sl.Kind))
	}
	return pairs, keys
}

// rewriteHeaders changes each live value in response headers to its
// placeholder, one pass per header. It names the slots that it hit.
func rewriteHeaders(resp *httpwire.Response, slots map[string]secrets.Slot) []string {
	pairs, keys := scrubPairs(slots)
	if len(pairs) == 0 {
		return nil
	}
	var hit []string
	counts := make([]int, len(pairs))
	for i, f := range resp.Fields {
		for j := range counts {
			counts[j] = 0
		}
		nv := httpwire.ReplaceAll(nil, []byte(f.Value), pairs, counts)
		changed := false
		for j, c := range counts {
			if c > 0 {
				changed = true
				hit = append(hit, keys[j])
			}
		}
		if changed {
			resp.SetIndex(i, string(nv))
		}
	}
	return hit
}

func rewriteResponse(resp *httpwire.Response, slots map[string]secrets.Slot) []string {
	hit := rewriteHeaders(resp, slots)
	pairs, keys := scrubPairs(slots)
	if len(pairs) == 0 || len(resp.Body) == 0 {
		return hit
	}
	counts := make([]int, len(pairs))
	body := httpwire.ReplaceAll(make([]byte, 0, len(resp.Body)), resp.Body, pairs, counts)
	for j, c := range counts {
		if c > 0 {
			hit = append(hit, keys[j])
		}
	}
	resp.Body = body
	return hit
}
