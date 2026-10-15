package fetch

import (
	"encoding/json"
	"slices"
)

// MergeSeed is the answer of the ship to a sources.json that the Pi owns.
// The copy of the operator wins, so a feed that was new in git never
// reached a box that already had one (hagezi-doh-vpn-proxy-bypass was
// added by hand on 2026-09-23). MergeSeed appends each shipped feed, as
// shipped, if the box has not listed its id and was not offered it before.
// It records each shipped id in Seeded. Nothing already on the box
// changes: a disabled feed stays disabled, and a deleted feed stays deleted.
//
// changed is false when there was nothing to add, so the kept file stays
// byte for byte the same. A kept file that does not parse also stays as
// it is: the next apply reports it, and a ship is the wrong place to
// rewrite a broken edit of an operator.
func MergeSeed(kept, shipped []byte) (out []byte, changed bool, err error) {
	var box, seed Spec
	if err := json.Unmarshal(kept, &box); err != nil {
		return kept, false, nil
	}
	if err := json.Unmarshal(shipped, &seed); err != nil {
		return kept, false, err
	}
	known := map[string]bool{}
	for _, id := range box.Seeded {
		known[id] = true
	}
	for _, f := range box.Feeds {
		known[f.ID] = true
	}
	for _, f := range seed.Feeds {
		if !known[f.ID] {
			box.Feeds = append(box.Feeds, f)
			changed = true
		}
		known[f.ID] = true
	}
	for _, f := range seed.Feeds {
		if !slices.Contains(box.Seeded, f.ID) {
			box.Seeded = append(box.Seeded, f.ID)
			changed = true
		}
	}
	if !changed {
		return kept, false, nil
	}
	raw, err := json.MarshalIndent(box, "", "  ")
	if err != nil {
		return kept, false, err
	}
	return append(raw, '\n'), true, nil
}
