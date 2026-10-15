package secrets

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ExpiresPath is the optional-expiry sidecar next to secrets.env: one
// "<slot> <unix-ts>" per line, the unix time when the slot goes bad. A
// slot that is not in this file has no expiry. Each row minted before
// this existed is already in that state. The sidecar is additive, and an
// old store continues to work with nothing in it.
func (s *Store) ExpiresPath() string {
	return filepath.Join(filepath.Dir(s.path), "secrets.expires")
}

// parseExpires reads the sidecar. It is different from the quarantine
// sidecar: it discards a missing or non-positive timestamp, and does not
// set it to zero. In quarantine, zero still means "disabled, since
// forever unknown". But an expiry of zero would mean "expires at the
// epoch", and no hand edit or caller means that. Thus it reads a
// malformed row as no expiry, not as an expiry that already occurred.
func parseExpires(raw string) map[string]int64 {
	out := map[string]int64{}
	for line := range strings.SplitSeq(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		if id := strings.ToLower(f[0]); validSlotID(id) == nil {
			out[id] = ts
		}
	}
	return out
}

// Expires returns slot -> unix time it goes bad, for every slot that has
// one.
func (s *Store) Expires() (map[string]int64, error) {
	m, _, err := s.expiresStamped()
	return m, err
}

// expiresStamped reads the sidecar and reports the identity of the inode
// that it read, for the same reason as disabledStamped. A SetExpiry
// occurs by rename. Thus Snapshot must cache the file that it read, not
// a new stat of the pathname taken after.
func (s *Store) expiresStamped() (map[string]int64, stamp, error) {
	return readSidecar(s.ExpiresPath(), parseExpires)
}

// editExpires reads the sidecar, edits it and writes it back under the
// store lock. This is the same read-modify-write-under-lock as
// editDisabled, for the same reason. Two processes in a race on an
// unlocked edit each write back the list that they read. The one that
// finishes second erases what the other set.
func (s *Store) editExpires(slot string, fn func(map[string]int64) error) error {
	return s.editSidecar(slot, s.ExpiresPath(), parseExpires, fn)
}

// SetExpiry sets or replaces the expiry deadline of the slot. A zero at
// clears it. The slot then never expires, the same as a row that this
// sidecar never named. Mint calls this one time, at mint time, with the
// value from --expires. renew calls it again later. Harvest never calls
// it. A refresh of the live oat/ort of a slot rewrites secrets.env and
// does not touch this file. Thus a refresh cannot silently make a deadline later.
func (s *Store) SetExpiry(slot string, at time.Time) error {
	return s.editExpires(slot, func(m map[string]int64) error {
		id := strings.ToLower(strings.TrimSpace(slot))
		if at.IsZero() {
			delete(m, id)
			return nil
		}
		m[id] = at.Unix()
		return nil
	})
}

// ClearExpiry removes the deadline of a slot, if it has one. It is
// SetExpiry with the zero time, spelled out for callers that only clear.
func (s *Store) ClearExpiry(slot string) error {
	return s.SetExpiry(slot, time.Time{})
}

// applyExpiryDeadlines records the deadline of each slot from the
// sidecar. This runs one time at load time, and the cache of Snapshot
// holds the result. The deadline is a fact about the file. It does not
// change while the file does not change. If "now" is past it, that is a
// fact about the clock. That check belongs in cloneSlots, which runs on
// each Snapshot call, with or without the cache. Busy is decided fresh
// in the same place.
func applyExpiryDeadlines(slots map[string]Slot, exp map[string]int64) {
	for k, v := range slots {
		if ts, ok := exp[v.ID]; ok {
			v.Expires = time.Unix(ts, 0)
			slots[k] = v
		}
	}
}
