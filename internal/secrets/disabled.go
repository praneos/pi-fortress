package secrets

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DisabledPath is the quarantine sidecar next to secrets.env: one
// "<slot> <unix-ts>" per line. A slot listed here is served as unknown.
func (s *Store) DisabledPath() string {
	return filepath.Join(filepath.Dir(s.path), "secrets.disabled")
}

func parseDisabled(raw string) map[string]int64 {
	out := map[string]int64{}
	for line := range strings.SplitSeq(raw, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ts := int64(0)
		if len(f) > 1 {
			ts, _ = strconv.ParseInt(f[1], 10, 64)
		}
		if id := strings.ToLower(f[0]); ValidSlotID(id) == nil {
			out[id] = ts
		}
	}
	return out
}

// Disabled returns slot -> unix time it was quarantined.
func (s *Store) Disabled() (map[string]int64, error) {
	m, _, err := s.disabledStamped()
	return m, err
}

// disabledStamped reads the sidecar and reports the identity of the
// inode that it read, from the descriptor. Snapshot needs the two from
// the same file. A Disable occurs by rename. Thus a stamp from a new
// stat of the pathname would put the pre-quarantine answer under the
// post-quarantine file. The cache would then serve the revoked slot
// until something else moved the sidecar again.
func (s *Store) disabledStamped() (map[string]int64, stamp, error) {
	return readSidecar(s.DisabledPath(), parseDisabled)
}

func (s *Store) writeDisabled(m map[string]int64) error {
	return s.writeSidecar(s.DisabledPath(), m)
}

// editDisabled reads the sidecar, edits it and writes it back under the
// store lock. Without the lock, the three steps are a read-modify-write
// that two pf processes interleave. Each writes back the list that it
// read, and the one that finishes second erases the entry of the other.
// What it erases is a revocation. Thus a slot that an operator
// quarantined is served again: the fence spends a credential that was
// withdrawn, and nothing reports it.
func (s *Store) editDisabled(slot string, fn func(map[string]int64) error) error {
	return s.editSidecar(slot, s.DisabledPath(), parseDisabled, fn)
}

func (s *Store) Disable(slot string) error {
	return s.editDisabled(slot, func(m map[string]int64) error {
		if _, ok := m[strings.ToLower(slot)]; !ok {
			m[strings.ToLower(slot)] = time.Now().Unix()
		}
		return nil
	})
}

func (s *Store) Restore(slot string) error {
	return s.editDisabled(slot, func(m map[string]int64) error { delete(m, strings.ToLower(slot)); return nil })
}

// Purge deletes a disabled slot from secrets.env and the sidecar.
func (s *Store) Purge(slot string) ([]string, error) {
	removed, err := s.DeleteSlot(slot)
	if err != nil {
		return nil, err
	}
	return removed, s.Restore(slot)
}

// PurgeOlderThan purges every slot disabled at least d ago.
func (s *Store) PurgeOlderThan(d time.Duration) ([]string, error) {
	m, err := s.Disabled()
	if err != nil {
		return nil, err
	}
	cut := time.Now().Add(-d).Unix()
	var purged []string
	for id, ts := range m {
		if ts <= cut {
			if _, err := s.Purge(id); err != nil {
				return purged, err
			}
			purged = append(purged, id)
		}
	}
	sort.Strings(purged)
	return purged, nil
}
