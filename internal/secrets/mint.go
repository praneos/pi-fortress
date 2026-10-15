// Package secrets is the slotted credential store behind the broker's
// secrets.env: slot ids, placeholders, live values, quarantine and the locked
// rewrites. The broker, the fence, internal/admin and internal/enroll use it.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	SlotLen   = 16
	mintTries = 64
)

var (
	kindRe     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	ClaudePair = []string{"CLAUDE_OAT", "CLAUDE_ORT"}
)

type KeyInfo struct {
	Kind  string `json:"kind"`
	Dummy string `json:"dummy"`
	State string `json:"state"`
}

type SlotList struct {
	Slot string    `json:"slot"`
	Keys []KeyInfo `json:"keys"`
	// Expires is RFC3339, or empty for a slot with no expiry: each row
	// minted before this existed, and each row minted since with no --expires.
	Expires string `json:"expires,omitempty"`
}

type Migration struct {
	Old  string
	Slot string
	Kind string
}

func randomSlot() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

func MintSlot(taken map[string]struct{}, tokenFn func() string) (string, error) {
	if taken == nil {
		taken = map[string]struct{}{}
	}
	gen := tokenFn
	if gen == nil {
		gen = randomSlot
	}
	for range mintTries {
		slot := strings.ToLower(gen())
		if len(slot) != SlotLen {
			continue
		}
		if _, err := hex.DecodeString(slot); err != nil {
			continue
		}
		if _, ok := taken[slot]; ok {
			continue
		}
		return slot, nil
	}
	return "", errors.New("pi-fortress: could not mint a unique slot")
}

func KindsFor(kind string) ([]string, error) {
	raw := strings.ToUpper(strings.TrimSpace(kind))
	switch raw {
	case "CLAUDE", "CLAUDE_OAT", "CLAUDE_ORT":
		out := make([]string, len(ClaudePair))
		copy(out, ClaudePair)
		return out, nil
	}
	if !kindRe.MatchString(raw) {
		return nil, fmt.Errorf("invalid secret kind: %s", kind)
	}
	return []string{raw}, nil
}

func existingSlots(m map[string]Slot) map[string]struct{} {
	out := map[string]struct{}{}
	for _, sl := range m {
		out[sl.ID] = struct{}{}
	}
	return out
}

func (s *Store) withLock(fn func() error) error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	fd, err := s.flock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}()
	err = fn()
	s.mu.Lock()
	s.cache = nil
	s.st = stamp{}
	s.mu.Unlock()
	return err
}

// ErrSealedMint is a mint on a sealed store that nobody unlocked in
// this process. It is the refusal that writeMerged would give anyway,
// moved to the front and said in the terms that the operator types. The
// old sentinel names a passphrase and no way to supply one, because
// there is none. A mint runs in pf enroll, which builds its own store
// and never gets the key. Thus pf unlock never helps. The way through
// is the whole-file round trip. That is why the message spells it out.
//
// An empty value is also refused. To create a slot writes no secret,
// and in principle it could be let through. But if a store accepts one
// shape of mint and refuses another, the operator must remember that
// rule at the moment when they are least able to.
var ErrSealedMint error = sealedMintError{}

type sealedMintError struct{}

func (sealedMintError) Error() string {
	return "secrets: store is locked: a mint has to seal the row it writes and the key is held by the broker, not by pf enroll. " +
		"Unseal, mint, then seal again: sudo pf enroll unseal; sudo pf enroll mint ...; sudo pf enroll seal; sudo pf unlock."
}

// Unwrap keeps errors.Is(err, ErrLocked) true. This is that refusal
// with a way out attached, not a second, different refusal.
func (sealedMintError) Unwrap() error { return ErrLocked }

// MintAllowed reports the cause for which a mint would be refused. Thus a
// caller can fail before it prompts, reads a token from stdin or writes a
// paste file. MintKinds asks it too. This function gives the answer
// without the lock file and the slot id that a real mint takes first.
func (s *Store) MintAllowed() error {
	state, err := s.State()
	if err != nil {
		return err
	}
	if state.Sealed && !state.Unlocked {
		return ErrSealedMint
	}
	return nil
}

func (s *Store) MintKinds(kinds []string, values map[string]string) (string, error) {
	if len(kinds) == 0 {
		return "", errors.New("no kinds")
	}
	// Before the lock file and before a slot id is drawn. The rewrite
	// refuses a locked store anyway, and a failure there gives the
	// operator an error that names no remedy.
	if err := s.MintAllowed(); err != nil {
		return "", err
	}
	var slot string
	err := s.withLock(func() error {
		cur, err := loadFile(s.path, nil)
		if err != nil {
			return err
		}
		id, err := MintSlot(existingSlots(cur.slots), nil)
		if err != nil {
			return err
		}
		updates := map[string]string{}
		for _, kind := range kinds {
			v := ""
			if values != nil {
				v = values[kind]
			}
			updates[EnvKey(id, kind)] = v
		}
		if err := s.writeUpdates(updates); err != nil {
			return err
		}
		slot = id
		return nil
	})
	return slot, err
}

func (s *Store) ListSlots() ([]SlotList, error) {
	snap, err := s.Snapshot()
	if err != nil {
		return nil, err
	}
	grouped := map[string][]KeyInfo{}
	expires := map[string]time.Time{}
	for _, sl := range snap {
		state := "empty"
		switch {
		case sl.Disabled:
			state = "disabled"
		case sl.Expired:
			state = "expired"
		case sl.Live != "":
			state = "set"
		}
		grouped[sl.ID] = append(grouped[sl.ID], KeyInfo{
			Kind:  sl.Kind,
			Dummy: sl.Dummy,
			State: state,
		})
		if !sl.Expires.IsZero() {
			expires[sl.ID] = sl.Expires
		}
	}
	ids := make([]string, 0, len(grouped))
	for id := range grouped {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]SlotList, 0, len(ids))
	for _, id := range ids {
		keys := grouped[id]
		sort.Slice(keys, func(i, j int) bool { return keys[i].Kind < keys[j].Kind })
		row := SlotList{Slot: id, Keys: keys}
		if at, ok := expires[id]; ok {
			row.Expires = at.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out, nil
}

func validSlotID(slot string) error {
	slot = strings.ToLower(strings.TrimSpace(slot))
	if len(slot) != SlotLen {
		return errors.New("invalid slot")
	}
	if _, err := hex.DecodeString(slot); err != nil {
		return errors.New("invalid slot")
	}
	return nil
}

func readLines(path string) ([]string, error) {
	raw, err := readNoFollow(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	s := strings.TrimSuffix(string(raw), "\n")
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}

func writeLines(path string, lines []string) error {
	text := strings.Join(lines, "\n")
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return replaceFile(path, text)
}

// dropSlotLines gives the lines without the rows of slot, and the kind
// of each row that it removed.
func dropSlotLines(lines []string, slot string) (kept, removed []string) {
	for _, raw := range lines {
		stripped := strings.TrimSpace(raw)
		if stripped != "" && !strings.HasPrefix(stripped, "#") && strings.Contains(raw, "=") {
			key := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
			id, kind, ok := ParseEnvKey(key)
			if ok && id == slot {
				removed = append(removed, kind)
				continue
			}
		}
		kept = append(kept, raw)
	}
	return kept, removed
}

func (s *Store) DeleteSlot(slot string) ([]string, error) {
	slot = strings.ToLower(strings.TrimSpace(slot))
	if err := validSlotID(slot); err != nil {
		return nil, err
	}
	var removed []string
	err := s.withLock(func() error {
		if _, err := os.Stat(s.path); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		lines, err := readLines(s.path)
		if err != nil {
			return err
		}
		var out []string
		out, removed = dropSlotLines(lines, slot)
		if len(removed) == 0 {
			return nil
		}
		return writeLines(s.path, out)
	})
	if err != nil {
		return removed, err
	}
	// A slot that is gone cannot be in quarantine. Before, the line
	// stayed until the purge timer removed it for age. The budget stop of
	// the broker now writes that file without a request. Thus a delete of
	// the slot that it stopped is the ordinary case, not the odd one.
	if m, derr := s.Disabled(); derr == nil {
		if _, held := m[slot]; held {
			if err := s.Restore(slot); err != nil {
				return removed, err
			}
		}
	}
	// The same for a deadline: a gone slot has nothing left to expire. A
	// stale line would stay in the sidecar forever with no row to name.
	if m, eerr := s.Expires(); eerr == nil {
		if _, held := m[slot]; held {
			return removed, s.ClearExpiry(slot)
		}
	}
	return removed, nil
}

func (s *Store) HarvestClaude(oat, ort, slot string) (string, error) {
	var used string
	err := s.withLock(func() error {
		cur, err := loadFile(s.path, nil)
		if err != nil {
			return err
		}
		taken := existingSlots(cur.slots)
		chosen := strings.ToLower(slot)
		if chosen != "" {
			if _, ok := taken[chosen]; ok {
				used = chosen
			}
		}
		if used == "" {
			id, err := MintSlot(taken, nil)
			if err != nil {
				return err
			}
			used = id
		}
		updates := map[string]string{}
		if oat != "" {
			updates[EnvKey(used, "CLAUDE_OAT")] = oat
		}
		if ort != "" {
			updates[EnvKey(used, "CLAUDE_ORT")] = ort
		}
		if len(updates) == 0 {
			return nil
		}
		return s.writeUpdates(updates)
	})
	return used, err
}

func parseLineKV(raw string) (key, value string, ok bool) {
	stripped := strings.TrimSpace(raw)
	if stripped == "" || strings.HasPrefix(stripped, "#") || !strings.Contains(raw, "=") {
		return "", "", false
	}
	k, v, found := strings.Cut(raw, "=")
	if !found {
		return "", "", false
	}
	key = strings.TrimSpace(k)
	value = strings.Trim(strings.TrimSpace(v), `"'`)
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func (s *Store) MigrateUnslotted() ([]Migration, error) {
	var moved []Migration
	err := s.withLock(func() error {
		if _, err := os.Stat(s.path); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		lines, err := readLines(s.path)
		if err != nil {
			return err
		}
		// Migration reads values in the clear and writes them back. Thus
		// a sealed store must be open for it. writeUpdates below seals
		// what it writes. Nothing here puts a plain value under a sealed
		// header.
		if f, err := loadFile(s.path, s.sealerFor()); err != nil {
			return err
		} else if f.state.Sealed && !f.state.Unlocked {
			return ErrLocked
		}
		kept, p, err := planMigration(lines)
		moved = p.moved
		if err != nil {
			return err
		}
		// One publication, not two. Before, this wrote `kept` (the file
		// without the legacy rows) and then called writeUpdates to add the
		// slotted replacements. Thus a failure between the two left a store
		// with neither: the legacy credentials were already gone, and their
		// slotted replacements were not yet written. writeMerged takes the
		// lines to keep and the rows to add together, and renames one time.
		// It is still the one path that knows whether the store is
		// sealed.
		return s.writeMerged(kept, p.updates)
	})
	return moved, err
}

type migrationPlan struct {
	taken   map[string]struct{}
	updates map[string]string
	moved   []Migration
}

func (p *migrationPlan) newSlot() (string, error) {
	id, err := MintSlot(p.taken, nil)
	if err != nil {
		return "", err
	}
	p.taken[id] = struct{}{}
	return id, nil
}

func (p *migrationPlan) add(id, kind, value string) {
	p.updates[EnvKey(id, kind)] = value
	p.moved = append(p.moved, Migration{Old: kind, Slot: id, Kind: kind})
}

// planMigration gives the lines to keep and a new slot for each legacy
// row. The Claude pair shares one slot. Each other legacy row gets its
// own slot, in key order. A legacy key that is not a kind stays as a
// line.
func planMigration(lines []string) ([]string, migrationPlan, error) {
	kept, unslotted, taken := splitUnslotted(lines)
	p := migrationPlan{taken: taken, updates: map[string]string{}}
	oat, ort := unslotted["CLAUDE_OAT"], unslotted["CLAUDE_ORT"]
	delete(unslotted, "CLAUDE_OAT")
	delete(unslotted, "CLAUDE_ORT")
	if oat != "" || ort != "" {
		id, err := p.newSlot()
		if err != nil {
			return kept, p, err
		}
		if oat != "" {
			p.add(id, "CLAUDE_OAT", oat)
		}
		if ort != "" {
			p.add(id, "CLAUDE_ORT", ort)
		}
	}
	rest := make([]string, 0, len(unslotted))
	for key := range unslotted {
		rest = append(rest, key)
	}
	sort.Strings(rest)
	for _, key := range rest {
		value := unslotted[key]
		if !kindRe.MatchString(key) {
			kept = append(kept, key+"="+value)
			continue
		}
		id, err := p.newSlot()
		if err != nil {
			return kept, p, err
		}
		p.add(id, key, value)
	}
	return kept, p, nil
}

// splitUnslotted keeps each line that is not a legacy row and records
// each slot that a kept row uses. It gives the value of each legacy row
// that has one. A legacy row with no value is dropped.
func splitUnslotted(lines []string) (kept []string, unslotted map[string]string, taken map[string]struct{}) {
	unslotted = map[string]string{}
	taken = map[string]struct{}{}
	for _, raw := range lines {
		key, value, ok := parseLineKV(raw)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		id, _, slotted := ParseEnvKey(key)
		if slotted {
			taken[id] = struct{}{}
			kept = append(kept, raw)
			continue
		}
		if value == "" {
			continue
		}
		unslotted[key] = value
	}
	return kept, unslotted, taken
}

func (s *Store) LiveMap() (map[string]string, error) {
	snap, err := s.Snapshot()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, sl := range snap {
		if sl.Live != "" {
			out[k] = sl.Live
		}
	}
	return out, nil
}
