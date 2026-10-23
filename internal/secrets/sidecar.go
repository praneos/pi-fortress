package secrets

import (
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// readSidecar reads a "<slot> <unix-ts>" sidecar and stamps the inode
// that it read, from the descriptor. A missing file is an empty map.
func readSidecar(path string, parse func(string) map[string]int64) (map[string]int64, stamp, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]int64{}, stamp{}, nil
		}
		return nil, stamp{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, stamp{}, err
	}
	return parse(string(raw)), fdStamp(f), nil
}

func (s *Store) writeSidecar(path string, m map[string]int64) error {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		b.WriteString(id + " " + strconv.FormatInt(m[id], 10) + "\n")
	}
	tmp, err := stage(path, []byte(b.String()))
	if err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0640)
	keepOwner(path, tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
	// The quarantine list is the one file where the loss of the last write
	// to a power cut is worse than the loss of a credential. The slot comes
	// back live, and the fence starts to spend a value that an operator revoked.
	return syncDir(path)
}

func (s *Store) editSidecar(slot, path string, parse func(string) map[string]int64, fn func(map[string]int64) error) error {
	slot = strings.ToLower(strings.TrimSpace(slot))
	if err := ValidSlotID(slot); err != nil {
		return err
	}
	return s.withLock(func() error {
		m, _, err := readSidecar(path, parse)
		if err != nil {
			return err
		}
		if err := fn(m); err != nil {
			return err
		}
		return s.writeSidecar(path, m)
	})
}
