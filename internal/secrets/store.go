package secrets

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"pi-fortress/internal/placeholder"
)

var (
	slotRe     = regexp.MustCompile(`^([0-9a-fA-F]{16})_([A-Z][A-Z0-9_]*)$`)
	ErrBusy    = errors.New("secrets: harvest busy")
	ErrBadLive = errors.New("secrets: live value is not a token")
)

// ValidLive accepts what survives a round trip through secrets.env:
// printable ASCII without space, quotes or '#', at most 4 KiB. All other
// values would be truncated, unquoted, or become a second line and a
// second key on disk.
func ValidLive(v string) bool {
	if v == "" || len(v) > 4096 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c > '~' || c == '#' || c == '"' || c == '\'' {
			return false
		}
	}
	return true
}

const StripRepl = "pf_stripped"

type Slot struct {
	ID    string
	Kind  string
	Dummy string
	Live  string
	Busy  bool
	// Disabled slots keep their rows but snapshot with an empty Live, so
	// the fence treats the placeholder as unknown.
	Disabled bool
	// Sealed means that the row exists and its value is encrypted at
	// rest with a key that nobody has entered yet. The inventory stays
	// readable on purpose. An operator can see which slots need an unlock
	// without an unlock. A slot ID is not a secret: it is already in the
	// placeholder that the agent holds.
	Sealed bool
	// Expires is the deadline from secrets.expires, or the zero time for
	// a slot with none. It is read from the sidecar at load time. Each
	// Snapshot decides again whether it has passed (see Expired).
	Expires time.Time
	// Expired works like Disabled: true after Expires has passed. The
	// row then snapshots with an empty Live, so the fence treats the
	// placeholder as unknown, the same as a quarantined slot.
	Expired bool
	// Stale is the value that a disabled or expired slot held before its
	// Live was blanked. It is never injected. NewIndex keeps it out of the
	// placeholder lookup and lists it only for the strip. Thus, if the
	// agent holds a revoked credential by some route, it is still stripped
	// from a request. It is not forwarded because the store no longer knows
	// it. A locked sealed store cannot know its values and has none.
	Stale string
}

func EnvKey(slot, kind string) string {
	return strings.ToLower(slot) + "_" + kind
}

func Placeholder(slot, kind string) string {
	return "pf_" + EnvKey(slot, kind)
}

func ParseEnvKey(key string) (slot, kind string, ok bool) {
	m := slotRe.FindStringSubmatch(strings.TrimSpace(key))
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), m[2], true
}

func FindPlaceholders(text string) [][2]string {
	b := []byte(text)
	spans := placeholder.FindPlaceholderSpans(b)
	out := make([][2]string, 0, len(spans))
	for _, sp := range spans {
		slot, kind := placeholder.PlaceholderParts(b, sp)
		out = append(out, [2]string{slot, kind})
	}
	return out
}

type stamp struct{ ino, mtime, size uint64 }

// testHookAfterLoad runs in the window between the read of one of the
// two files that a snapshot is built from and the record of the
// identity that the contents get cached under. Its name is "secrets" or
// "disabled", for the file just read. The bug that it exists for is a
// rename exactly in that window. Goroutines in a race cannot open a
// window that narrow reliably. Thus the test reaches in and opens it.
// It is nil in all code except tests.
var testHookAfterLoad func(stage string)

// testHookRead gives the error for a read through readNoFollow when it
// is set. Thus a test can make one read fail while the file stays
// readable. It is nil in all code except tests.
var testHookRead func(path string) error

type Store struct {
	path  string
	mu    sync.Mutex
	busy  map[string]struct{}
	st    stamp
	dst   stamp
	ext   stamp
	cache map[string]Slot
	// sealer is the key for this boot, or nil. mu guards it. It is never
	// written anywhere.
	sealer *Sealer
	state  State
}

// State is what an operator needs to know about the store without a
// view of a value. Fault is the store that fails shut: the inventory is
// still readable, each value reads as sealed, and each substitution
// refuses through the one wall that the fence already has.
type State struct {
	Sealed   bool
	Unlocked bool
	Fault    string
}

func Open(path string) *Store {
	return &Store{path: path, busy: map[string]struct{}{}}
}

func (s *Store) lockPath() string { return s.path + ".lock" }

// The names of the store are in the directory of the broker, and root
// runs pf enroll on the same names. Neither the lock nor the store is
// opened through a link. A link at either name would change the create
// of root into a file that the broker selects. It would change the
// read-and-rewrite of root into a copy of a different file into the store.
func (s *Store) flock(how int) (int, error) {
	fd, err := syscall.Open(s.lockPath(), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, err
	}
	if err := syscall.Flock(fd, how); err != nil {
		syscall.Close(fd)
		return 0, err
	}
	return fd, nil
}

func fileStamp(path string) stamp {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stampOf(fi)
}

// fdStamp stamps the inode that a reader has open. That is not always
// the inode that the pathname now resolves to. Each writer here
// replaces the file by rename. Thus identity tells a new read from a
// read of the file that was just superseded.
func fdStamp(f *os.File) stamp {
	fi, err := f.Stat()
	if err != nil {
		return stamp{}
	}
	return stampOf(fi)
}

func stampOf(fi os.FileInfo) stamp {
	ino := uint64(0)
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = uint64(sys.Ino)
	}
	return stamp{ino: ino, mtime: uint64(fi.ModTime().UnixNano()), size: uint64(fi.Size())}
}

type loaded struct {
	slots map[string]Slot
	state State
	// st identifies the inode that these slots were read from. It comes
	// from the descriptor, not from the pathname. Thus the caller can
	// tell whether what it holds is still what the path names.
	st stamp
}

// loadFile reads the store. A sealed file is a file that carries the
// header. All checks of that file then use that fact, because the file
// is sealed or it is not.
//
// Each failure inside a sealed file goes into state.Fault, not into the
// error return. It leaves the inventory with each value sealed and
// empty. That is the fail-shut path. The fence already answers a slot
// with no value with the same refusal that it gives for all other
// causes. Thus a store that cannot be trusted stops substitution without
// a second code path, and tells the agent nothing new.
func loadFile(path string, key *Sealer) (loaded, error) {
	out := loaded{slots: map[string]Slot{}}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return loaded{}, err
	}
	defer f.Close()
	lines, hdr, err := scanStore(f, &out.state)
	if err != nil {
		return loaded{}, err
	}
	out.st = fdStamp(f)
	if out.state.Sealed {
		if _, err := ParseHeader(hdr); err != nil {
			out.state.fault(err.Error())
		}
		out.state.Unlocked = key != nil && out.state.Fault == ""
	}
	for _, raw := range lines {
		sl, envKey, value, ok := parseStoreLine(raw, out.state.Sealed)
		if !ok {
			continue
		}
		if out.state.Sealed {
			sl = sealedSlot(sl, envKey, value, key, &out.state)
		} else if value != "" && !ValidLive(value) {
			continue
		} else {
			sl.Live = value
		}
		out.slots[envKey] = sl
	}
	if out.state.Fault != "" {
		out.state.Unlocked = false
		for k, sl := range out.slots {
			sl.Live, sl.Sealed = "", true
			out.slots[k] = sl
		}
	}
	return out, nil
}

// scanStore gives the lines of the store without the sealed header, and
// the last header line. A header line sets st.Sealed.
func scanStore(f *os.File, st *State) (lines []string, hdr string, err error) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if isSealedHeader(line) {
			if hdr != "" {
				st.fault("more than one sealed header")
			}
			hdr, st.Sealed = line, true
			continue
		}
		lines = append(lines, line)
	}
	return lines, hdr, sc.Err()
}

// fault records msg as the fault of the store. The first fault stays.
func (st *State) fault(msg string) {
	if st.Fault == "" {
		st.Fault = msg
	}
}

// parseStoreLine reads one line of the store. ok is false for a line
// that names no slot.
func parseStoreLine(raw string, sealed bool) (sl Slot, envKey, value string, ok bool) {
	// A sealed value starts with '#', so that a build without sealing
	// treats it as a comment and reads the slot as empty. Here the
	// header says otherwise, so the value is kept whole.
	if !sealed {
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
	} else if strings.HasPrefix(strings.TrimSpace(raw), "#") {
		return Slot{}, "", "", false
	}
	line := strings.TrimSpace(raw)
	if line == "" || !strings.Contains(line, "=") {
		return Slot{}, "", "", false
	}
	k, value, _ := strings.Cut(line, "=")
	id, kind, ok := ParseEnvKey(strings.TrimSpace(k))
	if !ok {
		return Slot{}, "", "", false
	}
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	return Slot{ID: id, Kind: kind, Dummy: Placeholder(id, kind)}, EnvKey(id, kind), value, true
}

// sealedSlot fills sl from a value in a sealed store. Each failure goes
// into st.Fault, not into an error return.
func sealedSlot(sl Slot, envKey, value string, key *Sealer, st *State) Slot {
	switch {
	case value == "":
		// A minted slot waiting for its first value. Nothing to
		// seal, nothing to downgrade.
		sl.Sealed = true
	case !isSealedValue(value):
		// The format exists to prevent this downgrade: anything that
		// can write the file puts a value back in the clear, and the
		// value still works under a header that still says sealed.
		// It makes the whole store fail, not only this slot.
		st.fault(ErrPlainInSealed.Error())
		sl.Sealed = true
	case key == nil:
		sl.Sealed = true
	default:
		live, err := key.Unseal(envKey, value)
		switch {
		case err != nil:
			st.fault(err.Error())
			sl.Sealed = true
		case !ValidLive(live):
			st.fault("sealed value is not a token: " + envKey)
			sl.Sealed = true
		default:
			sl.Live = live
		}
	}
	return sl
}

func cloneSlots(m map[string]Slot, busy map[string]struct{}) map[string]Slot {
	now := time.Now()
	out := make(map[string]Slot, len(m))
	for k, v := range m {
		_, v.Busy = busy[v.ID]
		// The deadline is cached. Whether it has passed is not. A slot
		// that nobody touched must still go from live to expired at the
		// instant when the clock crosses Expires. Nothing changes the file
		// at that moment, so the cache-invalidation stamp has nothing to catch.
		if !v.Expires.IsZero() && !now.Before(v.Expires) {
			v.Expired = true
			if v.Live != "" {
				v.Stale, v.Live = v.Live, ""
			}
		}
		out[k] = v
	}
	return out
}

func (s *Store) Snapshot() (map[string]Slot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, dst, ext := fileStamp(s.path), fileStamp(s.DisabledPath()), fileStamp(s.ExpiresPath())
	if s.cache != nil && st == s.st && dst == s.dst && ext == s.ext && st != (stamp{}) {
		return cloneSlots(s.cache, s.busy), nil
	}
	// The cache key is the identity of the inodes that were read, not a
	// new stat of the three pathnames after the read. Each file is
	// replaced by rename (each harvest, each quarantine edit, each renew).
	// Thus a replacement during a read is ordinary. A stamp of the read
	// with the identity of the new file would put superseded contents
	// under a key that continues to match. The broker takes a snapshot
	// for each request. Thus that cache entry is not a one-request
	// mistake: it continues to give out the revoked credential until
	// something unrelated moves a file again. When the identities
	// disagree, the code reads again from the file that the path
	// names now.
	var f loaded
	var off map[string]int64
	var exp map[string]int64
	for try := 0; ; try++ {
		var err error
		if f, err = loadFile(s.path, s.sealer); err != nil {
			return nil, err
		}
		if testHookAfterLoad != nil {
			testHookAfterLoad("secrets")
		}
		var dfd stamp
		if off, dfd, err = s.disabledStamped(); err != nil {
			return nil, err
		}
		if testHookAfterLoad != nil {
			testHookAfterLoad("disabled")
		}
		var efd stamp
		if exp, efd, err = s.expiresStamped(); err != nil {
			return nil, err
		}
		if testHookAfterLoad != nil {
			testHookAfterLoad("expires")
		}
		st, dst, ext = fileStamp(s.path), fileStamp(s.DisabledPath()), fileStamp(s.ExpiresPath())
		if st == f.st && dst == dfd && ext == efd {
			break
		}
		// A writer that loops over the store is not a reason to loop here
		// too. After a few tries, the read in hand is still an honest read
		// of a file that existed. It is served but not cached. Thus the
		// next caller reads again, and does not inherit the doubt.
		if try >= 4 {
			applyDisabled(f.slots, off)
			applyExpiryDeadlines(f.slots, exp)
			s.cache, s.st, s.dst, s.ext = nil, stamp{}, stamp{}, stamp{}
			s.state = f.state
			return cloneSlots(f.slots, s.busy), nil
		}
	}
	applyDisabled(f.slots, off)
	applyExpiryDeadlines(f.slots, exp)
	s.cache, s.state = f.slots, f.state
	s.st, s.dst, s.ext = st, dst, ext
	return cloneSlots(f.slots, s.busy), nil
}

// applyDisabled blanks the quarantined slots. They keep their rows, so
// the inventory still shows them. But with no value, the fence answers
// the placeholder the same way as a placeholder that it does not know.
func applyDisabled(slots map[string]Slot, off map[string]int64) {
	for k, v := range slots {
		if _, ok := off[v.ID]; ok {
			if v.Live != "" {
				v.Stale = v.Live
			}
			v.Live, v.Disabled = "", true
			slots[k] = v
		}
	}
}

// State reports whether the store is sealed, whether a passphrase was
// entered, and what is wrong with it. It reads the file. Thus it is
// current, and not the state that the last request left.
func (s *Store) State() (State, error) {
	if _, err := s.Snapshot(); err != nil {
		return State{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

// Unlock derives the key from a passphrase and keeps it for this
// process. It never returns which part failed, beyond sealed-or-not. The
// caller is an operator on a root-only channel. But there is also no
// reason for an answer richer than "this passphrase opens it".
func (s *Store) Unlock(passphrase []byte) error {
	hdr, err := s.header()
	if err != nil {
		return err
	}
	sealer, err := hdr.Open(passphrase)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sealer, s.cache, s.st = sealer, nil, stamp{}
	s.mu.Unlock()
	return nil
}

// Lock discards the key. The next substitution refuses again.
func (s *Store) Lock() {
	s.mu.Lock()
	s.sealer, s.cache, s.st = nil, nil, stamp{}
	s.mu.Unlock()
}

// ErrNotSealed is a plaintext store asked for something only a sealed
// one can answer.
var ErrNotSealed = errors.New("secrets: store is not sealed")

func (s *Store) header() (Header, error) {
	raw, err := readNoFollow(s.path)
	if err != nil {
		return Header{}, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if isSealedHeader(line) {
			return ParseHeader(line)
		}
	}
	return Header{}, ErrNotSealed
}

func (s *Store) sealerFor() *Sealer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealer
}

// Acquire marks a slot busy for one refresh and reports false when
// another holder has it. The holder must Release.
func (s *Store) Acquire(slotID string) bool {
	slotID = strings.ToLower(slotID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.busy[slotID]; ok {
		return false
	}
	s.busy[slotID] = struct{}{}
	return true
}

func (s *Store) Release(slotID string) {
	s.mu.Lock()
	delete(s.busy, strings.ToLower(slotID))
	s.mu.Unlock()
}

func (s *Store) Harvest(slotID string, fn func(cur []Slot) ([]Slot, error)) error {
	if !s.Acquire(slotID) {
		return ErrBusy
	}
	defer s.Release(slotID)
	return s.HarvestHeld(slotID, fn)
}

// HarvestHeld rewrites a slot that the caller already holds through
// Acquire. Thus the busy mark can span the origin round trip, not only
// the file write.
func (s *Store) HarvestHeld(slotID string, fn func(cur []Slot) ([]Slot, error)) error {
	slotID = strings.ToLower(slotID)
	fd, err := s.flock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}()
	f, err := loadFile(s.path, s.sealerFor())
	if err != nil {
		return err
	}
	if f.state.Sealed && !f.state.Unlocked {
		return ErrLocked
	}
	var cur []Slot
	for _, v := range f.slots {
		if v.ID == slotID {
			v.Busy = true
			cur = append(cur, v)
		}
	}
	next, err := fn(cur)
	if err != nil {
		return err
	}
	updates := map[string]string{}
	for _, sl := range next {
		if !ValidLive(sl.Live) {
			return ErrBadLive
		}
		updates[EnvKey(sl.ID, sl.Kind)] = sl.Live
	}
	if err := s.writeUpdates(updates); err != nil {
		return err
	}
	s.mu.Lock()
	s.cache = nil
	s.st = stamp{}
	s.mu.Unlock()
	return nil
}

// writeUpdates rewrites the named keys in place. With a sealed store,
// it seals what it writes, and it refuses to write at all without the
// key. That rule stops a plaintext value from ever appearing under a
// sealed header. A store with no file is empty. Any other read error
// stops the write: the rows that it did not read would go out of the
// store.
func (s *Store) writeUpdates(updates map[string]string) error {
	if len(updates) == 0 {
		return nil
	}
	var existing []string
	raw, err := readNoFollow(s.path)
	switch {
	case err == nil:
		existing = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(existing) == 1 && existing[0] == "" {
			existing = nil
		}
	case !os.IsNotExist(err):
		return err
	}
	return s.writeMerged(existing, updates)
}

// writeMerged publishes the store one time: the lines that it gets, with
// each update applied to the row that names it, and appended where no
// row names it. Callers that also remove rows pass the lines that they
// want to keep. Thus to add the replacements and remove the originals is
// one rename, not two. Before, migration did it as two. A failure in
// the gap took the legacy credentials with it, and left nothing slotted
// in their place.
func (s *Store) writeMerged(lines []string, updates map[string]string) error {
	path := s.path
	// Validated before sealing, because after sealing all values look
	// the same. HarvestHeld always checked. The mint, the Claude harvest
	// and migration did not. A value with a newline in it becomes a
	// second line of the file. If that line has the shape of a key, it
	// is a second credential that nobody minted.
	for k, v := range updates {
		if v != "" && !ValidLive(v) {
			return fmt.Errorf("%w: %s", ErrBadLive, k)
		}
	}
	f, err := loadFile(path, nil)
	if err != nil {
		return err
	}
	if f.state.Sealed {
		key := s.sealerFor()
		if key == nil {
			return ErrLocked
		}
		sealed := make(map[string]string, len(updates))
		for k, v := range updates {
			if v == "" {
				sealed[k] = ""
				continue
			}
			sealed[k] = key.Seal(k, v)
		}
		updates = sealed
	}
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range lines {
		stripped := strings.TrimSpace(raw)
		if stripped != "" && !strings.HasPrefix(stripped, "#") && strings.Contains(raw, "=") {
			key := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
			// The update keys come from EnvKey, with a lower-case slot.
			// parseStoreLine also reads a slot in upper case. Thus the
			// file key gets the same form before the lookup. Otherwise
			// the old row stays and the update adds a second row.
			if id, kind, ok := ParseEnvKey(key); ok {
				key = EnvKey(id, kind)
			}
			if v, ok := updates[key]; ok {
				out = append(out, key+"="+v)
				seen[key] = struct{}{}
				continue
			}
		}
		out = append(out, raw)
	}
	for k, v := range updates {
		if _, ok := seen[k]; !ok {
			out = append(out, k+"="+v)
		}
	}
	text := strings.Join(out, "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return replaceFile(path, text)
}

// replaceFile puts the new contents in through a temp file and a
// rename. Thus a reader in a race with the write sees the whole old
// file or the whole new one, and never a half of either.
//
// On purpose, there is no fallback to a truncate of the live file. The
// causes of a staging failure (a full or read-only filesystem, an I/O
// error, a directory that the writer cannot touch) are mostly the same
// causes that make the second write fail. A write that fails after the
// truncate means the loss of all credentials on the box. If this
// returns the staging error, the old store stays unchanged, and the box
// is only one harvest behind. The loss of a harvest that cannot be
// recorded is acceptable. The loss of the store is not.
//
// Before, the reason for the fallback was that the store was in a
// root-owned directory that the broker could not write. vm/pi/apply.sh
// now installs that directory -o pf-broker so that the rewrite can be a
// rename. Thus the last caller that needed truncate-in-place is gone.
func replaceFile(path, text string) error {
	tmp, err := stage(path, []byte(text))
	if err != nil {
		return err
	}
	// Rename makes a new inode that belongs to the user that runs
	// this: root for pf enroll. The broker runs as pf-broker and must
	// still be able to open the file after. Thus copy the old owner across.
	keepOwner(path, tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return syncDir(path)
}

// stage writes data to a fresh file beside path and returns its name.
//
// Before, the staging name was path + ".tmp". That gave two problems.
// First, it is guessable, and the broker can write to the store
// directory. Thus anything that could put a symlink there could send
// the whole file of credentials to the target of the symlink: the open
// had neither O_EXCL nor O_NOFOLLOW. Second, it is shared. Thus two
// writers in a race stage into the same name, and one renames the
// half-built file of the other over the store. CreateTemp solves both:
// a name that nobody can predict, created exclusively or not at all.
func stage(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(f.Name(), 0600)
	}
	if werr != nil {
		_ = os.Remove(f.Name())
		return "", werr
	}
	return f.Name(), nil
}

// syncDir flushes the directory that holds path. A rename is on disk
// only after the directory entry that names it is on disk. Without
// this, a power loss immediately after a harvest can come back to the
// pre-harvest file, with the new inode orphaned. The credential was
// spent at the origin, and the store no longer has what it got in exchange.
func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// keepOwner gives tmp the uid and gid of path when they are different
// from those of the caller. Only root can chown, and only root needs to.
func keepOwner(path, tmp string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if int(st.Uid) == os.Getuid() && int(st.Gid) == os.Getgid() {
		return
	}
	_ = os.Chown(tmp, int(st.Uid), int(st.Gid))
}

func readNoFollow(path string) ([]byte, error) {
	if testHookRead != nil {
		if err := testHookRead(path); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
