package ship

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"pi-fortress/internal/jsonl"
)

// DefaultPendingPath and DefaultPendingTTL are the confirm-or-revert
// timer of pf ship install. An upgrade that passes the post-upgrade
// doctor still arms this before it is trusted, the same as "commit
// confirmed" on a router.
const (
	DefaultPendingPath = "/var/lib/pi-fortress/ship.pending"
	DefaultPendingTTL  = 10 * time.Minute
)

// Pending is the armed state that an unconfirmed upgrade leaves behind.
// pf ship deadman rolls back to PrevVersion after Deadline has passed and
// nothing has confirmed. pf ship confirm only removes the file.
type Pending struct {
	Version     int64     `json:"version"`
	PrevVersion int64     `json:"prev_version"`
	Deadline    time.Time `json:"deadline"`
}

// ErrPendingUnreadable is a pending file that is there but cannot be
// read, or does not hold a whole Pending. Only an install writes the
// file, so it stands for an upgrade that nobody has confirmed. pf ship
// deadman treats it as due and reverts to whatever Dir.prev holds. pf
// ship confirm clears it. Neither of them fails on it each minute
// forever.
var ErrPendingUnreadable = errors.New("ship.pending is unreadable")

// WritePending writes p to path, root-only, and replaces whatever was
// there. It is best-effort by design. A ship that already swapped and
// applied cleanly must not be undone because the safety-net file could
// not be written. Thus callers log a failure here, and do not roll back
// over it. The file and its directory entry are flushed before this
// returns. The reboot that an upgrade most often causes is exactly when
// an armed timer must still be there.
func WritePending(path string, p Pending) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ship.pending-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(raw)
	if werr == nil {
		werr = tmp.Chmod(0600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	cerr := tmp.Close()
	if werr != nil {
		os.Remove(name)
		return werr
	}
	if cerr != nil {
		os.Remove(name)
		return cerr
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return syncDir(path)
}

// ReadPending reads path. ok is false when there is no armed upgrade.
// That is the ordinary state of a confirmed box. A file that is there
// but unreadable, empty or incomplete returns ok true with an error
// that wraps ErrPendingUnreadable: it is armed, and only its contents
// are unknown.
func ReadPending(path string) (Pending, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, true, fmt.Errorf("%w: %s: %v", ErrPendingUnreadable, path, err)
	}
	var p Pending
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pending{}, true, fmt.Errorf("%w: %s: %v", ErrPendingUnreadable, path, err)
	}
	if p.Version <= 0 || p.PrevVersion < 0 {
		return Pending{}, true, fmt.Errorf("%w: %s: no upgrade named in %q", ErrPendingUnreadable, path, raw)
	}
	return p, true, nil
}

// RemovePending clears the armed state. The removal of a file that is
// already gone is not an error: confirm and deadman both call this,
// and only one of them should find something to remove.
func RemovePending(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(path)
}

// Confirm is pf ship confirm: disarm the dead-man timer on an upgrade
// that has proven itself. ok is false when nothing was pending. An
// unreadable pending file is also cleared, with the reason in the row.
// The confirm of the operator is the decision that the file waited
// for, whatever it said.
func (in *Installer) Confirm() (jsonl.Ship, bool, error) {
	path := in.pendingPath()
	p, ok, perr := ReadPending(path)
	if perr != nil && !errors.Is(perr, ErrPendingUnreadable) {
		return jsonl.Ship{}, false, perr
	}
	if !ok {
		return jsonl.Ship{}, false, nil
	}
	if err := RemovePending(path); err != nil {
		return jsonl.Ship{}, false, err
	}
	row := jsonl.Ship{Result: "confirm", Version: p.Version, Reason: fmt.Sprintf("upgrade from %d confirmed", p.PrevVersion)}
	if perr != nil {
		row.Reason = fmt.Sprintf("confirmed and cleared: %v", perr)
	}
	in.record(row)
	return row, true, nil
}

// Deadman is pf ship deadman, run by ship-deadman.timer. now is passed
// in, so a test controls it. The OnBootSec/OnUnitActiveSec cadence of
// the timer makes an unconfirmed upgrade revert itself even across a
// reboot. A transient systemd-run timer would not survive a reboot.
//
// The pending file goes only after the previous tree is live again, or
// when there is no previous tree to put back, and thus nothing that a
// retry could change. A rollback that did not occur (the apply lock was
// held by the TUI or a feed refresh) keeps it, logs deadman_failed and
// returns an error. The run in the next minute tries again.
func (in *Installer) Deadman(now time.Time) (jsonl.Ship, bool, error) {
	path := in.pendingPath()
	p, ok, perr := ReadPending(path)
	if perr != nil && !errors.Is(perr, ErrPendingUnreadable) {
		return jsonl.Ship{}, false, perr
	}
	if !ok {
		return jsonl.Ship{}, false, nil
	}
	why := fmt.Errorf("upgrade to %d was never confirmed by its %s deadline", p.Version, p.Deadline.Format(time.RFC3339))
	if perr != nil {
		prev, err := readStamp(in.Dir + ".prev")
		if err != nil {
			row := jsonl.Ship{Result: "deadman_failed", Reason: fmt.Sprintf("%v; and the previous tree's version cannot be read: %v; ship.pending kept", perr, err)}
			// The timer runs each minute, and this state does not change
			// until the operator acts. Thus only a new reason gets a row
			// and an alert.
			if last, ok := jsonl.LastShip(in.Log); !ok || last.Result != row.Result || last.Reason != row.Reason {
				in.record(row)
			}
			return row, true, fmt.Errorf("pf ship deadman: %v; and the previous tree's version cannot be read: %w", perr, err)
		}
		p = Pending{PrevVersion: prev}
		why = fmt.Errorf("%v; treated as an unconfirmed upgrade", perr)
	} else if now.Before(p.Deadline) {
		return jsonl.Ship{}, false, nil
	}
	res := in.rollback(p.PrevVersion, why)
	if res.restored || errors.Is(res.err, errNoPrev) {
		RemovePending(path)
		row := jsonl.Ship{Result: "deadman", Version: p.PrevVersion, Reason: res.err.Error()}
		in.record(row)
		return row, true, nil
	}
	row := jsonl.Ship{Result: "deadman_failed", Version: p.Version, Reason: res.err.Error() + "; ship.pending kept, the next run retries"}
	in.record(row)
	return row, true, fmt.Errorf("pf ship deadman: the rollback to %d did not happen: %v", p.PrevVersion, res.err)
}

func (in *Installer) pendingPath() string {
	if in.PendingPath != "" {
		return in.PendingPath
	}
	return DefaultPendingPath
}
