package www

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"pi-fortress/internal/base"
)

const (
	ledgerMax = 1 << 20
	ledgerCap = 2 << 20
)

// Event is one enrollment ledger line: issued (TUI), redeemed and
// setup (www).
type Event struct {
	Ev   string `json:"ev"`
	T    string `json:"t"`
	Code string `json:"code,omitempty"`
	Slot string `json:"slot,omitempty"`
	IP   string `json:"ip,omitempty"`
	UID  int    `json:"uid,omitempty"`
	Path string `json:"path,omitempty"`
}

func LedgerPath(claimsDir string) string { return filepath.Join(claimsDir, "ledger.jsonl") }

// openLedger opens the ledger by name, and never follows what that name
// points at. The claims directory is group-writable, so that www can rename
// claim files in it (vm/pi/apply.sh installs it 2770 root:pf-fortress).
// This also lets a compromised www unlink ledger.jsonl and put a symlink,
// or a second hard link, in its place. Root issues claims through this same
// path. Without O_NOFOLLOW and the checks below, one unprivileged unlink
// turns `pf claim` into an append to any file on the gateway. A ledger that
// the deployment created is a regular file with exactly one link. All else
// is the attack, not a state to repair in place. O_NONBLOCK is for a FIFO
// in the place of the name. Without it, the read end or the write end waits
// for the other end, and the TUI of root, pf claim and pf apply hang on it.
// With it, the open returns (or fails) immediately, and the regular-file
// check below refuses the FIFO. On a regular file, it changes nothing.
func openLedger(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0660)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("ledger: not a regular file: " + path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
		f.Close()
		return nil, errors.New("ledger: more than one link to " + path)
	}
	return f, nil
}

// InitLedger makes the ledger, or repairs it. The owner of the ledger is
// the caller, the group is the group of the claims directory, and the mode
// is 0660. Thus both appenders can write it. It
// works through the descriptor that openLedger gives back. apply runs this
// as root on each pass. A chown or chmod by name in a directory that www
// can write would apply to whatever www left in the place of the name.
func InitLedger(claimsDir string) error {
	fi, err := os.Stat(claimsDir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ledger: no owner for " + claimsDir)
	}
	f, err := openLedger(LedgerPath(claimsDir), os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		return err
	}
	err = f.Chown(os.Getuid(), int(st.Gid))
	if err == nil {
		err = f.Chmod(0660)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// rotate stops the ledger before it fills the partition that it shares
// with the broker store and the audit log. Nothing else bounds it. The file
// is under /var/lib, which the hourly logrotate run never reads. Sweep
// does not remove it, because the name ends .jsonl, not .json. rotate keeps
// only one generation, which is one generation more than ReadLedger reads.
// Two appenders can race here, and the rename of the loser drops a
// generation early. The loss of old enrollment lines is the cheap outcome.
// We choose it over an unbounded file.
func rotate(path string, f *os.File) (*os.File, error) {
	fi, err := f.Stat()
	if err != nil || fi.Size() < ledgerCap {
		return f, nil
	}
	f.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		return nil, err
	}
	nf, err := openLedger(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		return nil, err
	}
	// The code sets the mode, and does not leave it to the open. The umask
	// removes the group write bit from 0660, and the two appenders are not the
	// same principal. apply.sh makes the first ledger 0660 root:pf-fortress.
	// But root or www makes this one: the one of the two that filled the last
	// one. The group is already correct, because the claims directory is
	// setgid. Without this, the other appender loses the file at the first
	// rotation, and the ledger quietly stops the record of enrolments.
	if err := nf.Chmod(0660); err != nil {
		nf.Close()
		return nil, err
	}
	return nf, nil
}

// AppendEvent writes one line. The file is group-writable, because www
// (DynamicUser, group pf-fortress) and root both append.
func AppendEvent(claimsDir string, ev Event) error {
	if ev.T == "" {
		ev.T = base.NowISO(nil)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := openLedger(LedgerPath(claimsDir), os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		return err
	}
	if f, err = rotate(LedgerPath(claimsDir), f); err != nil {
		return err
	}
	_, werr := f.Write(append(raw, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ReadLedger returns the events in the last MiB of the ledger.
func ReadLedger(claimsDir string) []Event {
	ev, _ := ReadLedgerCovering(claimsDir)
	return ev
}

// ReadLedgerCovering returns the same events, and whether they are all the
// events. A count from this is a tail when a rotated generation exists, or
// when the live one is longer than the window. A caller that prints a tail
// as a total tells its reader that enrolments were undone each time the
// ledger rotates.
func ReadLedgerCovering(claimsDir string) (events []Event, partial bool) {
	if _, err := os.Lstat(LedgerPath(claimsDir) + ".1"); err == nil {
		partial = true
	}
	f, err := openLedger(LedgerPath(claimsDir), os.O_RDONLY)
	if err != nil {
		return nil, partial
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > ledgerMax {
		_, _ = f.Seek(fi.Size()-ledgerMax, io.SeekStart)
		r := bufio.NewReader(f)
		_, _ = r.ReadString('\n')
		return decodeEvents(r), true
	}
	return decodeEvents(bufio.NewReader(f)), partial
}

func decodeEvents(r *bufio.Reader) []Event {
	var out []Event
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Ev != "" {
			out = append(out, ev)
		}
	}
	return out
}
