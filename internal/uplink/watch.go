package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
)

// state is what the watcher keeps between two checks (StateFile). It is
// for one boot: a new boot ID starts it again. Thus a down period before a
// power cycle does not become the down time of an alert after it.
type state struct {
	Boot string `json:"boot,omitempty"`
	// DownSince is the first check of this down period that found the
	// connection not up. Zero while the uplink is up.
	DownSince time.Time `json:"down_since,omitzero"`
	// Seen counts the checks of this down period. Streak counts the checks
	// in a row that found the connection not active and not activating.
	Seen   int `json:"seen,omitempty"`
	Streak int `json:"streak,omitempty"`
	// Tries counts the `nmcli connection up` runs of this down period. Fails
	// counts the failed runs in a row.
	Tries   int       `json:"tries,omitempty"`
	Fails   int       `json:"fails,omitempty"`
	LastTry time.Time `json:"last_try,omitzero"`
	// Said is the key of the last one-time note (no record, no
	// NetworkManager, ...). The same note is not said again until the
	// condition changes.
	Said string `json:"said,omitempty"`
}

// calm ends the down period with no alert. The watcher cannot act on it.
func (s *state) calm() {
	*s = state{Boot: s.Boot, Said: s.Said}
}

// due reports whether a try may run now: MinGap after the last try, and
// BackoffEvery after BackoffAfter failed tries in a row.
func (s state) due(now time.Time) bool {
	if s.LastTry.IsZero() {
		return true
	}
	gap := MinGap
	if s.Fails >= BackoffAfter {
		gap = BackoffEvery
	}
	return !now.Before(s.LastTry.Add(gap))
}

// Watcher is one check of pf uplink watch.
type Watcher struct {
	// Record is the path of the record (DefaultRecord). Dir holds the state
	// and the event file (DefaultDir).
	Record string
	Dir    string
	NM     Runner
	Now    func() time.Time
	// Out gets one line for each action and each change. The unit sends it
	// to the journal.
	Out io.Writer
	// BootID gives the ID of this boot. nil reads bootIDPath.
	BootID func() string
	// Wait is the --wait of `nmcli connection up`. 0 is UpWait.
	Wait time.Duration
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) say(format string, a ...any) {
	out := w.Out
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "uplink: "+format+"\n", a...)
}

// note says a line one time, until the condition with that key changes.
func (w *Watcher) note(st *state, key, format string, a ...any) {
	if st.Said == key {
		return
	}
	st.Said = key
	w.say(format, a...)
}

func (w *Watcher) bootID() string {
	if w.BootID != nil {
		return w.BootID()
	}
	raw, _ := os.ReadFile(bootIDPath)
	return strings.TrimSpace(string(raw))
}

func (w *Watcher) statePath() string  { return filepath.Join(w.Dir, StateFile) }
func (w *Watcher) eventsPath() string { return filepath.Join(w.Dir, EventsFile) }

// load reads the state, and gives the bytes that it read. A state that
// does not parse, or is from another boot, starts again. A time after now
// is from a clock that moved back (a Pi with no RTC battery, before NTP).
// It must not hold a try back.
func (w *Watcher) load(now time.Time) (state, []byte) {
	boot := w.bootID()
	var st state
	raw, err := os.ReadFile(w.statePath())
	if err == nil && json.Unmarshal(raw, &st) != nil {
		st = state{}
	}
	if st.Boot != boot {
		st = state{Boot: boot}
	}
	if st.DownSince.After(now) {
		st.DownSince = now
	}
	if st.LastTry.After(now) {
		st.LastTry = time.Time{}
	}
	return st, raw
}

// save writes the state when it is not the same as the bytes that load
// read. While the uplink is up, a check changes nothing. Thus a gateway on
// an SD card does not write a file each 30 s.
func (w *Watcher) save(st state, old []byte) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if bytes.Equal(raw, old) {
		return nil
	}
	if err := os.MkdirAll(w.Dir, 0o755); err != nil {
		return err
	}
	return writeFile(w.statePath(), raw)
}

// Check is one run of the watcher. It returns an error only when it could
// not keep its state or write its event row. A connection that does not
// come up is not an error: the next check tries again.
func (w *Watcher) Check(ctx context.Context) error {
	now := w.now()
	st, old := w.load(now)
	err := w.check(ctx, &st, now)
	if serr := w.save(st, old); err == nil {
		err = serr
	}
	return err
}

func (w *Watcher) nm() Runner {
	if w.NM != nil {
		return w.NM
	}
	return Exec
}

func (w *Watcher) check(ctx context.Context, st *state, now time.Time) error {
	rec, err := LoadRecord(w.Record)
	if err != nil {
		why := err.Error()
		if errors.Is(err, fs.ErrNotExist) {
			why = "no " + w.Record
		}
		w.note(st, "record", "no uplink record (%s); the watchdog does nothing until pf apply records the uplink connection", why)
		st.calm()
		return nil
	}
	nm := w.nm()
	act, err := active(ctx, nm)
	if err != nil {
		w.note(st, "nm", "NetworkManager does not answer (%v); no action", err)
		return nil
	}
	for _, c := range act {
		if c.UUID != rec.UUID {
			continue
		}
		if c.State == "activated" {
			return w.up(st, rec, now)
		}
		// activating or deactivating: NetworkManager is at work on it. The
		// watcher waits, and the streak starts again.
		if st.DownSince.IsZero() {
			st.DownSince = now
			w.say("%q (%s) on %s is %s; NetworkManager is at work, no action", short(rec.Name), rec.UUID, rec.Device, short(c.State))
		}
		st.Seen++
		st.Streak = 0
		st.Said = ""
		return nil
	}
	devs, err := devices(ctx, nm)
	if err != nil {
		w.note(st, "nm", "NetworkManager does not answer (%v); no action", err)
		return nil
	}
	if s, ok := devs[rec.Device]; ok && notNM(s) {
		w.note(st, "unmanaged "+rec.Device, "%s is %s: NetworkManager does not manage it; no action", rec.Device, short(s))
		st.calm()
		return nil
	}
	for _, c := range act {
		if c.Device == rec.Device && link(c) {
			w.note(st, "held "+c.UUID, "%s carries %q (%s), not the recorded %q (%s); no action. pf apply records the new uplink",
				rec.Device, short(c.Name), c.UUID, short(rec.Name), rec.UUID)
			st.calm()
			return nil
		}
	}
	known, err := profiles(ctx, nm)
	if err != nil {
		w.note(st, "nm", "NetworkManager does not answer (%v); no action", err)
		return nil
	}
	if !known[rec.UUID] {
		w.note(st, "gone "+rec.UUID, "the recorded connection %q (%s) is not in NetworkManager; no action until pf apply records the uplink again", short(rec.Name), rec.UUID)
		st.calm()
		return nil
	}
	st.Said = ""
	st.Seen++
	st.Streak++
	if st.DownSince.IsZero() {
		st.DownSince = now
	}
	if st.Streak < ConfirmChecks {
		w.say("%q (%s) on %s is not active; the watchdog acts if the next check finds it so", short(rec.Name), rec.UUID, rec.Device)
		return nil
	}
	if !st.due(now) {
		return nil
	}
	w.try(ctx, st, rec)
	return nil
}

// try runs `nmcli connection up` one time. A root process gets the
// activation from NetworkManager without a polkit agent. NetworkManager
// does not block a manual activation as it blocks its own autoconnect.
func (w *Watcher) try(ctx context.Context, st *state, rec Record) {
	wait := w.Wait
	if wait <= 0 {
		wait = UpWait
	}
	st.Tries++
	w.say("%q (%s) on %s is not active for %d checks; nmcli connection up, try %d", short(rec.Name), rec.UUID, rec.Device, st.Streak, st.Tries)
	ctx, cancel := context.WithTimeout(ctx, wait+15*time.Second)
	defer cancel()
	_, err := w.nm()(ctx, "--wait", strconv.Itoa(int(wait/time.Second)), "connection", "up", "uuid", rec.UUID)
	st.LastTry = w.now()
	if err == nil {
		st.Fails = 0
		w.say("nmcli connection up %s: done", rec.UUID)
		return
	}
	st.Fails++
	w.say("nmcli connection up %s failed (%d in a row): %v", rec.UUID, st.Fails, err)
	if st.Fails == BackoffAfter {
		w.say("%d tries failed in a row; now one try each %s until the uplink is back", BackoffAfter, BackoffEvery)
	}
}

// up is a check that found the connection activated. After a down period
// of two checks or more, or after a try, it writes one event row: pf alert
// posts it, now that the uplink can carry the post. A one-check drop (a
// Wi-Fi roam, a short reconnect) gets a journal line only.
func (w *Watcher) up(st *state, rec Record, now time.Time) error {
	if st.DownSince.IsZero() {
		st.Said = ""
		return nil
	}
	down := now.Sub(st.DownSince).Truncate(time.Second)
	if st.Tries == 0 && st.Seen < ConfirmChecks {
		w.say("%q (%s) on %s is active again after %s; NetworkManager did it, no alert for a short drop", short(rec.Name), rec.UUID, rec.Device, down)
		*st = state{Boot: st.Boot}
		return nil
	}
	if err := w.event(rec, now, down, st.Tries); err != nil {
		w.say("%q (%s) is active again, but the alert row was not written (%v); the next check tries again", short(rec.Name), rec.UUID, err)
		return err
	}
	w.say("%q (%s) on %s is active again after %s down, %d tries by the watchdog; alert queued", short(rec.Name), rec.UUID, rec.Device, down, st.Tries)
	*st = state{Boot: st.Boot}
	return nil
}

// Event is one row of EventsFile. The fields that pf alert reads have the
// names of the other alert rows: threat, rule, where (the device) and host
// (the connection name).
type Event struct {
	TS     time.Time `json:"ts"`
	Threat string    `json:"threat"`
	Rule   string    `json:"rule"`
	Where  string    `json:"where"`
	Host   string    `json:"host"`
	UUID   string    `json:"uuid"`
	DownS  int64     `json:"down_s"`
	Tries  int       `json:"tries"`
}

// event appends one row with one write. When the file is over eventsMax,
// it goes to EventsFile.1 first. pf alert follows the rename: it reads the
// old file to its end before it opens the new one.
func (w *Watcher) event(rec Record, now time.Time, down time.Duration, tries int) error {
	raw, err := json.Marshal(Event{
		TS: now.UTC().Truncate(time.Second), Threat: jsonl.UplinkThreat, Rule: backRule,
		Where: rec.Device, Host: rec.Name, UUID: rec.UUID, DownS: int64(down / time.Second), Tries: tries,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(w.Dir, 0o755); err != nil {
		return err
	}
	p := w.eventsPath()
	if fi, err := os.Stat(p); err == nil && fi.Size() > eventsMax {
		if err := os.Rename(p, p+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Show writes the record and the state of the last check, for pf status.
func Show(recordPath, dir string, out io.Writer) {
	rec, err := LoadRecord(recordPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintln(out, "record: none; the watchdog does nothing (no NetworkManager uplink, or no pf apply yet)")
	case err != nil:
		fmt.Fprintf(out, "record: unusable (%v); the watchdog does nothing\n", err)
	default:
		at := ""
		if !rec.At.IsZero() {
			at = ", recorded " + rec.At.Format(time.RFC3339)
		}
		fmt.Fprintf(out, "record: %q (%s) on %s%s\n", short(rec.Name), rec.UUID, rec.Device, at)
	}
	raw, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		fmt.Fprintln(out, "last check: none yet")
		return
	}
	var st state
	if json.Unmarshal(raw, &st) != nil {
		fmt.Fprintln(out, "last check: state file does not parse")
		return
	}
	if st.DownSince.IsZero() {
		fmt.Fprintln(out, "last check: up, or nothing to watch")
		return
	}
	line := fmt.Sprintf("last check: not up since %s (%d checks), %d tries, %d failed in a row", st.DownSince.Format(time.RFC3339), st.Seen, st.Tries, st.Fails)
	if !st.LastTry.IsZero() {
		line += ", last try " + st.LastTry.Format(time.RFC3339)
	}
	fmt.Fprintln(out, line)
}
