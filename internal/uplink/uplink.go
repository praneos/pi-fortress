// Package uplink keeps the uplink connection of the gateway up.
//
// NetworkManager can stop its retries for a connection and wait for a
// person. One example: a Wi-Fi handshake fails one time, NetworkManager
// asks a secret agent for a new key, no agent answers, and NetworkManager
// marks the activation failed and blocks the autoconnect of that
// connection. The stored key is still correct. A manual `nmcli connection
// up` works at once. But a gateway has nobody at a terminal, so all of its
// networks stay without internet until a power cycle.
//
// Two parts:
//   - Recorder (pf uplink record, from apply) writes the NetworkManager
//     connection that carries the uplink device to a root-owned record, by
//     UUID. It never records a connection that pf made.
//   - Watcher (pf uplink watch, from pi-fortress-uplink-watch.timer) reads
//     the record. When that connection is not active, and NetworkManager is
//     not at work on it, for two checks in a row, it runs `nmcli connection
//     up`. When the uplink is back, it writes one row to its event file.
//     pf alert tails that file and posts the row (internal/alert).
//
// The watcher does nothing on a box where NetworkManager does not manage
// the uplink.
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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	// DefaultRecord is the record of the uplink connection. Only apply
	// (root) writes it. The watch unit cannot write it: ProtectSystem=strict
	// makes it read-only there.
	DefaultRecord = "/var/lib/pi-fortress/uplink.json"
	// DefaultDir is the StateDirectory of the watch unit: the state of the
	// checks and the event file.
	DefaultDir = "/var/lib/pi-fortress/uplink"
	// StateFile and EventsFile are in DefaultDir. pf alert tails EventsFile
	// (alert.Defaults).
	StateFile  = "watch.json"
	EventsFile = "events.jsonl"

	// ConfirmChecks is the number of checks in a row that must find the
	// connection not active, and not activating, before the watcher acts.
	// Thus the watcher does not fight NetworkManager while it connects.
	ConfirmChecks = 2
	// BackoffAfter failed tries in a row, the watcher tries one time each
	// BackoffEvery. It never stops.
	BackoffAfter = 3
	BackoffEvery = 5 * time.Minute
	// MinGap is the minimum time between two tries, also when the timer
	// fires more often or an operator starts the unit by hand.
	MinGap = 20 * time.Second
	// UpWait is the --wait of `nmcli connection up`. The unit gives the
	// command more time than this (TimeoutStartSec).
	UpWait = 45 * time.Second

	queryTimeout = 15 * time.Second
	eventsMax    = 256 << 10
	bootIDPath   = "/proc/sys/kernel/random/boot_id"
	backRule     = "uplink_back"
)

// Runner runs nmcli with args. It gives the standard output.
type Runner func(ctx context.Context, args ...string) (string, error)

// ErrNoNM is the error of Exec when nmcli is not installed. Then the box
// has no NetworkManager.
var ErrNoNM = errors.New("nmcli is not installed")

// Exec runs nmcli from PATH, with LC_ALL=C: the states are parsed as words,
// so they must be in English. An error carries the first line of the
// diagnostic of nmcli, made printable.
func Exec(ctx context.Context, args ...string) (string, error) {
	path, err := exec.LookPath("nmcli")
	if err != nil {
		return "", ErrNoNM
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := short(errb.String())
		if msg == "" {
			msg = short(out.String())
		}
		if msg != "" {
			return out.String(), fmt.Errorf("%w: %s", err, msg)
		}
		return out.String(), err
	}
	return out.String(), nil
}

// short is the first line of s, at most 200 bytes, with each rune that is
// not printable changed to '?'. The text comes from NetworkManager, and
// a connection name in it comes from the operator or a network.
func short(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, strings.ToValidUTF8(s, "?"))
}

// fields splits one line of `nmcli -t` output. nmcli writes a ':' in a
// value as '\:', and a '\' as '\\'. A connection name can have a ':'.
func fields(line string) []string {
	var out []string
	var b strings.Builder
	esc := false
	for _, r := range line {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

// conn is one row of `nmcli connection show --active`.
type conn struct{ UUID, Type, Device, State, Name string }

func lines(out string) []string {
	var l []string
	for line := range strings.SplitSeq(out, "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" {
			l = append(l, line)
		}
	}
	return l
}

func active(ctx context.Context, nm Runner) ([]conn, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := nm(ctx, "-t", "-f", "UUID,TYPE,DEVICE,STATE,NAME", "connection", "show", "--active")
	if err != nil {
		return nil, err
	}
	var cs []conn
	for _, line := range lines(out) {
		f := fields(line)
		if len(f) != 5 {
			continue
		}
		cs = append(cs, conn{UUID: f[0], Type: f[1], Device: f[2], State: f[3], Name: f[4]})
	}
	return cs, nil
}

// devices is `nmcli device status`: the state of each device that
// NetworkManager knows, by name.
func devices(ctx context.Context, nm Runner) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := nm(ctx, "-t", "-f", "DEVICE,STATE", "device", "status")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range lines(out) {
		if f := fields(line); len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	return m, nil
}

// profiles is the set of UUIDs of all connection profiles.
func profiles(ctx context.Context, nm Runner) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := nm(ctx, "-t", "-f", "UUID", "connection", "show")
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, line := range lines(out) {
		m[fields(line)[0]] = true
	}
	return m, nil
}

// notNM reports whether a device state means that NetworkManager does not
// manage the device: unmanaged, or configured by another tool
// ("connected (externally)"), as ifupdown or systemd-networkd do.
func notNM(state string) bool {
	return state == "unmanaged" || strings.Contains(state, "externally")
}

// link reports whether an active connection is the link of its device. A
// VPN connection shows the device that it goes over, and is not the
// uplink connection.
func link(c conn) bool { return c.Type != "vpn" && c.Type != "loopback" }

// pfMade reports whether pf made the connection: agent-net and house-net
// (apply.sh), seg-<name>, trunk-<if> and pf-parked-<if>
// (vm/pi/lib/netman.sh). Such a connection is never the uplink.
func pfMade(name string) bool {
	switch name {
	case "agent-net", "house-net":
		return true
	}
	for _, p := range []string{"seg-", "trunk-", "pf-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Record is the uplink connection, as apply found it.
type Record struct {
	UUID   string    `json:"uuid"`
	Name   string    `json:"name"`
	Device string    `json:"device"`
	Type   string    `json:"type,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// ifRe is an interface name as render accepts it for WAN_IF (reIface in
	// internal/render).
	ifRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,14}$`)
)

func (r Record) check() error {
	switch {
	case !uuidRe.MatchString(r.UUID):
		return fmt.Errorf("uuid %q is not a UUID", short(r.UUID))
	case !ifRe.MatchString(r.Device):
		return fmt.Errorf("device %q is not an interface name", short(r.Device))
	case r.Name == "" || len(r.Name) > 255:
		return errors.New("no connection name")
	}
	return nil
}

// LoadRecord reads the record at path. A record that does not parse, or
// that names no UUID and device, is an error: the watcher then does
// nothing, as with no record.
func LoadRecord(path string) (Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := r.check(); err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// writeFile replaces path with data through a rename in the same
// directory. Thus a reader never sees half a file.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// Recorder is the apply step: it records the connection that carries the
// uplink device.
type Recorder struct {
	Path string
	NM   Runner
	Now  func() time.Time
	Out  io.Writer
}

func (r *Recorder) say(format string, a ...any) {
	fmt.Fprintf(r.Out, "pi-fortress: uplink watchdog: "+format+"\n", a...)
}

// clear removes the record. The watcher then does nothing, and says so.
func (r *Recorder) clear() error {
	if err := os.Remove(r.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// keep leaves the last record when it is for dev. A record for another
// device is not the uplink now, so it goes.
func (r *Recorder) keep(dev, why string) error {
	old, err := LoadRecord(r.Path)
	if err == nil && old.Device == dev {
		r.say("%s; the last record stays: %q (%s)", why, old.Name, old.UUID)
		return nil
	}
	if err == nil {
		r.say("%s; the last record was for %s, not %s, and is removed. Run sudo pf apply again when the uplink is up", why, old.Device, dev)
		return r.clear()
	}
	r.say("%s; nothing is recorded. Run sudo pf apply again when the uplink is up", why)
	return nil
}

// Record writes the connection that carries dev (WAN_IF, after pf render:
// the device of the IPv4 default route, or the one that net.env names).
//   - The active link connection on dev, when pf did not make it: recorded.
//   - No NetworkManager (no nmcli), or NetworkManager does not manage dev:
//     the record is removed, and the watcher does nothing.
//   - NetworkManager does not answer, dev has no active connection (the
//     uplink is down now), or the connection is one that pf made: the last
//     record stays when it is for dev.
func (r *Recorder) Record(ctx context.Context, dev string) error {
	if !ifRe.MatchString(dev) {
		return fmt.Errorf("uplink record: %q is not an interface name", short(dev))
	}
	nm := r.NM
	if nm == nil {
		nm = Exec
	}
	devs, err := devices(ctx, nm)
	if errors.Is(err, ErrNoNM) {
		r.say("no NetworkManager on this box; the watchdog has nothing to do")
		return r.clear()
	}
	if err != nil {
		return r.keep(dev, fmt.Sprintf("NetworkManager does not answer (%v)", err))
	}
	st, ok := devs[dev]
	if !ok || notNM(st) {
		if !ok {
			st = "not known to NetworkManager"
		}
		r.say("%s is %s; the watchdog has nothing to do", dev, st)
		return r.clear()
	}
	act, err := active(ctx, nm)
	if err != nil {
		return r.keep(dev, fmt.Sprintf("NetworkManager does not answer (%v)", err))
	}
	var got *conn
	for i, c := range act {
		if c.Device == dev && link(c) && c.State == "activated" {
			got = &act[i]
			break
		}
	}
	if got == nil {
		return r.keep(dev, fmt.Sprintf("%s has no active connection now (%s)", dev, st))
	}
	if pfMade(got.Name) {
		return r.keep(dev, fmt.Sprintf("WARNING %s carries %q, a connection that pf made, not an uplink connection", dev, short(got.Name)))
	}
	rec := Record{UUID: got.UUID, Name: got.Name, Device: dev, Type: got.Type}
	if err := rec.check(); err != nil {
		return r.keep(dev, fmt.Sprintf("NetworkManager gave a connection that cannot be recorded (%v)", err))
	}
	if old, err := LoadRecord(r.Path); err == nil && old.UUID == rec.UUID && old.Name == rec.Name && old.Device == rec.Device {
		r.say("%q (%s) on %s, as before", short(rec.Name), rec.UUID, dev)
		return nil
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	rec.At = now().UTC().Truncate(time.Second)
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := writeFile(r.Path, append(raw, '\n')); err != nil {
		return fmt.Errorf("uplink record: %w", err)
	}
	r.say("recorded %q (%s) on %s", short(rec.Name), rec.UUID, dev)
	return nil
}
