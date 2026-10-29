package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/alert"
	"pi-fortress/internal/jsonl"
)

const (
	homeUUID  = "0b5e6b84-3c1d-4f7e-9a51-2a3f1c9d7e11"
	agentUUID = "6f1c2d3e-4b5a-4978-8a6b-1c2d3e4f5a6b"
	vpnUUID   = "9a8b7c6d-5e4f-4321-8765-0fedcba98765"
	otherUUID = "11111111-2222-4333-8444-555555555555"
)

// fakeNM puts a fake nmcli first on PATH. It answers from files in its
// directory: active (connection show --active), devices (device status),
// profiles (connection show) and up-rc (the exit code of connection up).
// The file nm-down makes each call fail as a stopped NetworkManager does.
// argv gets one line for each call, and env the LC_ALL of each call. The
// script uses only shell builtins.
type fakeNM struct{ dir string }

const fakeScript = `#!/bin/sh
d="$FAKE_NM"
printf '%s\n' "$*" >>"$d/argv"
printf '%s\n' "$LC_ALL" >>"$d/env"
if [ -e "$d/nm-down" ]; then
  echo 'Error: NetworkManager is not running.' >&2
  exit 8
fi
case "$*" in
  "-t -f UUID,TYPE,DEVICE,STATE,NAME connection show --active") f=active ;;
  "-t -f DEVICE,STATE device status") f=devices ;;
  "-t -f UUID connection show") f=profiles ;;
  "--wait "*" connection up uuid "*)
    rc=0
    [ -e "$d/up-rc" ] && read -r rc <"$d/up-rc"
    [ "$rc" = 0 ] || echo 'Error: Connection activation failed: Secrets were required, but not provided.' >&2
    exit "$rc" ;;
  *) echo "fake nmcli: unexpected $*" >&2; exit 2 ;;
esac
if [ -e "$d/$f" ]; then
  while IFS= read -r l; do printf '%s\n' "$l"; done <"$d/$f"
fi
exit 0
`

func newFakeNM(t *testing.T) *fakeNM {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "nmcli"), []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	f := &fakeNM{dir: t.TempDir()}
	t.Setenv("FAKE_NM", f.dir)
	return f
}

func (f *fakeNM) set(t *testing.T, name string, rows ...string) {
	t.Helper()
	body := ""
	for _, r := range rows {
		body += r + "\n"
	}
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeNM) calls(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "argv"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func (f *fakeNM) ups(t *testing.T) []string {
	t.Helper()
	var n []string
	for _, c := range f.calls(t) {
		if strings.Contains(c, " connection up ") {
			n = append(n, c)
		}
	}
	return n
}

// The box of most tests: the uplink "home" on wlan0 is a known profile,
// agent-net is up on eth0. down sets wlan0 disconnected with no active
// connection, as NetworkManager leaves it after it gave up.
func (f *fakeNM) box(t *testing.T, wlanState string, activeRows ...string) {
	t.Helper()
	f.set(t, "devices", "eth0:connected", "wlan0:"+wlanState, "lo:unmanaged")
	f.set(t, "profiles", homeUUID, agentUUID)
	f.set(t, "active", append([]string{agentUUID + ":802-3-ethernet:eth0:activated:agent-net"}, activeRows...)...)
}

func (f *fakeNM) up(t *testing.T) {
	f.box(t, "connected", homeUUID+":802-11-wireless:wlan0:activated:home")
}

func (f *fakeNM) down(t *testing.T) { f.box(t, "disconnected") }

type rig struct {
	nm  *fakeNM
	w   *Watcher
	out *bytes.Buffer
	now time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{nm: newFakeNM(t), out: &bytes.Buffer{}, now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	r.w = &Watcher{
		Record: filepath.Join(dir, "uplink.json"), Dir: filepath.Join(dir, "uplink"),
		Now: func() time.Time { return r.now }, Out: r.out, BootID: func() string { return "boot-1" },
	}
	writeRecord(t, r.w.Record, Record{UUID: homeUUID, Name: "home", Device: "wlan0", Type: "802-11-wireless"})
	return r
}

func writeRecord(t *testing.T, path string, rec Record) {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// check runs one check, then moves the clock by step.
func (r *rig) check(t *testing.T, step time.Duration) {
	t.Helper()
	if err := r.w.Check(context.Background()); err != nil {
		t.Fatalf("check: %v\n%s", err, r.out)
	}
	r.now = r.now.Add(step)
}

func (r *rig) events(t *testing.T) []Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.w.Dir, EventsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var evs []Event
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("event row %q: %v", l, err)
		}
		evs = append(evs, e)
	}
	return evs
}

func (r *rig) lines() []string {
	s := strings.TrimSpace(r.out.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestActiveConnectionNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.up(t)
	r.check(t, 30*time.Second)
	first, err := os.Stat(filepath.Join(r.w.Dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		r.check(t, 30*time.Second)
	}
	// A check that changes nothing writes nothing: the file is the same
	// inode, not a new one from a rename.
	if now, err := os.Stat(filepath.Join(r.w.Dir, StateFile)); err != nil || !os.SameFile(first, now) {
		t.Fatalf("the checks of an up uplink rewrote the state file (%v)", err)
	}
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up on an active uplink: %q", ups)
	}
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("an up uplink logged %q", l)
	}
	if ev := r.events(t); len(ev) != 0 {
		t.Fatalf("an up uplink wrote %v", ev)
	}
	// nmcli ran in the C locale: the states are parsed as English words.
	raw, _ := os.ReadFile(filepath.Join(r.nm.dir, "env"))
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "C" {
			t.Fatalf("nmcli ran with LC_ALL=%q", l)
		}
	}
}

func TestNotActiveOnceNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up after one check: %q", ups)
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "is not active") {
		t.Fatalf("first down check logged %q", l)
	}
}

func TestNotActiveTwiceOneUp(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	r.check(t, 30*time.Second)
	ups := r.nm.ups(t)
	if len(ups) != 1 || ups[0] != "--wait 45 connection up uuid "+homeUUID {
		t.Fatalf("connection up calls %q, want one by UUID with a bounded wait", ups)
	}
}

// NetworkManager at work on the connection: no try, also over many
// checks. Activating between two down checks starts the streak again.
func TestActivatingNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.box(t, "connecting (need authentication)", homeUUID+":802-11-wireless:wlan0:activating:home")
	for range 5 {
		r.check(t, 30*time.Second)
	}
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up while NetworkManager activates: %q", ups)
	}
	r.nm.down(t)
	r.check(t, 30*time.Second)
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up on the first down check after activating: %q", ups)
	}
	r.nm.box(t, "connecting (prepare)", homeUUID+":802-11-wireless:wlan0:activating:home")
	r.check(t, 30*time.Second)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("down, activating, down gave a try: %q", ups)
	}
	r.check(t, 30*time.Second)
	if ups := r.nm.ups(t); len(ups) != 1 {
		t.Fatalf("two down checks in a row gave %d tries, want 1", len(ups))
	}
}

// No record: no nmcli call at all, and one line over all checks.
func TestNoRecordSaysOnce(t *testing.T) {
	r := newRig(t)
	if err := os.Remove(r.w.Record); err != nil {
		t.Fatal(err)
	}
	r.nm.down(t)
	for range 4 {
		r.check(t, 30*time.Second)
	}
	if c := r.nm.calls(t); len(c) != 0 {
		t.Fatalf("nmcli ran with no record: %q", c)
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "no uplink record") {
		t.Fatalf("lines %q, want one note", l)
	}
	// A record that does not parse is the same as none.
	if err := os.WriteFile(r.w.Record, []byte(`{"uuid":"x; rm -rf /","name":"home","device":"wlan0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r.check(t, 30*time.Second)
	r.check(t, 30*time.Second)
	if c := r.nm.calls(t); len(c) != 0 {
		t.Fatalf("nmcli ran with a bad record: %q", c)
	}
	if l := r.lines(); len(l) != 1 {
		t.Fatalf("a bad record after no record said more: %q", l)
	}
}

// The recorded UUID is gone from NetworkManager: no try, one line.
func TestUnknownUUIDNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.nm.set(t, "profiles", agentUUID)
	for range 4 {
		r.check(t, 30*time.Second)
	}
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up for a UUID that NetworkManager does not have: %q", ups)
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "is not in NetworkManager") {
		t.Fatalf("lines %q, want one note", l)
	}
}

// A device that NetworkManager does not manage (ifupdown, networkd), or
// that another tool configured: no try, one line.
func TestUnmanagedDeviceNoAction(t *testing.T) {
	for _, st := range []string{"unmanaged", "connected (externally)"} {
		t.Run(st, func(t *testing.T) {
			r := newRig(t)
			r.nm.box(t, st)
			for range 4 {
				r.check(t, 30*time.Second)
			}
			if ups := r.nm.ups(t); len(ups) != 0 {
				t.Fatalf("connection up on a device that NetworkManager does not manage: %q", ups)
			}
			if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "does not manage it") {
				t.Fatalf("lines %q, want one note", l)
			}
		})
	}
}

// NetworkManager is stopped: no try, one line.
func TestNMNotRunningNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.set(t, "nm-down")
	for range 4 {
		r.check(t, 30*time.Second)
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "NetworkManager is not running") {
		t.Fatalf("lines %q, want one note with the cause", l)
	}
	for _, c := range r.nm.calls(t) {
		if strings.Contains(c, " up ") {
			t.Fatalf("connection up with NetworkManager stopped: %q", c)
		}
	}
}

// Another connection holds the uplink device: the owner changed it. No
// try, and pf apply records the new one.
func TestOtherConnectionOnDeviceNoAction(t *testing.T) {
	r := newRig(t)
	r.nm.box(t, "connected", otherUUID+":802-11-wireless:wlan0:activated:phone")
	r.nm.set(t, "profiles", homeUUID, agentUUID, otherUUID)
	for range 4 {
		r.check(t, 30*time.Second)
	}
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up while another connection holds the device: %q", ups)
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "not the recorded") {
		t.Fatalf("lines %q, want one note", l)
	}
}

// Three failed tries, then one try each BackoffEvery. The watcher never
// stops.
func TestBackoffAfterFailures(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.nm.set(t, "up-rc", "4")
	var at []time.Time
	for range 41 { // 0 s to 20 min, each 30 s
		before := len(r.nm.ups(t))
		now := r.now
		r.check(t, 30*time.Second)
		if len(r.nm.ups(t)) > before {
			at = append(at, now)
		}
	}
	// 30 s, 60 s and 90 s, then 90 s + 5 min each time: 390, 690, 990.
	if len(at) != 6 {
		t.Fatalf("%d tries in 20 minutes, want 6:\n%s", len(at), r.out)
	}
	for i := 1; i < BackoffAfter; i++ {
		if d := at[i].Sub(at[i-1]); d != 30*time.Second {
			t.Fatalf("try %d came %s after the one before, want each check before the back-off", i+1, d)
		}
	}
	for i := BackoffAfter; i < len(at); i++ {
		if d := at[i].Sub(at[i-1]); d < BackoffEvery {
			t.Fatalf("try %d came %s after the one before, inside the back-off", i+1, d)
		}
	}
	if !strings.Contains(r.out.String(), "Secrets were required") {
		t.Fatalf("the failure of nmcli is not in the log:\n%s", r.out)
	}
	if n := strings.Count(r.out.String(), "now one try each 5m0s"); n != 1 {
		t.Fatalf("the back-off was announced %d times", n)
	}
}

// A second start a few seconds after a try does not try again.
func TestMinGapBetweenTries(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.nm.set(t, "up-rc", "4")
	r.check(t, 30*time.Second)
	r.check(t, 5*time.Second)
	r.check(t, 5*time.Second)
	if ups := r.nm.ups(t); len(ups) != 1 {
		t.Fatalf("%d tries 5 s apart, want 1", len(ups))
	}
}

// The uplink comes back after a try: one event row with the down time and
// the tries. Later checks write nothing more. pf alert reads the row as an
// UPLINK BACK post.
func TestRecoveryQueuesOneAlert(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second) // 12:00:00 down
	r.check(t, 30*time.Second) // 12:00:30 try 1
	r.nm.up(t)
	r.check(t, 30*time.Second) // 12:01:00 up
	r.check(t, 30*time.Second)
	r.check(t, 30*time.Second)
	ev := r.events(t)
	if len(ev) != 1 {
		t.Fatalf("%d event rows, want 1: %v", len(ev), ev)
	}
	e := ev[0]
	if e.Threat != jsonl.UplinkThreat || e.Where != "wlan0" || e.Host != "home" || e.UUID != homeUUID || e.DownS != 60 || e.Tries != 1 {
		t.Fatalf("event %+v", e)
	}
	raw, _ := os.ReadFile(filepath.Join(r.w.Dir, EventsFile))
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	if got, want := alert.Summarize(row), "UPLINK BACK wlan0 (home) after 1m0s down; the uplink watchdog ran nmcli connection up 1 time"; got != want {
		t.Fatalf("alert line %q, want %q", got, want)
	}
	// The next down period gets its own row.
	r.nm.down(t)
	r.check(t, 30*time.Second)
	r.check(t, 30*time.Second)
	r.nm.up(t)
	r.check(t, 30*time.Second)
	if ev := r.events(t); len(ev) != 2 {
		t.Fatalf("%d event rows after two down periods, want 2", len(ev))
	}
}

// NetworkManager brings the uplink back itself after a down period of two
// checks: a row with no try. A drop of one check gets no row.
func TestRecoveryWithoutTry(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	r.nm.up(t)
	r.check(t, 30*time.Second)
	if ev := r.events(t); len(ev) != 0 {
		t.Fatalf("a one-check drop wrote %v", ev)
	}
	r.nm.down(t)
	r.check(t, 30*time.Second)
	r.nm.box(t, "connecting (configuring)", homeUUID+":802-11-wireless:wlan0:activating:home")
	r.check(t, 30*time.Second)
	r.nm.up(t)
	r.check(t, 30*time.Second)
	ev := r.events(t)
	if len(ev) != 1 || ev[0].Tries != 0 || ev[0].DownS != 60 {
		t.Fatalf("events %+v, want one row with no try and 60 s down", ev)
	}
	if ups := r.nm.ups(t); len(ups) != 0 {
		t.Fatalf("connection up while NetworkManager brought it back: %q", ups)
	}
	var row map[string]any
	raw, _ := os.ReadFile(filepath.Join(r.w.Dir, EventsFile))
	_ = json.Unmarshal(raw, &row)
	if got := alert.Summarize(row); !strings.HasSuffix(got, "; NetworkManager brought it back") {
		t.Fatalf("alert line %q", got)
	}
}

// A new boot starts the state again: a down period before a power cycle
// is not the down time of the next alert. A clock that moved back does not
// hold a try back.
func TestNewBootAndClockStepStartAgain(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	r.w.BootID = func() string { return "boot-2" }
	r.nm.up(t)
	r.check(t, 30*time.Second)
	if ev := r.events(t); len(ev) != 0 {
		t.Fatalf("a down period of the last boot wrote %v", ev)
	}

	r.nm.down(t)
	r.nm.set(t, "up-rc", "4")
	for range 4 {
		r.check(t, 30*time.Second)
	}
	n := len(r.nm.ups(t))
	r.now = r.now.Add(-48 * time.Hour)
	r.check(t, 30*time.Second)
	if len(r.nm.ups(t)) != n+1 {
		t.Fatalf("a clock 48 h back held the try back")
	}
}

func TestFieldsUnescape(t *testing.T) {
	got := fields(`0b5e6b84-3c1d-4f7e-9a51-2a3f1c9d7e11:802-11-wireless:wlan0:activated:my\:net\\5G`)
	want := []string{homeUUID, "802-11-wireless", "wlan0", "activated", `my:net\5G`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("fields %q, want %q", got, want)
	}
}

// pf alert tails the event file that the watcher writes.
func TestAlertTailsTheEventFile(t *testing.T) {
	if got, want := alert.Defaults().UplinkLog, filepath.Join(DefaultDir, EventsFile); got != want {
		t.Fatalf("alert tails %s, the watcher writes %s", got, want)
	}
}

// --- the record step of apply ---

type recRig struct {
	nm  *fakeNM
	r   *Recorder
	out *bytes.Buffer
}

func newRecRig(t *testing.T) *recRig {
	t.Helper()
	x := &recRig{nm: newFakeNM(t), out: &bytes.Buffer{}}
	x.r = &Recorder{
		Path: filepath.Join(t.TempDir(), "uplink.json"), Out: x.out,
		Now: func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) },
	}
	return x
}

func (x *recRig) record(t *testing.T, dev string) {
	t.Helper()
	if err := x.r.Record(context.Background(), dev); err != nil {
		t.Fatalf("record: %v\n%s", err, x.out)
	}
}

func (x *recRig) got(t *testing.T) (Record, bool) {
	t.Helper()
	rec, err := LoadRecord(x.r.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return rec, true
}

func same(a, b Record) bool {
	return a.UUID == b.UUID && a.Name == b.Name && a.Device == b.Device && a.Type == b.Type && a.At.Equal(b.At)
}

// The connection on the uplink device is recorded by UUID. The agent
// connection on the other port, and a VPN over the uplink, are not.
func TestRecordPicksTheUplinkConnection(t *testing.T) {
	x := newRecRig(t)
	x.nm.set(t, "devices", "eth0:connected", "wlan0:connected")
	x.nm.set(t, "active",
		agentUUID+":802-3-ethernet:eth0:activated:agent-net",
		vpnUUID+":vpn:wlan0:activated:work-vpn",
		homeUUID+`:802-11-wireless:wlan0:activated:home\:5G`)
	x.record(t, "wlan0")
	rec, ok := x.got(t)
	if !ok || rec.UUID != homeUUID || rec.Name != "home:5G" || rec.Device != "wlan0" || rec.Type != "802-11-wireless" {
		t.Fatalf("record %+v (%v)", rec, ok)
	}
	if fi, err := os.Stat(x.r.Path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("record mode %v (%v)", fi.Mode(), err)
	}
	if !strings.Contains(x.out.String(), "recorded") {
		t.Fatalf("output %q", x.out)
	}
}

// A connection that pf made is never the uplink, also when it holds the
// device. The last record for the device stays.
func TestRecordNeverPfMade(t *testing.T) {
	for _, name := range []string{"agent-net", "house-net", "seg-desk", "trunk-eth1", "pf-parked-eth2"} {
		t.Run(name, func(t *testing.T) {
			x := newRecRig(t)
			x.nm.set(t, "devices", "eth1:connected")
			x.nm.set(t, "active", otherUUID+":802-3-ethernet:eth1:activated:"+name)
			x.record(t, "eth1")
			if rec, ok := x.got(t); ok {
				t.Fatalf("recorded %+v", rec)
			}
			writeRecord(t, x.r.Path, Record{UUID: homeUUID, Name: "wired", Device: "eth1"})
			x.record(t, "eth1")
			if rec, ok := x.got(t); !ok || rec.UUID != homeUUID {
				t.Fatalf("the last record did not stay: %+v %v", rec, ok)
			}
			if !strings.Contains(x.out.String(), "a connection that pf made") {
				t.Fatalf("output %q", x.out)
			}
		})
	}
}

// The uplink is down at apply: the last record for that device stays. A
// record for another device goes.
func TestRecordKeepsLastWhenDown(t *testing.T) {
	x := newRecRig(t)
	old := Record{UUID: homeUUID, Name: "home", Device: "wlan0", At: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	writeRecord(t, x.r.Path, old)
	x.nm.set(t, "devices", "eth0:connected", "wlan0:disconnected")
	x.nm.set(t, "active", agentUUID+":802-3-ethernet:eth0:activated:agent-net")
	x.record(t, "wlan0")
	if rec, ok := x.got(t); !ok || !same(rec, old) {
		t.Fatalf("record %+v, want the last one %+v", rec, old)
	}
	// Activating is not up yet.
	x.nm.set(t, "active", agentUUID+":802-3-ethernet:eth0:activated:agent-net", otherUUID+":802-11-wireless:wlan0:activating:cafe")
	x.record(t, "wlan0")
	if rec, ok := x.got(t); !ok || !same(rec, old) {
		t.Fatalf("record %+v, want the last one", rec)
	}
	// NetworkManager does not answer: the last record stays.
	x.nm.set(t, "nm-down")
	x.record(t, "wlan0")
	if rec, ok := x.got(t); !ok || !same(rec, old) {
		t.Fatalf("record %+v, want the last one", rec)
	}
	if err := os.Remove(filepath.Join(x.nm.dir, "nm-down")); err != nil {
		t.Fatal(err)
	}
	// WAN_IF moved to eth2, which is down: the wlan0 record is not the
	// uplink now.
	x.nm.set(t, "devices", "eth2:disconnected", "wlan0:disconnected")
	x.record(t, "eth2")
	if rec, ok := x.got(t); ok {
		t.Fatalf("a record for wlan0 stayed after the uplink moved to eth2: %+v", rec)
	}
}

// NetworkManager does not manage the uplink, or is not installed: the
// record goes, and the watcher does nothing.
func TestRecordClearedWhenNotNetworkManager(t *testing.T) {
	x := newRecRig(t)
	writeRecord(t, x.r.Path, Record{UUID: homeUUID, Name: "home", Device: "eth0"})
	x.nm.set(t, "devices", "eth0:unmanaged")
	x.record(t, "eth0")
	if _, ok := x.got(t); ok {
		t.Fatal("the record stayed for an unmanaged uplink")
	}
	writeRecord(t, x.r.Path, Record{UUID: homeUUID, Name: "home", Device: "eth0"})
	x.r.NM = func(context.Context, ...string) (string, error) { return "", ErrNoNM }
	x.record(t, "eth0")
	if _, ok := x.got(t); ok {
		t.Fatal("the record stayed on a box with no nmcli")
	}
	if err := x.r.Record(context.Background(), "eth0; reboot"); err == nil {
		t.Fatal("a bad device name was taken")
	}
}

func TestShow(t *testing.T) {
	r := newRig(t)
	r.nm.down(t)
	r.check(t, 30*time.Second)
	var b bytes.Buffer
	Show(r.w.Record, r.w.Dir, &b)
	if s := b.String(); !strings.Contains(s, `record: "home" (`+homeUUID+") on wlan0") || !strings.Contains(s, "last check: not up since") {
		t.Fatalf("show:\n%s", s)
	}
}
