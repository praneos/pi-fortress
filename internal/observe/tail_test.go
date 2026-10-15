package observe

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func netEnv(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "net.env")
	if err := os.WriteFile(p, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\nVBOX_NAT_NET=10.0.2.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func query(name string) string {
	return rows(resolved("10.77.0.10", name, "93.184.216.34"))
}

// logrotate renames dns.jsonl, and the resolver opens a new file. The new
// file grows past the old offset within minutes. Thus a size check alone
// never sees the rotation, and each name resolved in between is missing
// from the ledger that the operator reads.
func TestTailAfterRotation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	if err := os.WriteFile(log, []byte(query("one.example")), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		DNSLog:     log,
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		NetEnvPath: []string{netEnv(t, dir)},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	if st := o.Snapshot(); st.DNS["one.example"] == nil {
		t.Fatal("first pass missed one.example")
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte(query("two.example")+query("three.example")), 0644); err != nil {
		t.Fatal(err)
	}
	st := o.Snapshot()
	if st.DNS["two.example"] == nil {
		t.Fatalf("rotation skipped two.example: %v", names(st))
	}
	if st.DNS["three.example"] == nil {
		t.Fatalf("rotation skipped three.example: %v", names(st))
	}
}

// offsetOf returns the byte count from a checkpoint file. The file also
// records the inode that those bytes were counted in.
func offsetOf(raw string) string {
	f := strings.Fields(raw)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func names(st *State) []string {
	var out []string
	for n := range st.DNS {
		out = append(out, n)
	}
	return out
}

// dnsmasq is a separate process. A pass can occur between the name and the
// newline. A parse of the prefix and a checkpoint past it lose the query.
func TestTailLeavesPartialLine(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	whole := query("done.example")
	// One row is one line. Thus cut a real row in half, and do not spell
	// out a prefix: the point is the newline, not the text.
	row := rows(resolved("10.77.0.10", "cut.example", "1.2.3.4"))
	partial, rest := row[:len(row)/2], row[len(row)/2:]
	if err := os.WriteFile(log, []byte(whole+partial), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		DNSLog:     log,
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		NetEnvPath: []string{netEnv(t, dir)},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	o.Snapshot()
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(rest); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	st := o.Snapshot()
	if st.DNS["cut.example"] == nil {
		t.Fatalf("query split across two passes was lost: %v", names(st))
	}
}

// Flush writes the offsets and the journal cursor before it saves the
// state that they describe. A failed Save leaves checkpoints that are
// ahead of the ledger. Thus nothing reads the window between them again.
func TestFlushKeepsOffsetsWhenSaveFails(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	if err := os.WriteFile(log, []byte(query("one.example")), 0644); err != nil {
		t.Fatal(err)
	}
	off := filepath.Join(dir, "off")
	// A directory where the state file belongs: MarshalIndent succeeds and
	// the rename cannot.
	state := filepath.Join(dir, "observe.json")
	if err := os.MkdirAll(state, 0755); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  state,
		DNSLog:     log,
		OffsetPath: off,
		CTPath:     filepath.Join(dir, "missing-ct"),
		NetEnvPath: []string{netEnv(t, dir)},
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	o.Snapshot()
	if err := o.Flush(); err == nil {
		t.Fatal("Flush reported success though Save could not write")
	}
	if raw, err := os.ReadFile(off); err == nil && strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("offset advanced to %q past a ledger that was never saved", raw)
	}
}

// pf observe once exits 0 on a run that wrote nothing. Thus a cron entry,
// or an operator who watches the status code, sees a healthy pipeline
// while the ledger does not change.
func TestOnceReportsAFailedFlush(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	if err := os.WriteFile(log, []byte(query("one.example")), 0644); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "observe.json")
	if err := os.MkdirAll(state, 0755); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:  state,
		DNSLog:     log,
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		NetEnvPath: []string{netEnv(t, dir)},
		Stdout:     io.Discard,
		Now:        func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	if err := o.Once(); err == nil {
		t.Fatal("Once reported success though the ledger was never written")
	}
}

// pf observe reset is the "start again" of the operator. If the house
// offset and the journal cursor stay where they were, the next run
// rebuilds a ledger with a hole of exactly the size of what reset claimed
// to discard.
func TestResetClearsEveryCheckpoint(t *testing.T) {
	dir := t.TempDir()
	house := filepath.Join(dir, "dns-house.jsonl")
	if err := os.WriteFile(house, []byte(query("house.example")), 0644); err != nil {
		t.Fatal(err)
	}
	houseOff := filepath.Join(dir, "house.off")
	if err := os.WriteFile(houseOff, []byte("999\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cursor := filepath.Join(dir, "journal.cursor")
	if err := os.WriteFile(cursor, []byte("s=abc;i=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		StatePath:         filepath.Join(dir, "observe.json"),
		DNSLog:            filepath.Join(dir, "missing.log"),
		OffsetPath:        filepath.Join(dir, "off"),
		HouseDNSLog:       house,
		HouseOffsetPath:   houseOff,
		JournalCursorPath: cursor,
		StripLog:          filepath.Join(dir, "strip.jsonl"),
		StripOffsetPath:   filepath.Join(dir, "strip.off"),
		Stdout:            &strings.Builder{},
		Now:               func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	if err := o.Reset(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(houseOff)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(house)
	if err != nil {
		t.Fatal(err)
	}
	if offsetOf(string(raw)) != strconv.FormatInt(fi.Size(), 10) {
		t.Fatalf("house offset left at %q, want the end of a %d byte log", raw, fi.Size())
	}
	if _, err := os.Stat(cursor); err == nil {
		t.Fatal("journal cursor survived reset")
	}
}

// pf observe reset runs from a root shell while the daemon runs. The
// daemon holds the ledger in memory between flushes. Thus, if it did not
// notice that somebody replaced the file, it put the discarded ledger back
// on its next tick, and the reset lasted ten seconds.
func TestSnapshotNoticesAnExternalReset(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "dns.jsonl")
	if err := os.WriteFile(log, []byte(query("one.example")), 0644); err != nil {
		t.Fatal(err)
	}
	env := netEnv(t, dir)
	mk := func() *Observer {
		return &Observer{
			StatePath:     filepath.Join(dir, "observe.json"),
			DNSLog:        log,
			OffsetPath:    filepath.Join(dir, "off"),
			CTPath:        filepath.Join(dir, "missing-ct"),
			NetEnvPath:    []string{env},
			FlushBytes:    1 << 20,
			FlushInterval: time.Hour,
			Stdout:        &strings.Builder{},
			Now:           func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		}
	}
	daemon := mk()
	daemon.Snapshot()
	if err := daemon.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := mk().Reset(); err != nil {
		t.Fatal(err)
	}
	st := daemon.Snapshot()
	if len(st.DNS) != 0 {
		t.Fatalf("the daemon kept the ledger reset discarded: %v", names(st))
	}
	if err := daemon.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(mk().Load().DNS) != 0 {
		t.Fatal("the daemon wrote the discarded ledger back to disk")
	}
}

// Save publishes through one fixed name. Thus when a person runs pf
// observe once by hand while the daemon flushes, each writer fills the
// temporary file of the other.
func TestSaveDoesNotShareATempName(t *testing.T) {
	dir := t.TempDir()
	o := &Observer{StatePath: filepath.Join(dir, "observe.json"), Now: time.Now}
	// The open of a second writer would collide with a directory at the
	// fixed name. Save must not require that name to be free.
	if err := os.MkdirAll(o.StatePath+".tmp", 0755); err != nil {
		t.Fatal(err)
	}
	if err := o.Save(o.empty()); err != nil {
		t.Fatalf("Save could not publish around a busy %s.tmp: %v", o.StatePath, err)
	}
}

// expireEvents stops at the first fresh row at the front of the ring.
// Thus a late journal line in front of the expired rows keeps a week of
// stale events in place forever.
func TestExpireEventsDropsOldRowsBehindAFreshOne(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	st := &State{Events: []Event{
		{T: now, Segment: "agent", Dst: "fresh.example"},
		{T: now.Add(-30 * 24 * time.Hour), Segment: "agent", Dst: "ancient.example"},
	}}
	expireEvents(st, now)
	for _, e := range st.Events {
		if e.Dst == "ancient.example" {
			t.Fatalf("kept a 30-day-old event: %+v", st.Events)
		}
	}
}

// A journal line carries a kernel stamp that can be older than a row
// already ingested. A LastSeen stamp from it moves the last contact of the
// client backwards, and the idle eviction of admin reads that field.
func TestClientLastSeenNeverGoesBackwards(t *testing.T) {
	o := &Observer{Now: func() time.Time { return time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC) }}
	st := o.empty()
	o.client(st, "agent", "10.77.0.10", "2026-01-20T10:00:00Z")
	o.client(st, "agent", "10.77.0.10", "2026-01-20T09:00:00Z")
	c := st.Clients["agent/10.77.0.10"]
	if c.LastSeen != "2026-01-20T10:00:00Z" {
		t.Fatalf("LastSeen = %q, want the newer stamp", c.LastSeen)
	}
	if c.FirstSeen != "2026-01-20T09:00:00Z" {
		t.Fatalf("FirstSeen = %q, want the older stamp", c.FirstSeen)
	}
}

// An expired lease is no longer the name of this address. If the code
// keeps it, the operator reads the device name of the previous tenant
// over the device that now holds the address.
func TestEnrichIgnoresExpiredLeases(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	leaseFile := filepath.Join(dir, "house.leases")
	body := "1000000000 aa:bb:cc:dd:ee:ff 10.78.0.50 oldphone *\n"
	if err := os.WriteFile(leaseFile, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		HouseLeases: leaseFile,
		HouseHosts:  filepath.Join(dir, "missing.hosts"),
		ARPPath:     filepath.Join(dir, "missing.arp"),
		Now:         func() time.Time { return now },
	}
	st := o.empty()
	o.client(st, "house", "10.78.0.50", now.Format("2006-01-02T15:04:05Z"))
	o.enrich(st)
	if got := st.Clients["house/10.78.0.50"].Name; got != "" {
		t.Fatalf("named the client %q from a lease that expired in 2001", got)
	}
}

// Before, a checkpoint was rewritten in place. Thus a crash or a full disk
// during the write left a torn or empty offset, and the next start read
// the log from the wrong place. Now it goes to a temp file and a rename
// over the old file. A reader that holds the old file (here a hard link)
// shows this: it keeps the whole old mark, and does not see the new one
// written into it.
func TestCheckpointIsReplacedNotRewritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dns.offset")
	if err := writeCheckpoint(path, checkpoint{off: 1234}); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "held")
	if err := os.Link(path, old); err != nil {
		t.Fatal(err)
	}
	if err := writeCheckpoint(path, checkpoint{off: 99}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(old); string(b) != "1234\n" {
		t.Fatalf("the old file was written into: %q", b)
	}
	if got := loadCheckpoint(path); got.off != 99 {
		t.Fatalf("checkpoint %+v", got)
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}
