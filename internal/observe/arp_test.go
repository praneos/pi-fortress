package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// arpFile writes ip/mac pairs in the shape of /proc/net/arp, with the
// header row. Thus a fixture says what the kernel would say, not what
// parseARP happens to accept.
func arpFile(t *testing.T, path string, pairs ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(&b, "%-16s 0x1         0x2         %-21s *        eth1\n", pairs[i], pairs[i+1])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
}

// arpWatcher is an Observer connected only to the files that the ARP watch
// reads: an agent segment, a configured house, and a clock that the test owns.
func arpWatcher(t *testing.T, dir string, clock *time.Time) *Observer {
	t.Helper()
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	house := filepath.Join(dir, "house.env")
	if err := os.WriteFile(house, []byte("HOUSE_IF=eth0\nHOUSE_NET=10.78.0.0/24\nHOUSE_IP=10.78.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return &Observer{
		StatePath:    filepath.Join(dir, "observe.json"),
		ARPPath:      filepath.Join(dir, "arp"),
		NetEnvPath:   []string{env},
		HouseEnvPath: []string{house},
		HouseLeases:  filepath.Join(dir, "house.leases"),
		HouseHosts:   filepath.Join(dir, "house.hosts"),
		SegmentsDir:  filepath.Join(dir, "segments.d"),
		Now:          func() time.Time { return *clock },
	}
}

// alertsOf picks the rows that a reader would print under ALERTS. Thus a
// test that asserts on a claim does not also assert on each nft drop.
func alertsOf(st *State) []Event {
	var out []Event
	for _, e := range st.Events {
		if e.Alert() {
			out = append(out, e)
		}
	}
	return out
}

func TestAnAddressAnsweredByASecondMACIsReportedWithBoth(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:aa:aa:aa")
	o.watchARP(st)
	if got := alertsOf(st); len(got) != 0 {
		t.Fatalf("a first sighting is not a claim: %+v", got)
	}

	clock = clock.Add(5 * time.Minute)
	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:bb:bb:bb")
	o.watchARP(st)
	got := alertsOf(st)
	if len(got) != 1 {
		t.Fatalf("alerts = %+v, want one flip", got)
	}
	e := got[0]
	if e.Threat != arpFlip || e.Segment != "agent" || e.Src != "10.77.0.10" || e.Dst != "08:00:27:bb:bb:bb" {
		t.Fatalf("%+v", e)
	}
	// Both MACs and the gap between them, or the operator cannot tell a
	// hijack from a DHCP handover.
	if !strings.Contains(e.Detail, "08:00:27:aa:aa:aa") || !strings.Contains(e.Detail, "5m0s") {
		t.Fatalf("detail = %q", e.Detail)
	}
}

func TestANeighbourAnsweringForThePisOwnAddressIsReported(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	arpFile(t, o.ARPPath, "10.78.0.1", "08:00:27:ee:ee:ee")
	o.watchARP(st)
	got := alertsOf(st)
	if len(got) != 1 || got[0].Threat != arpSelf || got[0].Segment != "house" || got[0].Src != "10.78.0.1" {
		t.Fatalf("%+v", got)
	}
	// It reports on the first sighting: there is no earlier MAC to compare
	// against. If it waited for one, a claim that arrives before the Pi ever
	// resolves that address would never be reported.
	if got[0].Dst != "08:00:27:ee:ee:ee" {
		t.Fatalf("%+v", got[0])
	}
}

func TestALeasedAddressAnsweredByAnotherMACIsReported(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	// Expiry 0 is the indefinite lease of dnsmasq. Thus the fixture does
	// not have to agree with the test clock about when the lease ends.
	if err := os.WriteFile(o.HouseLeases, []byte("0 08:00:27:11:11:11 10.78.0.50 phone *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The static management address of the AP is a reservation, not a
	// lease, and the claim on it is the same.
	if err := os.WriteFile(o.HouseHosts, []byte("08:00:27:22:22:22,10.78.0.2,ap\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st := o.Load()

	arpFile(t, o.ARPPath,
		"10.78.0.50", "08:00:27:99:99:99",
		"10.78.0.2", "08:00:27:99:99:99",
	)
	o.watchARP(st)
	got := alertsOf(st)
	if len(got) != 2 {
		t.Fatalf("alerts = %+v, want the lease and the reservation", got)
	}
	for _, e := range got {
		if e.Threat != arpLease {
			t.Fatalf("%+v", e)
		}
	}
	if !strings.Contains(got[0].Detail, "08:00:27:22:22:22") {
		t.Fatalf("the reservation's own MAC is missing: %q", got[0].Detail)
	}
	if !strings.Contains(got[1].Detail, "08:00:27:11:11:11") {
		t.Fatalf("the lease's own MAC is missing: %q", got[1].Detail)
	}
}

func TestALeaseHeldByItsOwnMACRaisesNothing(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	if err := os.WriteFile(o.HouseLeases, []byte("0 08:00:27:11:11:11 10.78.0.50 phone *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st := o.Load()
	arpFile(t, o.ARPPath, "10.78.0.50", "08:00:27:11:11:11")
	o.watchARP(st)
	if got := alertsOf(st); len(got) != 0 {
		t.Fatalf("the device holding its own lease is not a claim: %+v", got)
	}
}

func TestAFlappingNeighbourCannotDrownTheLedger(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	macs := []string{"08:00:27:aa:aa:aa", "08:00:27:bb:bb:bb"}
	for i := range 40 {
		arpFile(t, o.ARPPath, "10.77.0.10", macs[i%2])
		o.watchARP(st)
		clock = clock.Add(10 * time.Second)
	}
	got := alertsOf(st)
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want the flapping held to one inside arpQuiet", len(got))
	}
	// Held down, not discarded: the next alert after the window must say
	// how many claims it stands for.
	if rec := st.ARP["agent/10.77.0.10"]; rec == nil || rec.Claims == 0 {
		t.Fatalf("swallowed claims were not counted: %+v", rec)
	}
	clock = clock.Add(arpQuiet)
	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:cc:cc:cc")
	o.watchARP(st)
	got = alertsOf(st)
	if len(got) != 2 {
		t.Fatalf("alerts = %d, want the window to reopen", len(got))
	}
	if !strings.Contains(got[1].Detail, "more)") {
		t.Fatalf("detail does not say what it stands for: %q", got[1].Detail)
	}
}

func TestAStandingClaimIsRestatedSoItCannotAgeOutUnnoticed(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	arpFile(t, o.ARPPath, "10.78.0.1", "08:00:27:ee:ee:ee")
	o.watchARP(st)
	clock = clock.Add(time.Minute)
	o.watchARP(st)
	if got := alertsOf(st); len(got) != 1 {
		t.Fatalf("alerts = %d, want the unchanged claim to stay quiet", len(got))
	}
	clock = clock.Add(arpRepeat)
	o.watchARP(st)
	if got := alertsOf(st); len(got) != 2 {
		t.Fatalf("alerts = %d, want the claim restated once past arpRepeat", len(got))
	}
}

// A reboot is when an attacker wants the ledger to forget which MAC held
// an address. Thus the binding is in the state file with the log offsets,
// not in the process.
func TestABindingSurvivesARestartSoAFlipAcrossOneIsStillAFlip(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()
	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:aa:aa:aa")
	o.watchARP(st)
	if err := o.Save(st); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(time.Hour)
	next := arpWatcher(t, dir, &clock)
	st2 := next.Load()
	if rec := st2.ARP["agent/10.77.0.10"]; rec == nil || rec.MAC != "08:00:27:aa:aa:aa" {
		t.Fatalf("binding did not survive the restart: %+v", rec)
	}
	arpFile(t, next.ARPPath, "10.77.0.10", "08:00:27:bb:bb:bb")
	next.watchARP(st2)
	got := alertsOf(st2)
	if len(got) != 1 || got[0].Threat != arpFlip {
		t.Fatalf("%+v", got)
	}
}

func TestAPlainSegmentsAddressesAreWatchedAndTagged(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	if err := os.MkdirAll(o.SegmentsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.SegmentsDir, "desk.env"), []byte("IF=eth0.20\nNET=10.79.0.0/24\nIP=10.79.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st := o.Load()

	arpFile(t, o.ARPPath, "10.79.0.5", "08:00:27:aa:aa:aa")
	o.watchARP(st)
	clock = clock.Add(time.Minute)
	arpFile(t, o.ARPPath, "10.79.0.5", "08:00:27:bb:bb:bb")
	o.watchARP(st)
	got := alertsOf(st)
	if len(got) != 1 || got[0].Segment != "desk" {
		t.Fatalf("a plain segment went unwatched: %+v", got)
	}
}

func TestAnAddressOnNoSegmentOfThisBoxIsNotThisBoxsBusiness(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	arpFile(t, o.ARPPath, "192.168.1.1", "08:00:27:aa:aa:aa")
	o.watchARP(st)
	clock = clock.Add(time.Minute)
	arpFile(t, o.ARPPath, "192.168.1.1", "08:00:27:bb:bb:bb")
	o.watchARP(st)
	if got := alertsOf(st); len(got) != 0 {
		t.Fatalf("the upstream's own MAC change is not a claim here: %+v", got)
	}
	if len(st.ARP) != 0 {
		t.Fatalf("a WAN neighbour was tracked: %+v", st.ARP)
	}
}

// An address claim is not a block. It must go to the ring, because all
// readers read the ring. But it must not change the blocked count of the
// hour -- nothing was blocked, and the operator reads that number.
func TestAnAddressClaimIsShownAsAnAlertAndNotCountedAsABlock(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	st := o.Load()

	arpFile(t, o.ARPPath, "10.78.0.1", "08:00:27:ee:ee:ee")
	o.watchARP(st)
	for seg, buckets := range st.Series {
		for _, b := range buckets {
			if b.Blocked != 0 {
				t.Fatalf("segment %s hour %s counted a claim as a block", seg, b.Hour)
			}
		}
	}
	var out strings.Builder
	o.Stdout = &out
	o.Show(st)
	text := out.String()
	alerts := strings.Index(text, "ALERTS (1)")
	if alerts < 0 {
		t.Fatalf("no ALERTS section:\n%s", text)
	}
	if !strings.Contains(text, "BLOCKED (0)") {
		t.Fatalf("the claim was counted under BLOCKED:\n%s", text)
	}
	if !strings.Contains(text[alerts:], arpSelf) {
		t.Fatalf("the claim is not under ALERTS:\n%s", text)
	}
}

// The detector runs inside the observe pass. Thus it must work when the
// pass drives it, not only when a test calls it directly.
func TestASnapshotRaisesTheAddressClaimsItsOwnPassFinds(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	o := arpWatcher(t, dir, &clock)
	o.CTPath = filepath.Join(dir, "missing-ct")
	o.DNSLog = filepath.Join(dir, "missing-dns")

	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:aa:aa:aa")
	o.Snapshot()
	clock = clock.Add(time.Minute)
	arpFile(t, o.ARPPath, "10.77.0.10", "08:00:27:bb:bb:bb")
	st := o.Snapshot()
	if got := alertsOf(st); len(got) != 1 || got[0].Threat != arpFlip {
		t.Fatalf("%+v", got)
	}
}

// The daemon of the Pi cannot read /proc/net/arp: observe.service sets
// ProcSubset=pid, which hides /proc/net from the process. Thus the file is
// ENOENT to the daemon, while a shell on the same box reads it without a
// problem. For exactly this reason, the detector was silent on the real
// box and all unit tests passed, because the tests give it a fixture file.
func TestTheARPTableFallsBackToTheCommandWhenProcIsHidden(t *testing.T) {
	o := &Observer{
		ARPPath: filepath.Join(t.TempDir(), "absent", "arp"),
		ARPCmd: []string{"printf", `10.79.0.2 dev eth3 lladdr 08:00:27:5a:2c:c0 REACHABLE
10.77.0.11 dev eth1  FAILED
10.0.2.2 dev eth0 lladdr 52:54:00:12:35:00 STALE
`},
	}
	got := o.arpTable()
	if got["10.79.0.2"] != "08:00:27:5a:2c:c0" || got["10.0.2.2"] != "52:54:00:12:35:00" {
		t.Fatalf("the command fallback did not read the table: %v", got)
	}
	if _, ok := got["10.77.0.11"]; ok {
		t.Error("a neighbour that never answered was recorded as having a MAC")
	}
	// No command configured is the old behaviour: an empty table, not a
	// panic and not a stalled pass.
	o.ARPCmd = nil
	if len(o.arpTable()) != 0 {
		t.Error("an absent file with no fallback should be an empty table")
	}
}
