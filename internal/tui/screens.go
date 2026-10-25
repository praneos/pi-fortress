package tui

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/fetch"
	"pi-fortress/internal/monitor"
)

type feedRow struct {
	id string
	on bool
}

// figure renders a measurement, or n/a for one that the sample says it does
// not have. Each metric that the Status screen shows comes from a file whose
// read error collapses to zero. A screen cannot tell the operator which of
// its numbers to believe unless the source row says.
func figure(ok bool, format string, args ...any) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf(format, args...)
}

func (a *App) build() []row {
	v := a.cur
	switch v.sec {
	case secOverview:
		return a.buildOverview()
	case secDevices:
		if v.net == netHouse {
			return a.buildHouseDevices()
		}
		return a.buildClients(v.net)
	case secFiltering:
		if a.onFeedsTab() {
			return a.buildFeeds(v.net)
		}
		return a.buildList()
	case secActivity:
		if t := a.activityTab(); !t.blocked {
			if t.seg != "" {
				return a.buildSegLog(t.log, t.seg)
			}
			return a.buildLog(t.log)
		}
		return a.buildEvents(v.net)
	case secSettings:
		return a.buildSettings()
	case secKeys:
		return a.buildSecrets()
	case secHealth:
		return a.buildStatus()
	case secFeeds:
		return a.buildFeeds("")
	case secAdminLog:
		return a.buildLog(admin.LogAudit)
	case secActions:
		return a.buildActions()
	}
	return nil
}

// onFeedsTab says that Filtering is on its last tab, the feeds, not on one
// of the lists.
func (a *App) onFeedsTab() bool {
	return a.cur.sec == secFiltering && a.tabIndex() == len(filterLists(a.cur))
}

// activityTab is the Activity view on screen.
func (a *App) activityTab() activityTab {
	tabs := a.activityTabs(a.cur)
	return tabs[min(a.tabIndex(), len(tabs)-1)]
}

func text(lines ...string) []row {
	out := make([]row, len(lines))
	for i, l := range lines {
		out[i] = row{text: l}
	}
	return out
}

// get runs a query verb and returns its typed result. A failure sets the
// message and gives the zero value.
func get[T any](a *App, verb string, args admin.Args) T {
	var zero T
	v, err := a.call(verb, args)
	if a.fail(err) || v == nil {
		return zero
	}
	t, _ := v.(T)
	return t
}

// typed is the sibling of get for an action verb, whose result arrives as
// any. A reply of the wrong shape is a bug on the admin side, not an error
// of the operator. The seat says so and stays up. It does not panic out of
// raw mode during an edit.
func typed[T any](a *App, v any) (T, bool) {
	t, ok := v.(T)
	if !ok {
		a.msg = "error: the admin socket answered with an unexpected result"
	}
	return t, ok
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "missing"
	}
	return t.Local().Format("Jan 2 15:04")
}

// wgLine says what the tunnel does now. Before, the line said "not
// configured" in all box states. Thus a house segment whose kill switch had
// just dropped all outbound flows looked exactly like one that never had a
// tunnel. This occurred on the one screen that an operator opens to find
// why nothing works. WG_IF in house.env is the configuration. The interface
// list is the state.
func wgLine(ifname string, ifaces []admin.Iface) string {
	if ifname == "" {
		return "not configured"
	}
	for _, i := range ifaces {
		if i.Name != ifname {
			continue
		}
		if !i.Up {
			return ifname + "  down"
		}
		if len(i.Addrs) == 0 {
			return ifname + "  up (no address)"
		}
		return ifname + "  up  " + strings.Join(i.Addrs, " ")
	}
	return ifname + "  configured but the interface is missing"
}

func (a *App) buildStatus() []row {
	// Each column is as wide as its longest name. Thus a long name, such as
	// the wlx<mac> of a USB Wi-Fi adapter, does not push its row out of line.
	units := get[[]admin.UnitState](a, "units", admin.Args{})
	uw := 0
	for _, u := range units {
		uw = max(uw, len(u.Unit))
	}
	lines := []string{"units"}
	for _, u := range units {
		lines = append(lines, fmt.Sprintf("  %-*s  %s", uw, u.Unit, u.State))
	}
	lines = append(lines, "", "interfaces")
	ifaces := get[[]admin.Iface](a, "ifaces", admin.Args{})
	s := get[*monitor.Sample](a, "sample", admin.Args{})
	iw := 0
	for _, i := range ifaces {
		iw = max(iw, len(i.Name))
	}
	if s != nil {
		for name := range s.Wifi {
			iw = max(iw, len(name))
		}
	}
	for _, i := range ifaces {
		state := "down"
		if i.Up {
			state = "up"
		}
		lines = append(lines, fmt.Sprintf("  %-*s  %-4s %s", iw, i.Name, state, strings.Join(i.Addrs, " ")))
	}
	lines = append(lines, "", "uplink")
	if s != nil {
		for name, w := range s.Wifi {
			n := s.Net[name]
			lines = append(lines, fmt.Sprintf("  %-*s  %.0f dBm  quality %.0f  rx %.1f KB/s  tx %.1f KB/s  (%s)", iw, name, w.LevelDB, w.Quality, n.RxKBps, n.TxKBps, s.TS))
		}
		// A /proc file that the sampler could not read parses as zero. Zero
		// is also a true figure that this box reports: an idle load, an empty
		// conntrack table. The sample says which figures it measured. Thus a
		// failure shows as a failure, not as a confident number.
		lines = append(lines, fmt.Sprintf("  cpu %s  load %s  mem used %s  temp %s  conntrack %s",
			figure(s.Has("cpu"), "%.1f%%", s.CPU),
			figure(s.Has("load"), "%.2f", s.Load1),
			figure(s.Has("mem"), "%d MB (%.1f%%)", s.MemUsedMB, s.MemUsedPct),
			figure(s.Has("temp"), "%.0fC", s.TempC),
			figure(s.Has("conntrack"), "%d", s.Conntrack)))
	} else {
		lines = append(lines, "  no monitor sample yet")
	}
	st := get[admin.Status](a, "status", admin.Args{})
	hosts := get[[]admin.Host](a, "leases", admin.Args{})
	leases, pinned := 0, 0
	for _, h := range hosts {
		if h.Lease != nil {
			leases++
		}
		if h.Reserved {
			pinned++
		}
	}
	d := st.Device
	fs := a.cfg.FetchStatus()
	lines = append(lines, "",
		fmt.Sprintf("house      leases %d  reservations %d", leases, pinned),
		fmt.Sprintf("observe    agent %s  names %d  queries %d  flows %d  house names %d  strips %d", d.AgentIP, d.DNSNames, d.DNSQueries, d.Flows, d.HouseNames, d.Strips),
		fmt.Sprintf("feeds      %s", feedsLine(fs)),
		"wireguard  "+wgLine(a.cfg.House()["WG_IF"], ifaces),
	)
	if st.ApplyRunning {
		lines = append(lines, "apply      running (lock held)")
	} else {
		lines = append(lines, "apply      idle")
	}
	if st.RebootRequired {
		lines = append(lines, "system     reboot required (updates installed, kernel or libc still old)")
	}
	e := get[admin.EnrollStats](a, "enroll.stats", admin.Args{})
	// "never" is a claim about the full ledger. LedgerPartial says that
	// the code read only a tail of it: a generation rotated away, or the
	// live one is longer than the window. Silence in a tail is not
	// absence, and a count from a tail is not a total. Thus the screen
	// gives neither to the operator as if it were.
	unknown := "never"
	if e.LedgerPartial {
		unknown = "unknown (partial ledger)"
	}
	redeem, setup := unknown, unknown
	if !e.LastRedeem.IsZero() {
		redeem = stamp(e.LastRedeem) + " from " + e.LastRedeemIP
	}
	if !e.LastSetup.IsZero() {
		setup = stamp(e.LastSetup) + " from " + e.LastSetupIP
	}
	atLeast := func(n int) string {
		if e.LedgerPartial {
			return fmt.Sprintf("%d+", n)
		}
		return fmt.Sprint(n)
	}
	ca := "missing at " + e.CACertPath
	if e.CAFP != "" {
		ca = fmt.Sprintf("%s  sha256:%s  expires %s", e.CASubject, e.CAFP, e.CANotAfter.Format("2006-01-02"))
	}
	lines = append(lines, "", "enrollment",
		fmt.Sprintf("  slots %d  kinds %d  disabled %d", e.Slots, e.Kinds, e.Disabled),
		"  ca      "+ca,
		fmt.Sprintf("  www     setup.sh %s  ca.pem %s  (%s)", stamp(e.SetupSH), stamp(e.CAPEM), e.WWWDir),
		fmt.Sprintf("  claims  issued %s  redeemed %s  last redeem %s", atLeast(e.Issued), atLeast(e.Redeemed), redeem),
		"  setup   last fetch "+setup)
	if e.LedgerPartial {
		lines = append(lines, "  ledger  partial: a tail of it, so the counts are floors")
	}
	return text(lines...)
}

// feedsLine is the fetch state as one row of the Status screen. A warning
// goes on it verbatim (without the "feeds: " key that the title bar adds),
// because a partial fetch is a standing condition with no other symptom on
// this screen. A healthy report shows its counts. Thus a list that is only
// old is visible, but is not an alarm.
func feedsLine(st admin.FetchStatus) string {
	if w := st.Warning(); w != "" {
		return "! " + strings.TrimPrefix(w, "feeds: ")
	}
	ok := 0
	for _, l := range st.Lines {
		if strings.HasPrefix(l, "OK ") {
			ok++
		}
	}
	return fmt.Sprintf("fetched %s  %d ok  %d failed  %d stale", fetch.Ago(st.Age), ok, st.Fail, st.Stale)
}

// buildHouseDevices is the lease table, with the counts of observe for
// each address beside it. The house is the one network whose devices get
// addresses from the Pi. Thus it is the one with names to pin.
func (a *App) buildHouseDevices() []row {
	a.hosts = get[[]admin.Host](a, "leases", admin.Args{})
	a.stats = get[admin.Stats](a, "stats", admin.Args{})
	seen := map[string]admin.ClientStat{}
	for _, c := range a.stats.Clients {
		if c.Segment == netHouse {
			seen[c.IP] = c
		}
	}
	if a.detail != "" {
		for _, c := range seen {
			if clientKey(c) == a.detail {
				return a.buildDetail(c)
			}
		}
		a.detail = ""
		a.here().pos = a.back
	}
	// A device that observe counted, but with no lease now, is still a
	// house device. Its lease expired, or the device set its own address.
	// Without it, the table lost all devices seen more than a lease ago.
	for _, c := range a.stats.Clients {
		if c.Segment == netHouse && !slices.ContainsFunc(a.hosts, func(h admin.Host) bool { return h.IP == c.IP }) {
			a.hosts = append(a.hosts, admin.Host{MAC: c.MAC, IP: c.IP, Name: c.Name})
		}
	}
	// The counts come before the MAC, so they fit at 80 columns. The MAC
	// and lease follow for a wider terminal, and the detail also has them.
	w := a.contentWidth()
	line := func(name, ip, pin, q, bl, last, mac, lease string) string {
		return cols(w, col{name, 14}, col{ip, 15}, col{pin, 3}, col{q, -7}, col{bl, -7}, col{last, -5}, col{mac, 17}, col{lease, 17})
	}
	rows := []row{{text: line("name", "ip", "pin", "queries", "blocked", "last", "mac", "lease")}}
	now := time.Now()
	for _, h := range a.hosts {
		pin, lease := "", "-"
		if h.Reserved {
			pin = "yes"
		}
		if h.Lease != nil {
			lease = "until " + stamp(h.Lease.Expiry)
		}
		q, bl, last := "-", "-", "-"
		if c, ok := seen[h.IP]; ok {
			q, bl, last = fmt.Sprint(c.Queries), fmt.Sprint(c.Blocked), age(c.LastSeen, now)
		}
		rows = append(rows, row{line(h.Name, h.IP, pin, q, bl, last, h.MAC, lease), true})
	}
	if len(a.hosts) == 0 {
		rows = append(rows, row{text: "no leases or reservations"})
	}
	return rows
}

// listVerb returns the verb prefix and list name for the active tab.
func (a *App) listVerb() (string, string) {
	lists := filterLists(a.cur)
	name := lists[min(a.tabIndex(), len(lists)-1)]
	if a.cur.net == netHouse {
		return "house", name
	}
	return "agent", name
}

func (a *App) buildList() []row {
	prefix, name := a.listVerb()
	a.items = get[[]string](a, prefix+".list", admin.Args{List: name})
	head := listLabel(name) + ": " + name
	if a.cur.readOnlyLists() {
		head += "  (shared with the agent network; edit it there)"
	}
	if name == admin.DNSTypesList {
		head += "  (name TYPE..., *.name for every name under it)"
	}
	rows := []row{{text: head}}
	for _, it := range a.items {
		// pf dns skips or ignores a hand-edited line that the check refuses.
		// The journal is the only other place that says so.
		if name == admin.DNSTypesList {
			if _, err := admin.CheckDNSTypesLine(it); err != nil {
				it += "  (not applied: " + err.Error() + ")"
			}
		}
		rows = append(rows, row{it, true})
	}
	if len(a.items) == 0 {
		rows = append(rows, row{text: "(empty)"})
	}
	return rows
}

// buildFeeds is all feeds on System. On the Filtering of a network, it is
// the feeds that reach that network: its own feeds, and the feeds with no
// segment, which all networks get. A toggle applies to the full box in
// both cases.
func (a *App) buildFeeds(net string) []row {
	spec := get[*fetch.Spec](a, "feeds", admin.Args{})
	if spec == nil {
		return nil
	}
	a.feeds = a.feeds[:0]
	rows := []row{{text: fmt.Sprintf("%-28s %-8s %-8s %s", "id", "kind", "network", "enabled")}}
	for _, f := range spec.Feeds {
		if net != "" && f.Segment != "" && f.Segment != net {
			continue
		}
		seg := f.Segment
		if seg == "" {
			seg = "all"
		}
		a.feeds = append(a.feeds, feedRow{f.ID, f.On()})
		on := "no"
		if f.On() {
			on = "yes"
		}
		rows = append(rows, row{fmt.Sprintf("%-28s %-8s %-8s %s", clip(f.ID, 28), f.Kind, clip(seg, 8), on), true})
	}
	st := a.cfg.FetchStatus()
	if net != "" {
		return append(rows, row{text: ""}, row{text: "feeds " + feedsLine(st) + "  (System > Feeds has the rest)"})
	}
	when := "never"
	if st.Ran {
		when = st.When.Format("2006-01-02 15:04") + " (" + fetch.Ago(st.Age) + ")"
	}
	rows = append(rows, row{text: ""}, row{text: "last fetch: " + when})
	if w := st.Warning(); w != "" {
		rows = append(rows, row{text: "  ! " + w})
	}
	for _, l := range st.Lines {
		rows = append(rows, row{text: "  " + l})
	}
	return rows
}

func slotState(s admin.SlotInfo) string {
	if s.DisabledAt.IsZero() {
		return "active"
	}
	age := time.Since(s.DisabledAt)
	return fmt.Sprintf("disabled %dd, purge in %dd", int(age.Hours()/24), max(int(math.Ceil((admin.PurgeAfter-age).Hours()/24)), 0))
}

// slotHour is what this slot spent against its hourly budget. The code
// compares this number with the warn and stop thresholds. A broker that
// did not answer shows "?", not zero. An idle slot and a dead fence look
// the same from here, and only one of them is fine.
func slotHour(s admin.SlotInfo) string {
	if !s.HourKnown {
		return "?"
	}
	if s.Hour.Requests == 0 && s.Hour.Bytes == 0 {
		return "-"
	}
	return fmt.Sprintf("%d req %dM", s.Hour.Requests, s.Hour.Bytes>>20)
}

func (a *App) buildSecrets() []row {
	list := get[[]admin.SlotInfo](a, "slots", admin.Args{})
	a.slots = a.slots[:0]
	// The state of the store first. A sealed store is silent until
	// something needs a credential. That can be hours after the reboot
	// that caused it. Thus the screen that lists the slots is where an
	// operator must find out that none of them is usable.
	rows := []row{{text: "store: " + a.secretsState()}}
	w := a.contentWidth()
	line := func(slot, kinds, used, hour, state string) string {
		return cols(w, col{slot, 16}, col{kinds, 22}, col{used, 18}, col{hour, 13}, col{state, 25})
	}
	rows = append(rows, row{text: line("slot", "kinds (state)", "last used", "last hour", "state")})
	for _, s := range list {
		var kinds []string
		for _, k := range s.Keys {
			kinds = append(kinds, k.Kind+" ("+k.State+")")
		}
		// UsePartial: this slot had no line in a use log that the code read
		// through a window that did not reach the start. Thus the known fact
		// is that nobody looked, not that nobody used it. An operator who
		// reads "never" here deletes a live credential.
		used := "never"
		if s.UsePartial {
			used = "unknown (partial log)"
		}
		if !s.LastUsed.IsZero() {
			used = stamp(s.LastUsed) + " " + s.LastHost
		}
		a.slots = append(a.slots, s.Slot)
		rows = append(rows, row{line(s.Slot, strings.Join(kinds, ", "), used, slotHour(s), slotState(s)), true})
	}
	if len(list) == 0 {
		rows = append(rows, row{text: "no slots"})
	}
	return rows
}

func (a *App) buildLog(kind admin.LogKind) []row {
	lines := get[[]string](a, "logs", admin.Args{Log: kind, N: tailN})
	if len(lines) == 0 {
		lines = []string{"(empty)"}
	}
	return text(lines...)
}

func (a *App) buildSegLog(kind admin.LogKind, seg string) []row {
	lines := get[[]string](a, "logs", admin.Args{Log: kind, N: tailN, Name: seg})
	if len(lines) == 0 {
		lines = []string{"(empty)"}
	}
	return text(lines...)
}

// plainSegments is the segments.d half of the segment list: the segments
// that are a file that an operator can edit. agent and house are not in
// it. They belong to net.env and house.env, and the code above answers for
// them.
func (a *App) plainSegments() []admin.Segment {
	var out []admin.Segment
	for _, s := range get[[]admin.Segment](a, "segments", admin.Args{}) {
		if s.Plain {
			out = append(out, s)
		}
	}
	return out
}

// segmentEdit is Enter on the row of a plain segment. ADMIN is the one
// change that asks first. The desk is the seat of the operator, and ssh to
// the Pi arrives over it. Thus to disable ADMIN from there can be the press
// that ends the session that makes it, at the next apply. That is why the
// prompt says when, not whether. The prompt to delete a reservation has the
// same shape for the same reason: it names what will be lost, and does not
// ask whether to continue.
func (a *App) segmentEdit(seg, key string) {
	save := func(v string) {
		if a.said("segment.set", admin.Args{Name: seg, Env: map[string]string{key: v}}, seg+" "+key+"="+v+" saved") {
			a.saved(applyLocal)
		}
	}
	// A file that cannot be read has no current value to change from. A
	// change from "" writes the non-default: ADMIN=yes with no confirm.
	// The read error stays on the screen.
	raw, err := a.call("segment.env", admin.Args{Name: seg})
	if a.fail(err) {
		return
	}
	env, ok := typed[map[string]string](a, raw)
	if !ok {
		return
	}
	if slices.Contains(admin.SegmentDHCPRange, key) {
		a.askDHCPRange(seg, env)
		return
	}
	pair, flips := admin.SegmentToggle[key]
	if !flips {
		a.askValue(seg+" "+key, env[key], save)
		return
	}
	v := segmentFlip(pair, env[key])
	if key == "ADMIN" && v == "no" {
		a.confirm("ssh to the Pi from "+seg+" stops at the next apply; set ADMIN=no", func() { save(v) })
		return
	}
	save(v)
}

// askDHCPRange is Enter on either end of the DHCP range of a segment. It
// asks for both ends, and each prompt opens on the current value. It sends
// them as one edit, because render refuses one end without the other on a
// segment that has no range yet. It does not use askValue: its "unchanged"
// stops at the first prompt, and a move of only the end is a normal edit.
func (a *App) askDHCPRange(seg string, env map[string]string) {
	ask := func(key string, done func(string)) {
		a.pr = &prompt{label: seg + " " + key, buf: env[key], done: func(v string) {
			if v == "" {
				a.msg = "cancelled"
				return
			}
			done(v)
		}}
	}
	ask("DHCP_START", func(start string) {
		ask("DHCP_END", func(end string) {
			if start == env["DHCP_START"] && end == env["DHCP_END"] {
				a.msg = "unchanged"
				return
			}
			kv := map[string]string{"DHCP_START": start, "DHCP_END": end}
			if a.said("segment.set", admin.Args{Name: seg, Env: kv}, seg+" DHCP range "+start+"-"+end+" saved") {
				a.saved(applyLocal)
			}
		})
	})
}

// segmentFlip is the value that Enter writes for one of the two-valued
// segment keys. pair[0] is the default that an absent line means.
func segmentFlip(pair [2]string, cur string) string {
	if cur == pair[1] {
		return pair[0]
	}
	return pair[1]
}

// askPair walks a set of keys that must be set together, with one prompt
// for each key. It sends them as one edit. Nested callbacks are the method
// for multi-field entry here. The reservation flow does the same. The
// alternative is one edit for each field, but a check that wants the full
// set refuses the first field.
func (a *App) askPair(keys []string, verb, msg string) {
	env := map[string]string{}
	var step func(i int)
	step = func(i int) {
		if i == len(keys) {
			if a.said(verb, admin.Args{Env: env}, msg) {
				a.saved(applyFull)
			}
			return
		}
		a.ask(keys[i]+" (empty on both turns DoT off)", func(v string) {
			env[keys[i]] = v
			step(i + 1)
		})
	}
	step(0)
}

// netFlip is the value Enter writes for a 0/1 key.
func netFlip(cur, def string) string {
	if cur == "" {
		cur = def
	}
	if cur == "1" {
		return "0"
	}
	return "1"
}

// houseOnOffFlip is the value Enter writes for an on/off key.
func houseOnOffFlip(key, cur string) string {
	if cur == "" {
		cur = admin.HouseOnOff[key]
	}
	if cur == "on" {
		return "off"
	}
	return "on"
}

var actionNames = []string{"apply (fetch + compile + reload)", "apply --local (nft + dns only; no fetch; fence restarts if any fence input changed)", "fetch feeds", "restart house dns", "reload house dns", "reboot", "shutdown"}

// houseActions are the actionNames indexes that act on the house segment.
var houseActions = map[int]bool{3: true, 4: true}

const houseMissing = "house segment not configured"

// The rows stay selectable also when there is no house segment. runAction
// uses the selectable position as its key. Thus if the code removed or
// disabled them, each action below would move onto the wrong verb.
func (a *App) buildActions() []row {
	var rows []row
	house := a.houseConfigured()
	for i, n := range actionNames {
		if houseActions[i] && !house {
			n += "  (" + houseMissing + ")"
		}
		rows = append(rows, row{n, true})
	}
	return rows
}

// houseConfigured is the test of the Overview: a house segment exists when
// house.env names HOUSE_IF.
func (a *App) houseConfigured() bool {
	return a.cfg != nil && a.cfg.House()["HOUSE_IF"] != ""
}

// do runs a verb that makes a change. On success, it reloads and shows msg.
// said is do for a verb that answers with a warning, not an error.
// net.env.set writes the edit and then says what is still wrong with the
// configuration. A box that already did not render must stay editable. If
// not, the seat cannot repair its own fault. If the code dropped that
// answer, it would report a clean save on a box that will not apply.
func (a *App) said(verb string, args admin.Args, msg string) bool {
	v, err := a.call(verb, args)
	if a.fail(err) {
		return false
	}
	a.reload()
	if w, _ := v.(string); w != "" {
		a.msg = msg + " -- " + w
		return true
	}
	a.msg = msg
	return true
}

func (a *App) do(verb string, args admin.Args, msg string) bool {
	if _, err := a.call(verb, args); a.fail(err) {
		return false
	}
	a.reload()
	a.msg = msg
	return true
}

func (a *App) screenKey(k Key) {
	switch {
	case k.Kind == KeyDown || k.Rune == 'j':
		a.move(1)
		return
	case k.Kind == KeyUp || k.Rune == 'k':
		a.move(-1)
		return
	case k.Kind == KeyPgDn:
		a.move(a.h / 2)
		return
	case k.Kind == KeyPgUp:
		a.move(-a.h / 2)
		return
	case k.Kind == KeyHome:
		a.move(-1 << 20)
		return
	case k.Kind == KeyEnd:
		a.move(1 << 20)
		return
	case k.Kind == KeyLeft || k.Rune == 'h':
		a.nextSection(-1)
		return
	case k.Kind == KeyRight || k.Rune == 'l':
		a.nextSection(1)
		return
	}
	i := a.selected()
	switch a.cur.sec {
	case secDevices:
		if a.cur.net == netHouse {
			a.devicesKey(k, i)
		} else {
			a.clientsKey(k, i)
		}
	case secFiltering:
		if a.onFeedsTab() {
			a.feedKey(k, i)
		} else {
			a.listKey(k, i)
		}
	case secFeeds:
		a.feedKey(k, i)
	case secKeys:
		if !a.secretsStoreKey(k) {
			a.secretsKey(k, i)
		}
	case secSettings:
		if k.Kind == KeyEnter || k.Rune == 'e' {
			a.settingsEdit(i)
		}
	case secActions:
		if k.Kind == KeyEnter {
			a.runAction(i)
		}
	}
}

// feedKey is e on a feed, from System or from the Filtering of a network.
// A feed that is off stops its blocklist for all networks, and no row on
// this screen shows that cost. Thus disable asks first and names the feed.
// Enable adds protection and does not ask.
func (a *App) feedKey(k Key, i int) {
	if k.Rune != 'e' || i < 0 || i >= len(a.feeds) {
		return
	}
	f := a.feeds[i]
	toggle := func() {
		if a.do("feed.enable", admin.Args{Name: f.id, Value: fmt.Sprint(!f.on)}, f.id+" toggled") {
			a.saved(applyFull)
		}
	}
	if !f.on {
		toggle()
		return
	}
	a.confirm("disable feed "+f.id+" for the whole box", toggle)
}

func (a *App) secretsKey(k Key, i int) {
	if i < 0 || i >= len(a.slots) {
		return
	}
	slot := a.slots[i]
	args := admin.Args{Name: slot}
	switch k.Rune {
	case 'c':
		if v, err := a.call("claim.issue", args); !a.fail(err) {
			if c, ok := typed[admin.Claim](a, v); ok {
				a.showClaim(c)
			}
		}
	case 'x':
		a.confirm("disable slot "+slot, func() { a.do("slot.disable", args, "disabled "+slot+"; purged on an apply once 7 days old") })
	case 'R':
		a.do("slot.restore", args, "restored "+slot)
	case 'p':
		a.confirmTyped("purge slot "+slot, func() { a.do("slot.purge", args, "purged "+slot) })
	case 'd':
		// Delete removes the credentials at once, and nothing restores
		// them. Thus it asks for the typed yes, as purge does. x and R are
		// reversible and stay on one y.
		a.confirmTyped("delete slot "+slot+"; its credentials go away at once", func() { a.do("slot.delete", args, "deleted "+slot) })
	}
}

// The code reads secretsState on each build, and does not cache it. It
// changes while the operator works, from a reboot or from pf unlock on a
// different terminal. A stale "unlocked" is the one wrong answer here.
func (a *App) secretsState() string {
	v, err := a.call("secrets.state", admin.Args{})
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	st, _ := typed[string](a, v)
	return st
}

// secretsStoreKey is the screen-level half of secretsKey. It acts on the
// store, not on the slot under the cursor. Thus it runs also when there is
// no slot under the cursor.
func (a *App) secretsStoreKey(k Key) bool {
	switch k.Rune {
	case 'u':
		a.askSecret("passphrase", func(p string) {
			if p == "" {
				a.msg = "cancelled"
				return
			}
			a.do("secrets.unlock", admin.Args{Secret: p}, "unlocked")
		})
		return true
	case 'L':
		a.confirm("lock the credential store", func() {
			a.do("secrets.lock", admin.Args{}, "locked; substitution stops until pf unlock")
		})
		return true
	}
	return false
}

func (a *App) devicesKey(k Key, i int) {
	// When the detail of a device is open, the cursor indexes its rows,
	// not the lease table. Thus r or d would act on a different device.
	if a.detail != "" || i < 0 || i >= len(a.hosts) {
		return
	}
	h := a.hosts[i]
	switch {
	case k.Kind == KeyEnter:
		for _, c := range a.stats.Clients {
			if c.Segment == netHouse && c.IP == h.IP {
				a.detail, a.back = clientKey(c), i
				a.here().pos = 0
				a.rebuild()
				return
			}
		}
		a.msg = "nothing recorded for " + h.IP + " yet"
	case k.Rune == 'r':
		a.ask("name for "+h.MAC, func(name string) {
			next, _ := a.cfg.NextFreeIP()
			a.ask(fmt.Sprintf("ip (Enter = %s)", next), func(ip string) {
				v, err := a.call("reserve", admin.Args{MAC: h.MAC, IP: ip, Name: name})
				if a.fail(err) {
					return
				}
				r, ok := typed[admin.Reservation](a, v)
				if !ok {
					return
				}
				a.reload()
				a.seekHost(r.MAC)
				a.offerReload(fmt.Sprintf("reserved %s -> %s", r.MAC, r.IP))
			})
		})
	case k.Rune == 'd':
		if !h.Reserved {
			a.msg = "not a reservation"
			return
		}
		// The name and the address, and also the MAC. The MAC is the one
		// of the three that nobody recognises. On the day of the wrong
		// deletion of a reservation, the prompt showed only the MAC.
		a.confirm(fmt.Sprintf("delete reservation %s %s (%s)", h.Name, h.IP, h.MAC), func() {
			if a.do("unreserve", admin.Args{MAC: h.MAC}, "") {
				a.seekHost(h.MAC)
				a.offerReload("deleted " + h.MAC)
			}
		})
	}
}

// seekHost puts the cursor back on a device after the list was rebuilt.
// Reserved hosts sort before plain leases. Thus a pin or unpin moves the
// row of a host. A cursor left on the old index is on a different device,
// and the next key acts on a host that the operator never chose.
func (a *App) seekHost(mac string) {
	for i, h := range a.hosts {
		if h.MAC == mac {
			a.here().pos = i
			a.rebuild()
			return
		}
	}
}

func (a *App) offerReload(msg string) {
	a.msg = msg
	a.confirm(msg+"; reload house dns now", func() {
		if _, err := a.call("dns.reload", admin.Args{}); !a.fail(err) {
			a.msg = msg + "; house dns reloaded"
		}
	})
}

func (a *App) listKey(k Key, i int) {
	prefix, name := a.listVerb()
	if a.cur.readOnlyLists() && (k.Rune == 'a' || k.Rune == 'd') {
		a.msg = listLabel(name) + " is the agent network's; edit it under Agent network > Filtering"
		return
	}
	switch k.Rune {
	case 'a':
		a.ask("add to "+name, func(v string) {
			tok, err := admin.ValidateToken(name, v)
			if v == "" || a.fail(err) {
				return
			}
			if a.do(prefix+".add", admin.Args{List: name, Value: tok}, "added "+tok) {
				a.saved(applyLocal)
			}
		})
	case 'd':
		if i < 0 || i >= len(a.items) {
			return
		}
		it := a.items[i]
		a.confirm("delete "+it, func() {
			if a.do(prefix+".del", admin.Args{List: name, Value: it}, "deleted "+it) {
				a.saved(applyLocal)
			}
		})
	case 't':
		if a.cur.net != netHouse {
			return
		}
		def := ""
		if i >= 0 && i < len(a.items) {
			def = a.items[i]
		}
		a.ask("resolve via house dns (Enter = "+def+")", func(v string) {
			if v == "" {
				v = def
			}
			if v == "" {
				return
			}
			server := a.cfg.House()["HOUSE_IP"]
			addrs, err := admin.Resolve(server, v)
			if err != nil {
				a.msg = v + ": " + err.Error()
				return
			}
			a.msg = v + " @" + server + " -> " + strings.Join(addrs, " ")
		})
	}
}

func (a *App) runAction(i int) {
	if houseActions[i] && !a.houseConfigured() {
		a.msg = "house not configured: Home network > Settings"
		return
	}
	switch i {
	case 0:
		a.runApply(applyFull)
	case 1:
		a.runApply(applyLocal)
	case 2:
		a.stream("pf fetch", "fetch", admin.Args{})
	case 3:
		a.confirm("restart "+admin.HouseDNSUnit, func() { a.report("restarted", "dns.restart") })
	case 4:
		a.report("reloaded", "dns.reload")
	case 5:
		a.confirmTyped("reboot the Pi", func() { a.report("rebooting", "reboot") })
	case 6:
		a.confirmTyped("shut the Pi down", func() { a.report("shutting down", "poweroff") })
	}
}

// report runs a verb the operator has already confirmed at the prompt.
func (a *App) report(ok, verb string) {
	if _, err := a.call(verb, admin.Args{Confirm: true}); !a.fail(err) {
		a.msg = ok + " " + time.Now().Format("15:04:05")
	}
}
