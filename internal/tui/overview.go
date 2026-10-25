package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/monitor"
)

const overviewFmt = "%-16s %7s %14s  %s"

// buildOverview answers the first question of an operator who opens the
// seat (is all correct?) before any detail: a verdict, then a line for each
// network, then the Pi. The operator must act on each problem that this
// names. The detail behind each problem is on the views of its network or
// on System.
func (a *App) buildOverview() []row {
	// A failed query is not a clean answer. "All good" over a check that never
	// ran is the one verdict that this screen must not give.
	var blind []string
	units := checked[[]admin.UnitState](a, "units", &blind)
	ifaces := checked[[]admin.Iface](a, "ifaces", &blind)
	st := checked[admin.Status](a, "status", &blind)
	a.stats = checked[admin.Stats](a, "stats", &blind)
	house := map[string]string{}
	if a.cfg != nil {
		house = a.cfg.House()
	}

	var problems []string
	for _, verb := range blind {
		problems = append(problems, "cannot check: "+verb)
	}
	if a.warn != "" {
		problems = append(problems, strings.Split(a.warn, "  |  ")...)
	}
	if len(units) > 0 && !slices.ContainsFunc(units, func(u admin.UnitState) bool { return u.State != "unknown" }) {
		problems = append(problems, "cannot check: units (systemctl answered for none of them; System > Health)")
	}
	for _, u := range units {
		// unknown is systemctl saying nothing, not a unit that stopped.
		if u.State != "active" && u.State != "unknown" {
			problems = append(problems, u.Unit+" is "+u.State+" (System > Health)")
		}
	}
	if st.RebootRequired {
		problems = append(problems, "reboot required: updates installed, kernel or libc still old (System > Actions)")
	}
	if wg := house["WG_IF"]; wg != "" {
		if l := wgLine(wg, ifaces); !strings.HasPrefix(l, wg+"  up  ") {
			problems = append(problems, "home VPN tunnel "+strings.TrimPrefix(l, wg+"  ")+": the house is offline")
		}
	}

	// A threat that the Pi saw and did not stop is the most important fact
	// on the box. Before, only Activity showed it. The count is the events
	// that Activity shows: the newest rows of the observe ring, at most
	// seven days. They are marked with seenMark, not with "!", because they
	// are events, not a standing fault.
	alerts := map[string]int{}
	for _, e := range a.stats.Events {
		if e.Alert {
			alerts[e.Segment]++
		}
	}
	var seen []string
	for _, e := range a.netList() {
		if n := alerts[e.id]; n > 0 {
			seen = append(seen, fmt.Sprintf("%d %s seen and not stopped on %s (Activity)", n, plural(n, "threat"), e.label))
		}
	}

	var rows []row
	if len(problems)+len(seen) == 0 {
		rows = append(rows, row{text: "All good"})
	} else {
		rows = append(rows, row{text: "Needs attention"})
		for _, p := range problems {
			rows = append(rows, row{text: "  ! " + p})
		}
		for _, p := range seen {
			rows = append(rows, row{text: "  " + seenMark + " " + p})
		}
	}
	rows = append(rows, row{text: ""}, row{text: fmt.Sprintf(overviewFmt, "network", "devices", "blocked today", "notes")})
	for _, e := range a.netList() {
		if e.id == netOverview || e.id == netSystem {
			continue
		}
		devices, blocked := 0, "-"
		for _, c := range a.stats.Clients {
			if c.Segment == e.id {
				devices++
			}
		}
		if days := a.stats.Series[e.id]; len(days) > 0 {
			blocked = fmt.Sprint(days[len(days)-1].Blocked)
		}
		notes := a.netNotes(e.id, house, st, ifaces)
		if n := alerts[e.id]; n > 0 {
			notes = strings.TrimRight(fmt.Sprintf("%s %d not stopped  %s", seenMark, n, notes), " ")
		}
		rows = append(rows, row{text: strings.TrimRight(fmt.Sprintf(overviewFmt, clip(e.label, 16), fmt.Sprint(devices), blocked, notes), " ")})
	}
	rows = append(rows, row{text: ""}, row{text: a.piLine(st)})
	return rows
}

// netNotes is the one important fact about each network at first look.
func (a *App) netNotes(id string, house map[string]string, st admin.Status, ifaces []admin.Iface) string {
	switch id {
	case netAgent:
		return fmt.Sprintf("keys stripped %d", st.Device.Strips)
	case netHouse:
		if house["HOUSE_IF"] == "" {
			return "not set up (docs: home_network.md)"
		}
		egress := house["HOUSE_EGRESS"]
		if egress == "" {
			egress = "strict"
		}
		notes := "ports " + egress
		if egress == "audit" {
			notes += " (logging, not blocking)"
		}
		if wg := house["WG_IF"]; wg != "" {
			notes += "  vpn " + wgLine(wg, ifaces)
		}
		return notes
	}
	return ""
}

// piLine starts with the time of the checks. A seat that froze continues
// to show its last verdict, and without a time that verdict looks current.
// The time goes before the figures, so a narrow terminal does not clip it.
func (a *App) piLine(st admin.Status) string {
	apply := "idle"
	if st.ApplyRunning {
		apply = "running"
	}
	pi := "Pi  checked " + a.now().Format("15:04:05")
	s := get[*monitor.Sample](a, "sample", admin.Args{})
	if s == nil {
		return pi + "  no monitor sample yet  apply " + apply
	}
	return fmt.Sprintf("%s  cpu %s  temp %s  mem %s  apply %s", pi,
		figure(s.Has("cpu"), "%.0f%%", s.CPU),
		figure(s.Has("temp"), "%.0fC", s.TempC),
		figure(s.Has("mem"), "%.0f%%", s.MemUsedPct),
		apply)
}

// now is the clock of the config, so a test can fix it.
func (a *App) now() time.Time {
	if a.cfg != nil && a.cfg.Now != nil {
		return a.cfg.Now()
	}
	return time.Now()
}

func plural(n int, s string) string {
	if n == 1 {
		return s
	}
	return s + "s"
}

// checked is get for the verdict of the Overview. A verb that fails, or
// answers with the wrong shape, is named in blind, and not read as empty.
func checked[T any](a *App, verb string, blind *[]string) T {
	var zero T
	v, err := a.call(verb, admin.Args{})
	if err != nil {
		*blind = append(*blind, verb)
		return zero
	}
	if v == nil {
		return zero
	}
	t, ok := v.(T)
	if !ok {
		*blind = append(*blind, verb)
	}
	return t
}
