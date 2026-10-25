package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/admin"
)

// threatOf marks a row that the Pi only saw. An address claim goes on the
// same ring as a sinkhole drop and shows in the same table. The columns
// read as things that were stopped. An arp_flip row even puts the claimed
// MAC under "destination". Without the mark, an operator reads a neighbour
// that took an address with no consequence as a neighbour that was refused.
// The mark is "^", not "!". "!" is a standing fault: the title bar, the
// problems on Overview, a stale feed. "?" is a value that nothing answered,
// "-" is none, and "*" is a masked passphrase.
const seenMark = "^"

func threatOf(e admin.EventStat) string {
	if e.Alert {
		return seenMark + " " + e.Threat
	}
	return e.Threat
}

// Devices and Activity show
// observe.json as last flushed. The code reads it again on each statsTick
// while one of them shows.
var statsTick = 5 * time.Second

// logTabs is logs.list: the fixed logs, then one for each plain segment.
// The code asks for it one time and keeps it.
func (a *App) logTabs() []string {
	if a.logs == nil {
		a.logs = get[[]string](a, "logs.list", admin.Args{})
	}
	if len(a.logs) == 0 {
		return admin.LogNames
	}
	return a.logs
}

const (
	noStats = "no data yet; observe flushes every PF_OBSERVE_FLUSH_INTERVAL"
	// The header of eventFmt is 62 wide. That is the content width at 80
	// columns beside the menu. The source column is 15, the width of an address.
	eventFmt = "%-14s  %-18s %-15s %s"
	// namedFmt is eventFmt with the name of the source after its address.
	// The header is 77 wide.
	namedFmt   = "%-14s  %-18s %-15s %-14s %s"
	detailEvts = 20
	// seriesFmt is the label column of the bar rows. Day cells follow, four
	// wide, with one space between, so the numbers are under the bars.
	seriesFmt = "%-5s  %-10s  "
	barGlyphs = "▁▂▃▄▅▆▇█"
	barASCII  = "_.:-=+*#"
)

// clientRow is a row of the Devices of a plain network: the counts before
// the MAC, as on the home network, so they fit at 80 columns.
func clientRow(w int, name, ip, q, fl, bl, last, mac string) string {
	return cols(w, col{name, 13}, col{ip, 15}, col{q, -7}, col{fl, -5}, col{bl, -7}, col{last, -5}, col{mac, 17})
}

// ticks says that the view shows live counts that are worth a new read.
func (a *App) ticks() bool {
	switch a.cur.sec {
	case secOverview, secDevices:
		return true
	case secActivity:
		return a.activityTab().blocked
	}
	return false
}

// closeDetail returns to the device table. It returns false when the detail was not open.
func (a *App) closeDetail() bool {
	if a.detail == "" {
		return false
	}
	a.detail = ""
	a.here().pos = a.back
	a.rebuild()
	return true
}

func age(t, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", max(int(d.Seconds()), 0))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func when(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("01-02 15:04:05")
}

func clientKey(c admin.ClientStat) string { return c.Segment + "/" + c.IP }

// buildClients is the devices of a network as observe counted them. Only
// the house has leases to show beside them. Refer to buildHouseDevices.
func (a *App) buildClients(seg string) []row {
	a.stats = get[admin.Stats](a, "stats", admin.Args{})
	a.clients = a.clients[:0]
	for _, c := range a.stats.Clients {
		if c.Segment == seg {
			a.clients = append(a.clients, c)
		}
	}
	if a.detail != "" {
		for _, c := range a.clients {
			if clientKey(c) == a.detail {
				return a.buildDetail(c)
			}
		}
		a.detail = ""
		a.here().pos = a.back
	}
	w := a.contentWidth()
	rows := []row{{text: clientRow(w, "name", "ip", "queries", "flows", "blocked", "last", "mac")}}
	now := time.Now()
	for _, c := range a.clients {
		rows = append(rows, row{clientRow(w, c.Name, c.IP,
			fmt.Sprint(c.Queries), fmt.Sprint(c.Flows), fmt.Sprint(c.Blocked), age(c.LastSeen, now), c.MAC), true})
	}
	if len(a.clients) == 0 {
		rows = append(rows, row{text: noStats})
	}
	return rows
}

// buildDetail is one client: top names beside top dests, then its events.
// Each row is selectable, so j/k scrolls on a short terminal.
func (a *App) buildDetail(c admin.ClientStat) []row {
	name := c.Name
	if name == "" {
		name = c.IP
	}
	rows := []row{
		{text: fmt.Sprintf("%s  %s  %s  queries %d  flows %d  blocked %d  last %s", name, c.MAC, c.IP, c.Queries, c.Flows, c.Blocked, age(c.LastSeen, time.Now()))},
		{text: ""},
		{text: fmt.Sprintf("%-37s  %s", "top names", "top dests")},
	}
	for i := 0; i < max(len(c.TopNames), len(c.TopDests)); i++ {
		l, r := "", ""
		if i < len(c.TopNames) {
			l = fmt.Sprintf("%-30s %6d", clip(c.TopNames[i].Name, 30), c.TopNames[i].Count)
		}
		if i < len(c.TopDests) {
			r = fmt.Sprintf("%-30s %6d", clip(c.TopDests[i].Dest, 30), c.TopDests[i].Count)
		}
		rows = append(rows, row{strings.TrimRight(fmt.Sprintf("%-37s  %s", l, r), " "), true})
	}
	rows = append(rows, row{text: ""}, row{text: "events"})
	n := 0
	for _, e := range a.stats.Events {
		if e.Segment != c.Segment || e.Src != c.IP {
			continue
		}
		rows = append(rows, row{fmt.Sprintf("%-14s  %-18s %s", when(e.T), clip(threatOf(e), 18), dstHits(e)), true})
		if n++; n == detailEvts {
			break
		}
	}
	if n == 0 {
		rows = append(rows, row{text: "  none"})
	}
	return rows
}

// dstHits is the destination, with ×N when the row folds repeats.
func dstHits(e admin.EventStat) string {
	if e.Hits > 1 {
		return fmt.Sprintf("%s ×%d", e.Dst, e.Hits)
	}
	return e.Dst
}

// buildEvents is the blocked table of one network, with its week under it.
// The table stays short, so the bar rows stay on the screen. The events
// give way, but the series does not.
func (a *App) buildEvents(seg string) []row {
	a.stats = get[admin.Stats](a, "stats", admin.Args{})
	series := a.buildSeries(seg)
	h := a.h
	if h == 0 {
		h = 24
	}
	// Five lines of chrome: the title, the section and tab strips, the
	// column head and the status line.
	limit := max(h-5-len(series), 1)
	evs := make([]admin.EventStat, 0, len(a.stats.Events))
	for _, e := range a.stats.Events {
		if seg == "" || e.Segment == seg {
			evs = append(evs, e)
		}
	}
	shown := evs[:min(len(evs), limit)]
	// The source is the address. A device chooses its own name, so the name
	// goes beside the address and never in its place. Before, the name
	// replaced the address, and a device could show itself as a different
	// one. The name gets a column only when the width has space for it. At
	// 80 columns it does not, and Devices gives the name of each address.
	named := false
	for _, e := range shown {
		named = named || e.Name != ""
	}
	head := fmt.Sprintf(eventFmt, "time", "threat", "source", "destination")
	if wide := fmt.Sprintf(namedFmt, "time", "threat", "source", "name", "destination"); named && len(wide) <= a.contentWidth() {
		head = wide
	} else {
		named = false
	}
	// The legend goes on only when the row has space. At 80 columns, the
	// header already fills the content width exactly. Thus any addition
	// removed the last character of "destination". That legend explained one
	// mark and removed a different one. Where it does not fit, ? help has the
	// same sentence.
	for _, e := range evs {
		if e.Alert {
			if legend := "  " + seenMark + " = not stopped"; len(head)+len(legend) <= a.w-menuWidth {
				head += legend
			}
			break
		}
	}
	rows := []row{{text: head}}
	for _, e := range shown {
		text := fmt.Sprintf(eventFmt, when(e.T), clip(threatOf(e), 18), e.Src, dstHits(e))
		if named {
			text = fmt.Sprintf(namedFmt, when(e.T), clip(threatOf(e), 18), e.Src, clip(e.Name, 14), dstHits(e))
		}
		rows = append(rows, row{text, true})
	}
	if len(evs) == 0 {
		rows = append(rows, row{text: noStats})
	}
	return append(rows, series...)
}

// buildSeries is three rows for each segment: blocked for each local day as
// a bar scaled to the week of that segment, then queries and flows. One
// segment when seg names one, else all of them.
func (a *App) buildSeries(seg string) []row {
	segs := make([]string, 0, len(a.stats.Series))
	for s := range a.stats.Series {
		if seg == "" || s == seg {
			segs = append(segs, s)
		}
	}
	sort.Strings(segs)
	glyphs := []rune(barASCII)
	if a.utf8 {
		glyphs = []rune(barGlyphs)
	}
	rows := []row{{text: ""}}
	for _, seg := range segs {
		days := a.stats.Series[seg]
		var peak uint32
		for _, d := range days {
			peak = max(peak, d.Blocked)
		}
		bars, qs, fs := make([]string, len(days)), make([]string, len(days)), make([]string, len(days))
		for i, d := range days {
			bars[i] = fmt.Sprintf("%4s", day(d.Day)+" "+string(glyphs[bar(d.Blocked, peak, len(glyphs))]))
			qs[i] = fmt.Sprintf("%4s", compact(d.Queries))
			fs[i] = fmt.Sprintf("%4s", compact(d.Flows))
		}
		rows = append(rows,
			row{text: fmt.Sprintf(seriesFmt+"%s  max %d", seg, "blocked 7d", strings.Join(bars, " "), peak)},
			row{text: fmt.Sprintf(seriesFmt+"%s", "", "queries", strings.Join(qs, " "))},
			row{text: fmt.Sprintf(seriesFmt+"%s", "", "flows", strings.Join(fs, " "))})
	}
	return rows
}

// day is the day of the month of an MM-DD label. The table above carries
// the month.
func day(mmdd string) string {
	if i := strings.IndexByte(mmdd, '-'); i >= 0 {
		return mmdd[i+1:]
	}
	return mmdd
}

// bar is the glyph index for v against peak: 0 for nothing, n-1 at the
// peak. A week with no blocks is a flat floor.
func bar(v, peak uint32, n int) int {
	if v == 0 || peak == 0 {
		return 0
	}
	return int((uint64(v)*uint64(n)+uint64(peak)-1)/uint64(peak)) - 1
}

// compact fits a count in four cells.
func compact(n uint32) string {
	switch {
	case n < 10000:
		return fmt.Sprint(n)
	case n < 10000000:
		return fmt.Sprintf("%dk", n/1000)
	}
	return fmt.Sprintf("%dM", n/1000000)
}

func (a *App) clientsKey(k Key, i int) {
	if k.Kind != KeyEnter || a.detail != "" || i < 0 || i >= len(a.clients) {
		return
	}
	a.detail, a.back = clientKey(a.clients[i]), i
	a.here().pos = 0
	a.rebuild()
}
