package admin

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/observe"
	"pi-fortress/internal/secrets"

	"pi-fortress/internal/base"
)

const topN = 8

type Dest struct {
	Dst   string
	Dport int
	Proto string
	Bytes int
}

type Device struct {
	AgentIP    string
	AgentNet   string
	Started    string
	LastSeen   string
	DNSNames   int
	DNSQueries int
	HouseNames int
	Flows      int
	Bytes      int
	Strips     int
	TopDests   []Dest
}

func loadObserve(path string) *observe.State {
	st := &observe.State{}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, st)
	}
	return st
}

func (c *Config) Device() Device {
	st := loadObserve(c.ObservePath)
	d := Device{AgentIP: c.netVal("AGENT_IP", "10.77.0.10"), AgentNet: c.netVal("AGENT_NET", "10.77.0.0/24"), Started: st.Started}
	srcs := map[string]struct{}{}
	for _, rec := range st.DNS {
		if rec == nil {
			continue
		}
		// The agent segment writes its rows with no segment name. The house and
		// each plain segment write their own name. Before plain segments had their
		// own resolver, this could be a two-way split: all rows not from the house
		// were from the agent. Now the desk also resolves here. If the summary
		// folds the desk in, it reports the desk lookups as lookups of the agent.
		// Also, through srcs below, it shows the address of a desk client as
		// AgentIP. A wrong number that looks right is worse than a missing number.
		// Thus this summary does not include a plain segment until the summary
		// has a location for it.
		switch rec.Segment {
		case "house":
			d.HouseNames++
			continue
		case "":
		default:
			continue
		}
		d.DNSNames++
		d.DNSQueries += rec.Count
		if rec.Src != "" {
			srcs[rec.Src] = struct{}{}
		}
		d.LastSeen = max(d.LastSeen, rec.LastSeen)
	}
	for _, rec := range st.Flows {
		if rec == nil {
			continue
		}
		d.Flows++
		d.Bytes += rec.Bytes
		d.TopDests = append(d.TopDests, Dest{rec.Dst, rec.Dport, rec.Proto, rec.Bytes})
		d.LastSeen = max(d.LastSeen, rec.LastSeen)
	}
	sort.Slice(d.TopDests, func(i, j int) bool { return d.TopDests[i].Bytes > d.TopDests[j].Bytes })
	if len(d.TopDests) > topN {
		d.TopDests = d.TopDests[:topN]
	}
	if len(srcs) > 0 {
		keys := make([]string, 0, len(srcs))
		for k := range srcs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d.AgentIP = keys[0]
	}
	d.Strips = countLines(c.StripLog)
	return d
}

func countLines(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// ResetObserve is the reset button of the TUI. It gives the work to the
// observe package, and does not do its own version of it. The old version
// wrote an empty ledger without a lock. Thus a daemon flush between the two
// writes published again all that reset had discarded. The old version
// also rewound only the agent DNS offset. It did not move the house
// resolver, the strip log or the journal cursor. Thus the next tick rebuilt
// the ledger with a hole of exactly the size of the discarded data.
func (c *Config) ResetObserve() error {
	o := observe.Defaults()
	o.Stdout = io.Discard
	o.StatePath, o.DNSLog, o.OffsetPath = c.ObservePath, c.DNSLogPath, c.OffsetPath
	o.HouseDNSLog, o.StripLog = c.HouseDNSLog, c.StripLog
	// The other checkpoints have no Config field of their own. They are
	// siblings of the agent offset in the state directory. The code takes them
	// from there, not from the package defaults. Thus a Config that points at
	// a test tree, or at the state of a second box, does not rewind the
	// checkpoints of the real box.
	if dir := filepath.Dir(c.OffsetPath); c.OffsetPath != "" {
		o.HouseOffsetPath = filepath.Join(dir, filepath.Base(o.HouseOffsetPath))
		o.StripOffsetPath = filepath.Join(dir, filepath.Base(o.StripOffsetPath))
		o.JournalCursorPath = filepath.Join(dir, filepath.Base(o.JournalCursorPath))
	}
	return o.Reset()
}

// SlotInfo is a slot as the Secrets screen shows it: names, kinds and
// states from the store, last use from the use log of the broker, and the
// quarantine time from the sidecar. Never a value.
type SlotInfo struct {
	secrets.SlotList
	LastUsed   time.Time
	LastHost   string
	DisabledAt time.Time
	// UsePartial says that the code read the use log through a window that did
	// not reach the start, and that this slot had no line in the window. Thus a
	// zero LastUsed means "not in what we read", not "never used". Without this
	// difference, an operator deletes a live slot because the screen said
	// never.
	UsePartial bool
	// Hour is the amount that this slot spent in the last hour, from the broker
	// (internal/broker/budget.go). HourKnown says that the broker answered. A
	// dead broker and an idle slot are different facts, and the screen does not
	// show them as the same fact. The reason is the same as for UsePartial.
	Hour      SlotHour
	HourKnown bool
}

const PurgeAfter = 7 * 24 * time.Hour

func (c *Config) Slots() ([]SlotInfo, error) {
	rows, err := c.store().ListSlots()
	off, _ := c.store().Disabled()
	use, partial := c.lastUse()
	// Best effort, and brief: this list is about the store. The operator must
	// be able to read the list when the broker is down.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hours, hoursErr := c.SlotHours(ctx)
	out := make([]SlotInfo, 0, len(rows))
	for _, r := range rows {
		si := SlotInfo{SlotList: r}
		if hoursErr == nil {
			si.Hour, si.HourKnown = hours[r.Slot], true
		}
		if u, ok := use[r.Slot]; ok {
			si.LastUsed, si.LastHost = u.at, u.host
		} else {
			// The window reaches the end of the log. Thus a use in the window is the
			// latest use. Only a slot that is not in the window is in doubt, and only
			// when the window did not reach the start.
			si.UsePartial = partial
		}
		if ts, ok := off[r.Slot]; ok {
			si.DisabledAt = time.Unix(ts, 0)
		}
		out = append(out, si)
	}
	return out, err
}

type useRec struct {
	at   time.Time
	host string
}

// lastUse scans the tail of use.jsonl (bounded by Tail) for the newest line
// of each slot. It reports whether that tail left out some lines.
func (c *Config) lastUse() (map[string]useRec, bool) {
	out := map[string]useRec{}
	lines, partial, _ := tailCovering(c.UseLog, 5000)
	for _, l := range lines {
		var ev jsonl.Use
		if json.Unmarshal([]byte(l), &ev) != nil || ev.Slot == "" {
			continue
		}
		at, err := base.ParseISO(ev.T)
		if err != nil {
			continue
		}
		out[ev.Slot] = useRec{at, ev.Host}
	}
	return out, partial
}

func (c *Config) DeleteSlot(slot string) ([]string, error) {
	return c.store().DeleteSlot(strings.ToLower(strings.TrimSpace(slot)))
}

func (c *Config) DisableSlot(slot string) error { return c.store().Disable(slot) }
func (c *Config) RestoreSlot(slot string) error { return c.store().Restore(slot) }
func (c *Config) PurgeSlot(slot string) ([]string, error) {
	return c.store().Purge(slot)
}
