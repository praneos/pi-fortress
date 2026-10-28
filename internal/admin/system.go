package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/monitor"
	"pi-fortress/internal/observe"
)

type UnitState struct{ Unit, State string }

// UnitsHealth runs one systemctl is-active over the unit list. The output
// has one state on each line, in argument order.
func (c *Config) UnitsHealth() []UnitState {
	ctx, cancel := timeout(5 * time.Second)
	defer cancel()
	units := c.units()
	out, _ := c.exec(ctx, append([]string{"systemctl", "is-active"}, units...)...)
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	states := make([]UnitState, len(units))
	for i, u := range units {
		st := "unknown"
		if i < len(lines) && strings.TrimSpace(lines[i]) != "" {
			st = strings.TrimSpace(lines[i])
		}
		states[i] = UnitState{u, st}
	}
	return states
}

type Iface struct {
	Name  string
	Up    bool
	Addrs []string
}

// Interfaces is c.Ifaces when set, else the host's own.
func (c *Config) Interfaces() []Iface {
	if c != nil && c.Ifaces != nil {
		return c.Ifaces()
	}
	return Interfaces()
}

func Interfaces() []Iface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Iface
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		row := Iface{Name: i.Name, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				row.Addrs = append(row.Addrs, a.String())
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LastSample returns the newest monitor sample, or nil when there is none.
func (c *Config) LastSample() *monitor.Sample {
	m := monitor.Defaults()
	m.Dir = c.MonitorDir
	return m.Latest()
}

type LogKind int

const (
	LogFirstSeen LogKind = iota
	LogStrips
	LogAlerts
	LogHouseDrops
	LogHouseDNS
	LogAudit
	LogAgentDNS
	// LogSegDNS is the resolver log of the first plain segment. The other
	// segments follow it in the order that Segments returns them. Before, the
	// screen had a case for no resolver log except the log of the house. It
	// did not show the log of the agents, which is the busiest file on the
	// box. It did not show the log of a plain segment, which nothing else on
	// the seat could show either. Thus the one screen for raw log text could
	// not reach the logs that the box writes most.
	LogSegDNS
)

var LogNames = []string{"first-seen", "strips", "alerts", "house drops", "house dns", "admin audit", "agent dns"}

// LogList is the tabs that the Logs screen shows: the fixed ones, then one
// for each plain segment. It is a method, not a variable, because a
// segment appears when an operator applies one.
func (c *Config) LogList() []string {
	out := append([]string(nil), LogNames...)
	for _, s := range observe.PlainSegments(c.SegmentsDir) {
		out = append(out, "dns "+s.Name)
	}
	return out
}

// segDNSLog names the resolver log of a plain segment. apply.sh writes it
// beside the log of the house, with the same convention that observe uses
// to read it.
func (c *Config) segDNSLog(name string) string {
	return filepath.Join(filepath.Dir(c.HouseDNSLog), "dns-"+name+".jsonl")
}

func (c *Config) Log(kind LogKind, n int) ([]string, error) {
	switch kind {
	case LogFirstSeen:
		return c.firstSeen(n), nil
	case LogStrips:
		return Tail(c.StripLog, n)
	case LogAlerts:
		last, err := Tail(c.AlertLast, 1)
		if len(last) > 0 {
			last[0] = "last alert: " + last[0]
		}
		return last, err
	case LogHouseDrops:
		ctx, cancel := timeout(5 * time.Second)
		defer cancel()
		out, err := c.exec(ctx, "journalctl", "-k", "-g", "pi-fortress house-drop|house-killswitch", "-n", fmt.Sprint(n), "--no-pager")
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if err != nil && len(strings.TrimSpace(string(out))) == 0 {
			return nil, err
		}
		return lines, nil
	case LogAudit:
		return Tail(c.AuditPath, n)
	case LogHouseDNS:
		lines, err := Tail(c.HouseDNSLog, n)
		return readableDNS(lines), err
	case LogAgentDNS:
		lines, err := Tail(c.DNSLogPath, n)
		return readableDNS(lines), err
	}
	if segs := observe.PlainSegments(c.SegmentsDir); kind >= LogSegDNS && int(kind-LogSegDNS) < len(segs) {
		lines, err := Tail(c.segDNSLog(segs[kind-LogSegDNS].Name), n)
		return readableDNS(lines), err
	}
	return nil, errors.New("unknown log")
}

// readableDNS renders the transaction rows of a JSONL resolver log as text
// that a person can read. It passes the lines of dnsmasq through unchanged.
// On this screen, the operator looks at raw log text. Thus a shape for a
// parser must be unpacked before it gets here.
func readableDNS(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ev, ok := dnslog.ParseEvent(strings.TrimSpace(ln))
		if !ok {
			out = append(out, Printable(ln))
			continue
		}
		if ev.Act == dnslog.ActSuppressed {
			what := "queries"
			if ev.Listed {
				what = "config queries"
			}
			out = append(out, Printable(fmt.Sprintf("%s %s suppressed %d %s", ev.T, ev.Src, ev.N, what)))
			continue
		}
		row := fmt.Sprintf("%s %s %s %s %s", ev.T, ev.Src, ev.QType, ev.Name, ev.Act)
		if ev.Answer != "" {
			row += " " + ev.Answer
		}
		out = append(out, Printable(row))
	}
	return out
}

func (c *Config) firstSeen(n int) []string {
	st := loadObserve(c.ObservePath)
	type row struct{ at, text string }
	var rows []row
	for name, r := range st.DNS {
		if r != nil {
			rows = append(rows, row{r.FirstSeen, fmt.Sprintf("%s dns %-40s src=%s n=%d", r.FirstSeen, name, r.Src, r.Count)})
		}
	}
	for key, r := range st.Flows {
		if r != nil {
			rows = append(rows, row{r.FirstSeen, fmt.Sprintf("%s flow %-40s bytes=%d", r.FirstSeen, key, r.Bytes)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].at < rows[j].at })
	if len(rows) > n {
		rows = rows[len(rows)-n:]
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = Printable(r.text)
	}
	return out
}

// SegmentFirstSeen is the newest n of the new destinations of one plain
// segment. This is what the "first-seen" log is for the agent. The request
// uses the segment name, so the tab list and the LogKind numbering do not
// change.
func (c *Config) SegmentFirstSeen(segment string, n int) []string {
	rows := observe.DestRows(loadObserve(c.ObservePath), segment)
	if n > 0 && len(rows) > n {
		rows = rows[len(rows)-n:]
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = Printable(r.Line())
	}
	return out
}

// Apply runs pf apply (which takes the apply lock) and streams its output.
func (c *Config) Apply(ctx context.Context, local bool, w io.Writer) error {
	argv := append(slices.Clone(c.PfCmd), "apply")
	if local {
		argv = append(argv, "--local")
	}
	return c.stream(ctx, w, argv...)
}

// Fetch writes generated/ like apply does, so it holds the same lock. It
// runs pf feeds run, which starts the download unit (pf fetch as
// pf-feeds) and imports its checked lists. The child inherits the lock
// descriptor and uses it.
func (c *Config) Fetch(ctx context.Context, w io.Writer) error {
	lock, err := TryLock(c.LockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	return c.stream(ctx, w, append(slices.Clone(c.PfCmd), "feeds", "run", "--fresh", "0")...)
}

func (c *Config) systemctl(verb string, args ...string) error {
	ctx, cancel := timeout(30 * time.Second)
	defer cancel()
	out, err := c.exec(ctx, append([]string{"systemctl", verb}, args...)...)
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func (c *Config) RestartHouseDNS() error { return c.systemctl("restart", HouseDNSUnit) }
func (c *Config) ReloadHouseDNS() error  { return c.systemctl("reload", HouseDNSUnit) }
func (c *Config) Reboot() error          { return c.systemctl("reboot") }
func (c *Config) Shutdown() error        { return c.systemctl("poweroff") }
