package eyeball

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is what the broker does with a dial to an eyeball network.
type Mode int

const (
	// Off: no check.
	Off Mode = iota
	// Audit: the broker dials, writes a strip row, and alerts.
	Audit
	// Refuse: the broker does not dial. It writes a strip row and alerts.
	Refuse
)

// ParseMode reads the value of the -eyeball flag and of EYEBALL in net.env.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "off":
		return Off, nil
	case "audit", "":
		return Audit, nil
	case "refuse":
		return Refuse, nil
	}
	return Off, fmt.Errorf("eyeball mode %q: it is off, audit or refuse", s)
}

func (m Mode) String() string {
	switch m {
	case Audit:
		return "audit"
	case Refuse:
		return "refuse"
	}
	return "off"
}

// DefaultMaxAge is the age at which the broker stops the use of a table.
// pf fetch refreshes the table each night. A table of 30 days means that
// the refresh has failed for a month. The ranges of the ISPs move, so the
// check stops, and the broker says so one time.
const DefaultMaxAge = 30 * 24 * time.Hour

// Allow is the list of names and ASNs that the check exempts.
type Allow struct {
	names map[string]struct{}
	asns  map[uint32]struct{}
}

// maxAllow limits the entries of the list. It is a file that the operator
// writes by hand.
const maxAllow = 10000

// ParseAllow reads the list: one entry for each line, "#" starts a comment.
// An entry is an ASN ("AS64496") or a name. A name also exempts each name
// below it. It gives back a line that it skipped as a warning, not as an
// error: one typo must not stop the use of the other entries.
func ParseAllow(r io.Reader) (*Allow, []string, error) {
	a := &Allow{names: map[string]struct{}{}, asns: map[uint32]struct{}{}}
	var warn []string
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		s, _, _ := strings.Cut(sc.Text(), "#")
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(a.names)+len(a.asns) >= maxAllow {
			return nil, warn, fmt.Errorf("eyeball allow: more than %d entries", maxAllow)
		}
		if n, ok := ParseASN(s); ok && (s[0] == 'A' || s[0] == 'a') {
			a.asns[n] = struct{}{}
			continue
		}
		if name, ok := allowName(s); ok {
			a.names[name] = struct{}{}
			continue
		}
		warn = append(warn, fmt.Sprintf("line %d: not an ASN (AS64496) or a name", line))
	}
	if err := sc.Err(); err != nil {
		return nil, warn, err
	}
	return a, warn, nil
}

func allowName(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return s, true
}

// Exempt reports whether the list exempts name or asn. A name matches an
// entry that is the name or a parent of the name.
func (a *Allow) Exempt(name string, asn uint32) bool {
	if a == nil {
		return false
	}
	if _, ok := a.asns[asn]; ok {
		return true
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for n != "" {
		if _, ok := a.names[n]; ok {
			return true
		}
		_, rest, ok := strings.Cut(n, ".")
		if !ok {
			break
		}
		n = rest
	}
	return false
}

// Checker is the check that the broker runs. It loads the table and the
// allow list from files, and loads them again when they change. pf fetch
// replaces the table each night, and the broker must not restart for it.
//
// The check fails open. With no table, a stale table, or a file that does
// not parse, Match reports no match, and the broker dials as before. The
// check is a detector on top of the fence. It is not the gate. Each change
// of that state is one log line, not one line for each dial.
type Checker struct {
	Mode      Mode
	TablePath string
	AllowPath string
	// MaxAge is the age at which a table is stale. 0 means DefaultMaxAge.
	MaxAge time.Duration
	// Now is the clock for the age. nil means time.Now.
	Now func() time.Time
	// Logf writes the state lines. nil means log.Printf.
	Logf func(format string, args ...any)

	cur atomic.Pointer[loaded]

	mu        sync.Mutex
	said      string
	tableID   fileID
	allowID   fileID
	table     *Table
	allow     *Allow
	tableErr  string
	allowNote string
}

type loaded struct {
	table *Table
	allow *Allow
}

type fileID struct {
	ok    bool
	size  int64
	mtime time.Time
}

// Static is a checker with a table and a list that are already in memory.
// It is for tests and for callers that have no files.
func Static(m Mode, t *Table, a *Allow) *Checker {
	c := &Checker{Mode: m}
	c.cur.Store(&loaded{table: t, allow: a})
	return c
}

// Match reports the ASN of a, and true, if a is in an eyeball network that
// the allow list does not exempt for name. It is false when the check is
// off or has no usable table.
func (c *Checker) Match(name string, a netip.Addr) (uint32, bool) {
	if c == nil || c.Mode == Off {
		return 0, false
	}
	l := c.cur.Load()
	if l == nil {
		return 0, false
	}
	asn, ok := l.table.Lookup(a)
	if !ok || l.allow.Exempt(name, asn) {
		return 0, false
	}
	return asn, true
}

// Ready reports whether the check has a table that it uses.
func (c *Checker) Ready() bool {
	if c == nil || c.Mode == Off {
		return false
	}
	l := c.cur.Load()
	return l != nil && l.table != nil
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func stat(path string) fileID {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return fileID{}
	}
	return fileID{ok: true, size: st.Size(), mtime: st.ModTime()}
}

// maxTableBytes limits the read of a table file. A real table is about
// 5 MB.
const maxTableBytes = 128 << 20

func readTable(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(io.LimitReader(f, maxTableBytes))
}

func readAllow(path string) (*Allow, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return ParseAllow(io.LimitReader(f, 4<<20))
}

// Reload reads a file that changed since the last call, and checks the
// age of the table. It never stops the check of a table that loaded for a
// file that went bad later: until the next good file, the broker keeps
// the last good table. Only age stops that table.
func (c *Checker) Reload() {
	if c == nil || c.Mode == Off {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id := stat(c.TablePath); id != c.tableID {
		c.tableID = id
		switch {
		case !id.ok:
			c.table, c.tableErr = nil, "no table at "+c.TablePath
		default:
			t, err := readTable(c.TablePath)
			if err != nil {
				c.tableErr = err.Error()
			} else {
				c.table, c.tableErr = t, ""
			}
		}
	}
	if id := stat(c.AllowPath); id != c.allowID {
		c.allowID = id
		c.allow, c.allowNote = nil, ""
		if id.ok {
			a, warn, err := readAllow(c.AllowPath)
			switch {
			case err != nil:
				c.allowNote = "allow list " + c.AllowPath + ": " + err.Error() + "; no exemptions"
			case len(warn) > 0:
				c.allow = a
				c.allowNote = fmt.Sprintf("allow list %s: skipped %d line(s), first %s", c.AllowPath, len(warn), warn[0])
			default:
				c.allow = a
			}
			if c.allowNote != "" {
				c.logf("pf broker: eyeball %s", c.allowNote)
			}
		}
	}
	use, state := c.table, ""
	maxAge := c.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	switch {
	case c.table == nil && c.tableErr != "":
		state = "check off (fail open): " + c.tableErr
	case c.table == nil:
		state = "check off (fail open): no table"
	case c.now().Sub(c.table.Built) > maxAge:
		use = nil
		state = fmt.Sprintf("check off (fail open): table built %s is older than %s", c.table.Built.Format(time.RFC3339), maxAge)
	case c.tableErr != "":
		state = fmt.Sprintf("%s with the last good table (%d ranges); the new file did not load: %s", c.Mode, c.table.Len(), c.tableErr)
	default:
		state = fmt.Sprintf("%s, %d ranges, built %s", c.Mode, c.table.Len(), c.table.Built.Format(time.RFC3339))
	}
	c.cur.Store(&loaded{table: use, allow: c.allow})
	if state != c.said {
		c.said = state
		c.logf("pf broker: eyeball %s", state)
	}
}

// Watch calls Reload each period until ctx ends.
func (c *Checker) Watch(ctx context.Context, every time.Duration) {
	if c == nil || c.Mode == Off {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Reload()
		}
	}
}
