// Package jsonl appends the strip, use and unknown events of the fence to
// their JSONL logs. The broker writes through it. internal/admin reads the
// same files.
package jsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pi-fortress/internal/base"
)

const Src = "split"

type Writer struct {
	StripPath   string
	UnknownPath string
	UsePath     string
	mu          sync.Mutex
	Now         func() time.Time
	// MaxBytes is the ceiling for each file (limits.go). 0 is DefaultMaxBytes.
	MaxBytes int64

	files     map[string]*fileState
	pairLim   *rowLimiter
	srcLim    *rowLimiter
	lastSweep time.Time
	// stripLim limits the ordinary strip and refusal rows of each client.
	// stripSweep is the time when it last wrote what it dropped.
	stripLim   *rowLimiter
	stripSweep time.Time
}

type Strip struct {
	T     string `json:"t"`
	Host  string `json:"host"`
	Where string `json:"where"`
	Rule  string `json:"rule"`
	// ClientIP is the agent-side address from the preamble. It is last,
	// so rows without it keep their bytes.
	ClientIP string `json:"client_ip,omitempty"`
	// Threat is "canary" on a row about the challenge credential
	// (docs/challenge_rules.md). It is "slot_budget" when a slot goes
	// past its hourly ceiling (internal/broker/budget.go). On all other
	// rows it is absent.
	Threat string `json:"threat,omitempty"`
	// Slot, Count and Limit are only on the slot_budget rows. They are
	// the slot whose hour went past a threshold, the value that hour
	// reached, and the threshold. The two numbers are in the unit that
	// Where names: requests or bytes.
	Slot  string `json:"slot,omitempty"`
	Count int64  `json:"count,omitempty"`
	Limit int64  `json:"limit,omitempty"`
}

type Unknown struct {
	T           string   `json:"t"`
	Host        string   `json:"host"`
	SNI         string   `json:"sni"`
	DestIP      string   `json:"dest_ip"`
	DestPort    int      `json:"dest_port"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	HTTPVersion string   `json:"http_version"`
	HeaderNames []string `json:"header_names"`
	UA          string   `json:"ua"`
	ContentType string   `json:"content_type"`
	BodyLen     int      `json:"body_len"`
	AuthScheme  string   `json:"auth_scheme"`
	CookieNames []string `json:"cookie_names"`
	Stripped    bool     `json:"stripped"`
	Where       string   `json:"where"`
	Src         string   `json:"src"`
	// Byte counts of a closed WebSocket relay. Only on the ws_close row.
	WSSent   int64  `json:"ws_sent,omitempty"`
	WSRecv   int64  `json:"ws_recv,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	// Suppressed is only on the where=suppressed row. It is the number of
	// rows for this client and host (host "*": this client across its
	// hosts) that the rate limit dropped in the last window.
	Suppressed int64 `json:"suppressed,omitempty"`
}

func (w *Writer) now() time.Time {
	if w != nil && w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w *Writer) stamp() string {
	return w.now().Format(base.ISO)
}

func (w *Writer) Strip(ev Strip) error {
	if w == nil || w.StripPath == "" {
		return nil
	}
	ev.T = w.stamp()
	ev.clip()
	// A threat row other than the canary (slot_budget) comes from the
	// broker. The broker debounces it where it raises it. Only plain
	// strips are rows that the agent can repeat.
	return w.appendStrip(ev, ev.Threat == "canary", ev.Threat != "", ev.ClientIP)
}

// Refused is one substitution that the fence did not make. The code writes
// it to the strip log, because that is the channel of the operator when the
// fence blocks something. Also, the alerter already tails that log. The
// agent gets none of this information: it gets one response for all causes.
type Refused struct {
	T     string `json:"t"`
	Ev    string `json:"ev"`
	Host  string `json:"host"`
	SNI   string `json:"sni"`
	Where string `json:"where"`
	// Rule has the cause in the field that the alert summary reads. Thus
	// a refusal gets to a webhook through the existing path.
	Rule     string `json:"rule"`
	Cause    string `json:"cause"`
	Slot     string `json:"slot"`
	Kind     string `json:"kind"`
	Alert    bool   `json:"alert,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	// Repo is the repo that a refused git push named. It is empty for
	// all other causes.
	Repo   string `json:"repo,omitempty"`
	Threat string `json:"threat,omitempty"`
	// DestIP is the address that the broker dialed, or refused to dial.
	// Only the eyeball_network row has it.
	DestIP string `json:"dest_ip,omitempty"`
}

func (w *Writer) Refused(ev Refused) error {
	if w == nil || w.StripPath == "" {
		return nil
	}
	ev.T = w.stamp()
	ev.clip()
	ev.Ev = "substitution_refused"
	ev.Rule = "refused:" + ev.Cause
	return w.appendStrip(ev, ev.Alert || ev.Threat == "canary", false, ev.ClientIP)
}

// appendStrip writes one strip.jsonl row. A priority row (the canary, a
// refusal that the broker marked for the webhook) passes the budget of the
// client and can use the reserve past the ceiling. An exempt row passes
// only the budget. The budget of each client limits all other rows, as it
// limits unknown rows.
func (w *Writer) appendStrip(v any, priority, exempt bool, client string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	w.sweepStrip(now)
	if !priority && !exempt && !w.stripLim.take(now, limitKey{client, "*"}) {
		return nil
	}
	return w.appendLocked(w.StripPath, b, priority)
}

// sweepStrip writes one row each window for each client with dropped strip
// rows. The row has the shape of a strip row. Thus pf alert and observe read
// it as a message from the fence.
func (w *Writer) sweepStrip(now time.Time) {
	if w.stripLim == nil {
		w.stripLim = newRowLimiter(stripSrcRate, stripSrcBurst)
		w.stripSweep = now
		return
	}
	if now.Sub(w.stripSweep) < unknownWindow {
		return
	}
	w.stripSweep = now
	w.stripLim.sweep(now, func(k limitKey, n int64) {
		row, err := json.Marshal(diskRow{
			T: now.Format(base.ISO), Ev: stripSuppressedEv, Host: "*", Where: suppressedWhere,
			Rule: suppressedWhere, Src: Src, Count: n, ClientIP: k.src,
		})
		if err == nil {
			_ = w.appendLocked(w.StripPath, row, false)
		}
	})
}

type Use struct {
	T        string `json:"t"`
	Slot     string `json:"slot"`
	Host     string `json:"host"`
	ClientIP string `json:"client_ip,omitempty"`
}

// Use records a substitution toward host for slot. The broker rate-limits
// the calls, so the log stays small.
func (w *Writer) Use(ev Use) error {
	if w == nil || w.UsePath == "" {
		return nil
	}
	ev.T = w.stamp()
	ev.clip()
	return w.append(w.UsePath, ev)
}

func (w *Writer) Unknown(ev Unknown) error {
	if w == nil || w.UnknownPath == "" {
		return nil
	}
	if ev.T == "" {
		ev.T = w.stamp()
	}
	if ev.Src == "" {
		ev.Src = Src
	}
	if ev.Where == "" {
		ev.Where = "http"
	}
	ev.clip()
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	w.sweepUnknown(now)
	// The bucket of the pair is first. A row that it refuses uses nothing
	// from the bucket of the source. Thus one noisy host does not use up
	// the other hosts of a client.
	if !w.pairLim.take(now, limitKey{ev.ClientIP, ev.Host}) {
		return nil
	}
	if !w.srcLim.take(now, limitKey{ev.ClientIP, "*"}) {
		return nil
	}
	return w.appendLocked(w.UnknownPath, b, false)
}

// sweepUnknown writes one row each window for each bucket that dropped
// rows. The code writes summaries only when a row arrives, as pf dns does.
// The next row of a quiet source gives its summary.
func (w *Writer) sweepUnknown(now time.Time) {
	if w.pairLim == nil {
		w.pairLim = newRowLimiter(unknownPairRate, unknownPairBurst)
		w.srcLim = newRowLimiter(unknownSrcRate, unknownSrcBurst)
		w.lastSweep = now
		return
	}
	if now.Sub(w.lastSweep) < unknownWindow {
		return
	}
	w.lastSweep = now
	emit := func(k limitKey, n int64) {
		row, err := json.Marshal(Unknown{
			T:          now.Format(base.ISO),
			ClientIP:   k.src,
			Host:       k.host,
			Where:      suppressedWhere,
			Src:        Src,
			Suppressed: n,
		})
		if err == nil {
			_ = w.appendLocked(w.UnknownPath, row, false)
		}
	}
	w.pairLim.sweep(now, emit)
	w.srcLim.sweep(now, emit)
}

func (w *Writer) append(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(path, b, false)
}

func (w *Writer) maxBytes() int64 {
	if w.MaxBytes > 0 {
		return w.MaxBytes
	}
	return DefaultMaxBytes
}

// appendLocked writes one line under the size ceiling. It reads the size
// from the descriptor that it will write. Thus it sees the current state of
// a file that logrotate renamed or truncated after the last row. It writes
// these rows past the ceiling:
//   - The one row that tells that the file is full.
//   - The one row that tells that the file has space again.
//   - A priority row, up to reserveBytes past the ceiling.
//
// It counts and drops all other rows past the ceiling.
func (w *Writer) appendLocked(path string, line []byte, priority bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if w.files == nil {
		w.files = map[string]*fileState{}
	}
	fs := w.files[path]
	if fs == nil {
		fs = &fileState{}
		w.files[path] = fs
	}
	max := w.maxBytes()
	if size := st.Size() + int64(len(line)) + 1; size > max {
		if priority && size <= max+reserveBytes(max) {
			if !fs.full {
				fs.full = true
				_ = w.writeDisk(f, path, "log_full", 0, max)
			}
			_, err = f.Write(append(line, '\n'))
			return err
		}
		fs.dropped++
		if !fs.full {
			fs.full = true
			_ = w.writeDisk(f, path, "log_full", 0, max)
		}
		return ErrFull
	}
	if fs.full {
		if err := w.writeDisk(f, path, "log_resumed", fs.dropped, max); err != nil {
			return err
		}
		fs.full, fs.dropped = false, 0
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

func (w *Writer) writeDisk(f *os.File, path, ev string, n, max int64) error {
	b, err := json.Marshal(diskRow{
		T:     w.stamp(),
		Ev:    ev,
		Host:  filepath.Base(path),
		Where: "disk",
		Rule:  ev,
		Src:   Src,
		Count: n,
		Limit: max,
	})
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}
