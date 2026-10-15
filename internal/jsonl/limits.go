package jsonl

import (
	"errors"
	"time"
)

// The agent causes the rows in the logs of the broker: one unknown row for
// each request to a host that is not on the allowlist, and strip rows for
// each token found. An agent in a loop writes as fast as it can send
// requests. logrotate (vm/pi/logrotate.timer, maxsize 50M) examines the
// files only when its timer starts. At 200 requests a second of 64 KiB rows,
// that is 13 MB/s, 46 GB an hour, and approximately 11 GB between two checks
// fifteen minutes apart. The SD card is full before that. The code below
// limits the three files in the writer. All rows go through the writer.

// DefaultMaxBytes is the ceiling for each file. Past it, the writer stops
// appending, counts what it drops, and tells this one time. It is the
// backstop when logrotate is late. It is not the working limit: logrotate
// rotates at 50 MiB. A file five times that size means that something went
// past the rate limits. Three files at the ceiling are 768 MiB. The card of
// the Pi can hold that beside all other data.
const DefaultMaxBytes = 256 << 20

// reserveBytes is how far past the ceiling the rows that must not be
// lost can go: the canary, and a refusal that the broker marked for the
// webhook. It is a sixteenth of the ceiling: 16 MiB of the default, tens
// of thousands of rows. It has a limit, so a loop of these rows stops.
func reserveBytes(ceiling int64) int64 {
	return max(ceiling/16, 64<<10)
}

// ErrFull is the error for a row that the ceiling dropped. The broker
// ignores log errors intentionally. ErrFull is for the tests.
var ErrFull = errors.New("jsonl: log at its size ceiling; row dropped")

// fileState is the memory of the ceiling for one path. The writer opens,
// appends and closes on each row. Thus it follows the two methods that
// logrotate can use to rotate. A rename plus create (as vm/pi/logrotate.conf
// does) gives it the new small file on the next open. copytruncate makes the
// old file smaller. Both show as a size under the ceiling. The writer checks
// only that. It does not need to track the inode.
type fileState struct {
	full    bool
	dropped int64
}

// diskRow is the one row that the ceiling writes when it starts to drop
// (log_full). It is also the one row that it writes when the file has space
// again (log_resumed, with the number of rows that it lost between). It has
// the fields that all readers of these files use as keys. pf alert reads it
// as a strip row and posts it ("STRIP log_full in disk -> strip.jsonl"). The
// use scan of the admin skips it because it has no slot.
type diskRow struct {
	T     string `json:"t"`
	Ev    string `json:"ev"`
	Host  string `json:"host"`
	Where string `json:"where"`
	Rule  string `json:"rule"`
	Src   string `json:"src,omitempty"`
	Count int64  `json:"count,omitempty"`
	Limit int64  `json:"limit,omitempty"`
	// ClientIP is only on the strip_suppressed row.
	ClientIP string `json:"client_ip,omitempty"`
}

const (
	// An unknown row is a sample to write policy: what the agent asks a host
	// for, and how. The first minute of a burst tells the operator that. A
	// loop that repeats it a thousand times tells nothing more. 120 rows at
	// one time is sufficient for the cold start of an agent against one host
	// (a package install, a crawl of one site). After that, one row a second
	// keeps a steady flow visible. A source across all its hosts gets five a
	// second and 600 at one time. Thus a loop over random hostnames, each with
	// a new bucket, still has a limit for each agent.
	unknownPairRate  = 1.0
	unknownPairBurst = 120
	unknownSrcRate   = 5.0
	unknownSrcBurst  = 600
	// unknownWindow is how often the code writes what it dropped, as one
	// row for each bucket. pf dns writes its suppressed rows the same way
	// (internal/dnsd/ratelimit.go).
	unknownWindow = time.Minute
	// unknownKeys limits each table. The agent segment is a /24. A table
	// this full is full of hosts that were made up to fill it. The code
	// counts all rows that arrive while it is full under "untracked".
	unknownKeys = 4096
	untracked   = "untracked"
	// suppressedWhere names the summary row in unknown.jsonl.
	suppressedWhere   = "suppressed"
	stripSrcRate      = StripRowRate
	stripSrcBurst     = StripRowBurst
	stripSuppressedEv = StripSuppressedEv
)

// The ordinary strip and refusal rows of a client: one for each token found
// in each request. Thus a loop over a planted key writes as fast as it asks.
// The budget is the same as for the unknown rows of a client. The canary
// and marked refusals are outside it. StripSuppressedEv is the summary row,
// one for each client in each sweep, with the number of dropped rows.
// Exported for pf alert, which uses this budget in the post, not a copy.
const (
	StripRowRate      = 5.0
	StripRowBurst     = 600
	StripSuppressedEv = "strip_suppressed"
)

type bucket struct {
	tokens  float64
	last    time.Time
	dropped int64
}

type limitKey struct{ src, host string }

// rowLimiter is a token bucket for each key. It holds no lock: the mutex
// of the Writer covers it.
type rowLimiter struct {
	rate     float64
	burst    float64
	m        map[limitKey]*bucket
	overflow int64
}

func newRowLimiter(rate float64, burst int) *rowLimiter {
	return &rowLimiter{rate: rate, burst: float64(burst), m: map[limitKey]*bucket{}}
}

func (l *rowLimiter) take(now time.Time, k limitKey) bool {
	b, ok := l.m[k]
	if !ok {
		if len(l.m) >= unknownKeys {
			l.overflow++
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[k] = b
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	b.dropped++
	return false
}

func (l *rowLimiter) refill(b *bucket, now time.Time) {
	// If the clock goes backwards, it refills nothing. It does not go negative.
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
}

// sweep reports what each key dropped after the last sweep. It forgets
// keys with a bucket that is full again. A new entry is exactly the
// same as that.
func (l *rowLimiter) sweep(now time.Time, emit func(k limitKey, n int64)) {
	for k, b := range l.m {
		l.refill(b, now)
		if b.dropped > 0 {
			emit(k, b.dropped)
			b.dropped = 0
		} else if b.tokens >= l.burst {
			delete(l.m, k)
		}
	}
	if l.overflow > 0 {
		emit(limitKey{src: untracked, host: "*"}, l.overflow)
		l.overflow = 0
	}
}

// clip limits one free-text field. clip cuts each string in these rows that
// the agent or an origin server can select, for all callers. Thus a row is
// a maximum of a few KiB, for all request shapes.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Field bounds. A hostname is a maximum of 253 bytes. The header-name bound
// is the same as the bound of the request parser (40 fields,
// internal/httpwire), at 64 bytes a name. No real header is near that.
const (
	maxHost      = 253
	maxShort     = 64
	maxRule      = 128
	maxPath      = 128
	maxUA        = 256
	maxRepo      = 256
	maxNames     = 40
	maxCookies   = 32
	maxNameBytes = 64
)

func clipNames(names []string, n int) []string {
	if len(names) > n {
		names = names[:n]
	}
	var out []string
	for i, s := range names {
		if len(s) > maxNameBytes {
			if out == nil {
				out = append([]string(nil), names...)
			}
			out[i] = s[:maxNameBytes]
		}
	}
	if out != nil {
		return out
	}
	return names
}

func (ev *Unknown) clip() {
	ev.Host = clip(ev.Host, maxHost)
	ev.SNI = clip(ev.SNI, maxHost)
	ev.DestIP = clip(ev.DestIP, maxShort)
	ev.Method = clip(ev.Method, 32)
	ev.Path = clip(ev.Path, maxPath)
	ev.HTTPVersion = clip(ev.HTTPVersion, 16)
	ev.HeaderNames = clipNames(ev.HeaderNames, maxNames)
	ev.UA = clip(ev.UA, maxUA)
	ev.ContentType = clip(ev.ContentType, maxRule)
	ev.AuthScheme = clip(ev.AuthScheme, 16)
	ev.CookieNames = clipNames(ev.CookieNames, maxCookies)
	ev.Where = clip(ev.Where, maxShort)
	ev.Src = clip(ev.Src, maxShort)
	ev.ClientIP = clip(ev.ClientIP, maxShort)
}

func (ev *Strip) clip() {
	ev.Host = clip(ev.Host, maxHost)
	ev.Where = clip(ev.Where, maxShort)
	// A rule can have text from the origin server: "encoded:" plus the
	// Content-Encoding that the origin server sent.
	ev.Rule = clip(ev.Rule, maxRule)
	ev.ClientIP = clip(ev.ClientIP, maxShort)
	ev.Threat = clip(ev.Threat, maxShort)
	ev.Slot = clip(ev.Slot, maxShort)
}

func (ev *Refused) clip() {
	ev.Host = clip(ev.Host, maxHost)
	ev.SNI = clip(ev.SNI, maxHost)
	ev.Where = clip(ev.Where, maxShort)
	ev.Cause = clip(ev.Cause, maxShort)
	ev.Slot = clip(ev.Slot, maxShort)
	ev.Kind = clip(ev.Kind, maxShort)
	ev.ClientIP = clip(ev.ClientIP, maxShort)
	ev.Repo = clip(ev.Repo, maxRepo)
	ev.Threat = clip(ev.Threat, maxShort)
}

func (ev *Use) clip() {
	ev.Slot = clip(ev.Slot, maxShort)
	ev.Host = clip(ev.Host, maxHost)
	ev.ClientIP = clip(ev.ClientIP, maxShort)
}
