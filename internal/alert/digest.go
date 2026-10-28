package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/keyshape"
	"pi-fortress/internal/secretscan"
	"pi-fortress/internal/tailer"
)

const (
	// DefaultDigestEvery is the length of a digest window: a maximum of one
	// digest post in this time.
	DefaultDigestEvery = 30 * time.Minute
	// MinDigestEvery is the shortest window that -digest accepts.
	MinDigestEvery = time.Minute
	// DefaultDigestState is in the StateDirectory of alert.service.
	DefaultDigestState = "/var/lib/pi-fortress/alert/digest.json"
	// digestTop is the number of destinations for each segment in a post.
	digestTop = 5
	// digestMaxHits bounds the destinations that one window keeps. A block
	// past it still counts in its class.
	digestMaxHits = 256
	// digestSeen is the number of row times that Seen keeps per segment.
	digestSeen = 16
	// digestMaxState bounds the read of the state file.
	digestMaxState = 1 << 20
	// digestNameMax is the longest name that a post shows (postName).
	digestNameMax = 64
	// digestHidden is what a post shows for a name that does not have the
	// shape of a host name.
	digestHidden = "(not shown)"
)

// Digest collects the Blocks rows of pf observe (jsonl.BlocksThreat) from
// the notice log. At the end of each window of Every, it gives one post,
// but only when the window has a block that counts (counts). The state
// file keeps the open window. Thus a restart does not lose it, and does
// not post a window two times. The Alerter calls each method under its mu.
type Digest struct {
	Every     time.Duration
	StatePath string
	Stderr    io.Writer
	st        digestState
	loaded    bool
}

type digestHit struct {
	Seg string `json:"seg"`
	jsonl.BlockHit
}

type digestState struct {
	// Start is the start of the open window.
	Start  time.Time                 `json:"start"`
	Counts map[string]map[string]int `json:"counts,omitempty"`
	Hits   []digestHit               `json:"hits,omitempty"`
	// Seen has the times of the last rows added for each segment. pf
	// observe writes one row for each segment at each flush, with a time in
	// nanoseconds. Thus a row with a time in Seen is a row that a restart
	// reads again, and it does not count two times. The code compares the
	// text, not the order: a clock that goes back after a reboot must not
	// make new rows look old.
	Seen map[string][]string `json:"seen,omitempty"`
}

func (d *Digest) errw() io.Writer {
	if d.Stderr != nil {
		return d.Stderr
	}
	return os.Stderr
}

func (d *Digest) every() time.Duration {
	if d.Every <= 0 {
		return DefaultDigestEvery
	}
	return d.Every
}

// load reads the state file one time. A missing or bad file starts a new
// window at now.
func (d *Digest) load(now time.Time) {
	if d.loaded {
		return
	}
	d.loaded = true
	if d.StatePath != "" {
		if f, err := os.Open(d.StatePath); err == nil {
			raw, rerr := io.ReadAll(io.LimitReader(f, digestMaxState))
			_ = f.Close()
			var st digestState
			if rerr == nil && json.Unmarshal(raw, &st) == nil {
				d.st = st
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(d.errw(), "digest: %v\n", err)
		}
	}
	// A start in the future is a clock that went back. The window then
	// starts again now, so that it does not stay open for that time.
	if d.st.Start.IsZero() || d.st.Start.After(now) {
		d.st.Start = now
	}
}

// save replaces the state file in one rename.
func (d *Digest) save() {
	if d.StatePath == "" {
		return
	}
	raw, err := json.Marshal(d.st)
	if err == nil {
		tmp := d.StatePath + ".tmp"
		if err = os.MkdirAll(filepath.Dir(d.StatePath), 0o755); err == nil {
			if err = os.WriteFile(tmp, append(raw, '\n'), 0o644); err == nil {
				err = os.Rename(tmp, d.StatePath)
			}
		}
	}
	if err != nil {
		fmt.Fprintf(d.errw(), "digest: state not saved: %v\n", err)
	}
}

// add puts one Blocks row into the open window.
func (d *Digest) add(row jsonl.Blocks, now time.Time) {
	d.load(now)
	if row.Where == "" || (row.T != "" && slices.Contains(d.st.Seen[row.Where], row.T)) {
		return
	}
	if d.st.Seen == nil {
		d.st.Seen = map[string][]string{}
	}
	if row.T != "" {
		seen := append(d.st.Seen[row.Where], row.T)
		if len(seen) > digestSeen {
			seen = seen[len(seen)-digestSeen:]
		}
		d.st.Seen[row.Where] = seen
	}
	if d.st.Counts == nil {
		d.st.Counts = map[string]map[string]int{}
	}
	for class, n := range row.Counts {
		if n <= 0 {
			continue
		}
		if d.st.Counts[row.Where] == nil {
			d.st.Counts[row.Where] = map[string]int{}
		}
		d.st.Counts[row.Where][class] += n
	}
	for _, h := range row.Top {
		if h.N <= 0 || h.Class == jsonl.BlockHouse {
			continue
		}
		found := false
		for i := range d.st.Hits {
			k := &d.st.Hits[i]
			if k.Seg == row.Where && k.Class == h.Class && k.Feed == h.Feed && k.Src == h.Src && k.Dst == h.Dst {
				k.N += h.N
				found = true
				break
			}
		}
		if !found && len(d.st.Hits) < digestMaxHits {
			d.st.Hits = append(d.st.Hits, digestHit{Seg: row.Where, BlockHit: h})
		}
	}
	d.save()
}

// due closes the window when its time is up. It returns the post for the
// window, or "" when the window had no block that counts. The state is
// saved before the post goes out. Thus a restart after this never posts
// the window again. It can lose this one post, and nothing more.
func (d *Digest) due(now time.Time) string {
	d.load(now)
	if now.Sub(d.st.Start) < d.every() {
		return ""
	}
	msg := ""
	if d.counts() {
		msg = d.render(now)
	}
	d.st = digestState{Start: now, Seen: d.st.Seen}
	d.save()
	return msg
}

// counts tells whether the window has a block that is worth a post: any
// block on the agent segment, and a block from a security feed or from
// the blacklist of the operator on any segment. A house list block (ads,
// trackers, VPN bypass) never causes a post.
func (d *Digest) counts() bool {
	for seg, by := range d.st.Counts {
		for class, n := range by {
			if n <= 0 {
				continue
			}
			if seg == "agent" || class == jsonl.BlockSecurity || class == jsonl.BlockOperator {
				return true
			}
		}
	}
	return false
}

// classNames are the class words of a post, in the order of the post.
var classNames = []struct{ class, name string }{
	{jsonl.BlockSecurity, "security feeds"},
	{jsonl.BlockOperator, "operator blacklist"},
	{jsonl.BlockOther, "not listed"},
	{jsonl.BlockHouse, "house ad and tracker lists"},
}

// render is the post, on one line: PostMessage changes a line break to
// "?", so that a name cannot forge a second line. The agent segment comes
// first, then the other segments in name order. A destination of the agent
// names the device. A destination of another segment does not, because
// those are personal devices.
func (d *Digest) render(now time.Time) string {
	segs := make([]string, 0, len(d.st.Counts))
	for s := range d.st.Counts {
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool {
		if (segs[i] == "agent") != (segs[j] == "agent") {
			return segs[i] == "agent"
		}
		return segs[i] < segs[j]
	})
	var b strings.Builder
	fmt.Fprintf(&b, "BLOCKED %s to %s UTC", d.st.Start.UTC().Format("2006-01-02 15:04"), now.UTC().Format("15:04"))
	for _, seg := range segs {
		var parts []string
		for _, c := range classNames {
			if n := d.st.Counts[seg][c.class]; n > 0 {
				parts = append(parts, c.name+" "+strconv.Itoa(n))
			}
		}
		if len(parts) == 0 {
			continue
		}
		b.WriteString(" | " + tailer.Printable(seg) + ": " + strings.Join(parts, ", "))
		var hits []digestHit
		for _, h := range d.st.Hits {
			if h.Seg != seg || (seg != "agent" && h.Class == jsonl.BlockOther) {
				continue
			}
			hits = append(hits, h)
		}
		sort.SliceStable(hits, func(i, j int) bool {
			if hits[i].N != hits[j].N {
				return hits[i].N > hits[j].N
			}
			return hits[i].Dst < hits[j].Dst
		})
		if len(hits) > digestTop {
			hits = hits[:digestTop]
		}
		for i, h := range hits {
			if i == 0 {
				b.WriteString("; top: ")
			} else {
				b.WriteString(", ")
			}
			if seg == "agent" {
				b.WriteString(postName(h.Src) + " -> ")
			}
			b.WriteString(postName(h.Dst))
			src := h.Feed
			if src == "" || src == "local" {
				src = h.Class
			}
			b.WriteString(" (" + postName(src) + ") x" + strconv.Itoa(h.N))
		}
	}
	return b.String()
}

// postName is a name as a post shows it. Only a name with the shape of a
// host name (hostShaped) is shown, after redactName. Any other name is
// digestHidden. Thus a name cannot put a scheme, a port, a path or markup
// in a post, and no sink can make a link from it. A name longer than
// digestNameMax keeps its right end, which has the zone, after "...". The
// fixed words of pf observe for blocks that the resolver did not log stay.
func postName(s string) string {
	switch s {
	case "(not logged)", "(untracked)":
		return s
	}
	if !hostShaped(s) {
		return digestHidden
	}
	if r := redactName(s); r != s {
		return r
	}
	if len(s) > digestNameMax {
		return "..." + s[len(s)-(digestNameMax-3):]
	}
	return s
}

// hostShaped tells whether s has only ASCII letters, digits, "-", "_" and
// ".". An IPv4 address has this shape too.
func hostShaped(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// redactName gives a name that can go in a post. An agent selects the
// names that it asks for, and a name under a listed zone is blocked too.
// Thus a name can carry a key or a placeholder of the gateway. Such a name
// becomes its zone (keyshape.Tail). If the zone also has the shape of a
// credential, nothing of the name stays.
func redactName(s string) string {
	if !credentialShaped(s) {
		return s
	}
	if t := keyshape.Tail(s); t != s && !credentialShaped(t) {
		return "(redacted)." + t
	}
	return "(redacted)"
}

// credentialShaped tells whether s has a placeholder of the gateway, a
// credential that secretscan knows, or a label of 32 characters or more.
// A long label is the shape of a key or of a payload in a DNS tunnel. A
// real host name rarely has one.
func credentialShaped(s string) bool {
	if keyshape.Rule(nil, s) != "" || len(secretscan.Scan([]byte(s))) > 0 {
		return true
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) >= 32 {
			return true
		}
	}
	return false
}

// blocksLine is the console line of a Blocks row.
func blocksLine(event map[string]any) string {
	counts, _ := event["counts"].(map[string]any)
	var parts []string
	for _, c := range classNames {
		if n, ok := counts[c.class].(float64); ok && n > 0 {
			parts = append(parts, c.name+" "+strconv.FormatInt(int64(n), 10))
		}
	}
	if len(parts) == 0 {
		parts = []string{"none"}
	}
	return "BLOCKS " + field(event, "where", "?") + ": " + strings.Join(parts, ", ")
}

// digestRow parses a notice line into a Blocks row.
func digestRow(raw string) (jsonl.Blocks, bool) {
	var row jsonl.Blocks
	if json.Unmarshal([]byte(raw), &row) != nil || row.Threat != jsonl.BlocksThreat {
		return jsonl.Blocks{}, false
	}
	return row, true
}
