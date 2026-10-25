package fence

import (
	"errors"
	"io"
	"sort"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
)

// ErrPlaceholderInStream is the error that a streamed request body returns
// at its first placeholder. The stream already forwarded all bytes before
// the placeholder. It never forwards a byte after it. The caller holds the
// origin connection and ends it: see CausePlaceholderInStream.
var ErrPlaceholderInStream = errors.New("fence: placeholder in a streamed body")

// StreamPlaceholderError is ErrPlaceholderInStream with the name of the
// placeholder that ended the copy. Thus the refusal row carries its slot and
// kind. For a kind run that did not settle within maxHold, the kind is the
// part of the run that arrived.
type StreamPlaceholderError struct{ Slot, Kind string }

func (e *StreamPlaceholderError) Error() string { return ErrPlaceholderInStream.Error() }

func (e *StreamPlaceholderError) Is(target error) bool { return target == ErrPlaceholderInStream }

// placeholderGuard is above the scrubber on a streamed body. The decision
// on the request did not read the body. Thus the fence did not refuse a
// placeholder in it at the start, and the head already went to the origin.
// The fence never substitutes into a streamed body (docs/fence.md 5.2), so
// each placeholder here is one that the buffered path would refuse. The
// guard emits bytes only up to the point where a placeholder could still
// start. The read that completes a placeholder fails with
// ErrPlaceholderInStream, and does not emit it.
type placeholderGuard struct {
	httpwire.ScanPump
	err error
}

func newPlaceholderGuard(src io.Reader) *placeholderGuard {
	g := &placeholderGuard{}
	g.Src, g.Scan = src, g.scan
	return g
}

func (g *placeholderGuard) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	n, err := g.ScanPump.Read(p)
	if g.err != nil {
		return 0, g.err
	}
	return n, err
}

func (g *placeholderGuard) scan() {
	n := len(g.Buf)
	if n == 0 {
		return
	}
	hold := 0
	if !g.EOF {
		hold = secrets.PlaceholderHold(g.Buf)
	}
	// A hold that grows past maxHold is a kind run that no real placeholder
	// has. The guard treats it as a placeholder, and does not let the agent
	// set the size of the broker buffer. Each span inside the settled prefix
	// is a whole placeholder. A span that ends at the edge of the buffer is
	// still in the hold, because the next byte can make the kind run
	// longer. The guard finds spans over the full buffer, never over the
	// settled prefix only: a kind run cut at n would look complete without
	// the byte after it.
	n -= hold
	// Also, the cut must not fall immediately after a placeholder-shaped
	// run. If the stream stops at the cut, the far end has read a whole
	// placeholder (FuzzPlaceholderGuard). The guard holds such a run with
	// the rest, and never drops it.
	if n < len(g.Buf) {
		n = secrets.TrailingPlaceholders(g.Buf[:n])
	}
	// maxHold is the limit on the actual hold. Without it, a long kind run
	// would grow the buffer without end.
	hold = len(g.Buf) - n
	// A whole placeholder in the settled prefix stops the copy. A hold past
	// maxHold also stops it. The guard does not emit the bytes of this pass.
	sp := secrets.FindPlaceholderSpans(g.Buf)
	if len(sp) > 0 && sp[0][1] <= n {
		hold = maxHold + 1
	}
	if hold > maxHold {
		// The first span is the placeholder that stops the copy. If it is a
		// run that did not settle, it ends at the edge of the buffer. Then
		// its slot and its kind are the part that arrived.
		var slot, kind string
		if len(sp) > 0 {
			slot, kind = secrets.PlaceholderParts(g.Buf, sp[0])
		}
		g.err = &StreamPlaceholderError{Slot: slot, Kind: kind}
		// EOF stops more reads by the pump. Read answers with err.
		g.Out, g.Buf, g.EOF = nil, nil, true
		return
	}
	g.Out = append(g.Out[:0], g.Buf[:n]...)
	tail := copy(g.Buf, g.Buf[n:])
	g.Buf = g.Buf[:tail]
}

// maxHold is the limit on how much body the token stream can hold while it
// waits for a match to complete. candidates() limits a match to window
// bytes. Thus with a complete prefilter, the horizon always advances well
// before this limit. maxHold exists for a rules file with a disabled
// prefilter. There, a match has no length limit, and without maxHold the
// agent would choose how much broker memory one upload costs.
const maxHold = 4 * window

// tokenStream runs the token-prefix rules over a streamed request body.
// The buffered path calls tokenSet.replace on the full body at one time.
// A stream must decide at each read boundary how much it can emit. It must
// not cut a token in half and leak the half that it did not scan yet.
//
// It is above the live-value scrubber. Thus the report for a stored secret
// uses its own slot name, as in the buffered path. Only values that the
// store never knew about reach these rules.
type tokenStream struct {
	httpwire.ScanPump
	ts *tokenSet
	// pad keeps each replacement at the length of the value that it
	// replaced. A body framed by Content-Length must not change size. A
	// chunked body can.
	pad bool
	// outBuf backs Out so a scan reuses one allocation.
	outBuf []byte
	// pre is the number of bytes at the head of buf that were already
	// emitted. The stream keeps them only to judge the lead of a rule
	// (leadExpr, up to leadMax bytes: a non-word byte, %0A, \u000a) against
	// the real bytes before the prefix. Without them, a retained buffer
	// starts mid-word, or past the start of an escape. Then the stream
	// would judge a token differently from the buffered path.
	pre  int
	hits map[string]int
}

func newTokenStream(src io.Reader, ts *tokenSet, pad bool) *tokenStream {
	t := &tokenStream{ts: ts, pad: pad, hits: map[string]int{}}
	t.Src, t.Scan = src, t.scan
	return t
}

// horizon is how far into buf the scan can commit. After that point, a
// token can still be in transit, so those bytes wait for the next read.
func (t *tokenStream) horizon() int {
	n := len(t.Buf)
	if !t.ts.complete {
		// No prefilter, so no limit on where a match starts. Hold a full
		// window, and let maxHold stop a body that never resolves.
		return max(n-window, 0)
	}
	// A prefix split across two reads must not be judged on its first
	// half alone.
	n -= t.ts.maxPrefix - 1
	// A prefix within a window of the tail may head a token whose last
	// bytes have not arrived.
	if i := t.ts.firstPrefixFrom(t.Buf, max(len(t.Buf)-window, 0)); i >= 0 && i < n {
		n = i
	}
	return max(n, 0)
}

func (t *tokenStream) scan() {
	if len(t.Buf) == 0 {
		return
	}
	ms := t.ts.matches(t.Buf)
	n := len(t.Buf)
	if !t.EOF {
		n = t.horizon()
		// If the horizon falls inside a match, the stream emits the full
		// match the next time and does not cut it. Nothing that starts
		// before n can end after n.
		for _, m := range ms {
			if lo, hi := t.ts.token(m); lo < n && hi > n {
				n = lo
			}
		}
		if len(t.Buf) > maxHold && n <= 0 {
			n = len(t.Buf) - window
		}
		if n <= 0 {
			return
		}
	}
	if n <= t.pre {
		return
	}
	out := t.outBuf[:0]
	pos := t.pre
	for _, m := range ms {
		lo, hi := t.ts.token(m)
		// A token that starts in the context bytes got its decision when
		// those bytes were emitted. Its lead can be there. The token cannot.
		if lo < t.pre {
			continue
		}
		if hi > n {
			break
		}
		repl := stripRepl
		if t.pad {
			repl = padRepl(hi - lo)
		}
		out = append(out, t.Buf[pos:lo]...)
		out = append(out, repl...)
		pos = hi
		t.hits[t.ts.ruleName(m)]++
	}
	t.outBuf = append(out, t.Buf[pos:n]...)
	t.Out = t.outBuf
	keep := max(n-leadMax, 0)
	tail := copy(t.Buf, t.Buf[keep:])
	t.Buf = t.Buf[:tail]
	t.pre = n - keep
}

// events is one StripEvent per rule that fired, with the names that the
// buffered path uses.
func (t *tokenStream) events() []StripEvent {
	if t == nil {
		return nil
	}
	names := make([]string, 0, len(t.hits))
	for rule := range t.hits {
		names = append(names, rule)
	}
	sort.Strings(names)
	ev := make([]StripEvent, 0, len(names))
	for _, rule := range names {
		ev = append(ev, StripEvent{Where: "body", Rule: rule})
	}
	return ev
}
