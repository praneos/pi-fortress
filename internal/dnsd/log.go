package dnsd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pi-fortress/internal/dnslog"
)

// segLog is the query log of one segment. It appends one line at a time.
// dnsmasq holds the file open in the same way and reopens it on SIGHUP.
// This lets a rotation take effect without a restart.
type segLog struct {
	path string
	mu   sync.Mutex
	f    *os.File
	// lim is nil when every query is logged.
	lim *limiter
}

func openSegLog(path string) (*segLog, error) {
	l := &segLog{path: path}
	if err := l.reopen(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *segLog) reopen() error {
	f, err := l.open()
	if err != nil {
		return err
	}
	l.swap(f)
	return nil
}

// open and swap are the two halves of reopen. They are separate so that
// Reload can open the file of each segment before it moves any of them.
func (l *segLog) open() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
}

func (l *segLog) swap(f *os.File) {
	l.mu.Lock()
	old := l.f
	l.f = f
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// line appends one log line. It drops a write that fails. The reader
// tails by byte offset. A resolver that stops its answers because its log
// is full is a worse failure than a gap in the record.
func (l *segLog) line(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	_, _ = l.f.WriteString(s + "\n")
}

func (l *segLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// OpenLogs opens the query log of each segment. Run calls it. New does
// not, because -check validates a config and must not create files.
//
// If the log of an isolatable segment does not open, the segment runs
// without it, and Segments marks it. This does not stop the resolver of
// every network at start. Reload tries the log again. The agent and the
// stubs stay strict.
func (s *Server) OpenLogs() error {
	for _, seg := range s.segs {
		if seg.LogPath == "" || seg.log.Load() != nil {
			continue
		}
		lg, err := s.openLog(seg)
		if err != nil {
			if !s.isolates(seg) {
				return err
			}
			why := err.Error()
			seg.logErr.Store(&why)
			s.logf("pf dns: segment %q answers without its query log until it opens (fix, then pf apply or SIGHUP): %v", seg.Name, err)
			continue
		}
		seg.log.Store(lg)
	}
	return nil
}

// openLog opens a segment's log with its budget.
func (s *Server) openLog(seg *Segment) (*segLog, error) {
	lg, err := openSegLog(seg.LogPath)
	if err != nil {
		return nil, fmt.Errorf("segment %q log: %w", seg.Name, err)
	}
	if s.cfg.LogRate > 0 {
		lg.lim = newClassLimiter(s.cfg.LogRate, s.cfg.LogBurst, logSources, func(now time.Time, src string, n int, c logClass) {
			seg.event(now, dnslog.Event{Src: src, Act: dnslog.ActSuppressed, N: n, Listed: c == logListed, Candidate: c == logCandidate})
		})
	}
	return lg, nil
}

// CloseLogs writes the counts still pending before it closes, so a
// shutdown does not lose them.
func (s *Server) CloseLogs() {
	for _, seg := range s.segs {
		lg := seg.log.Load()
		if lg == nil {
			continue
		}
		// The flush writes its summaries through seg.write. seg.write reads
		// the same pointer that this code removes. Thus the log stays
		// published until the last line for it is written.
		if lg.lim != nil {
			lg.lim.flush(s.cfg.Now())
		}
		seg.log.Store(nil)
		_ = lg.Close()
	}
}

// sweepLogs writes pending counts on a timer. Thus it reports a source
// that floods and then goes silent, and it does not wait for the next
// query.
func (s *Server) sweepLogs(ctx context.Context) {
	t := time.NewTicker(logSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, seg := range s.segs {
				if lg := seg.log.Load(); lg != nil && lg.lim != nil {
					lg.lim.flush(s.cfg.Now())
				}
			}
		}
	}
}
