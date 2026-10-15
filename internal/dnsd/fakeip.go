package dnsd

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"pi-fortress/internal/dnslog"
	"pi-fortress/internal/fakeip"
)

// fakeTTL is the TTL on a fake-IP answer. It is short on purpose, and
// much shorter than the life of the mapping. The journal keeps the
// address of a name while the pool is not full. So an agent that asks
// again each minute gets the same address back and loses nothing. The
// short TTL gives a way back. An operator can change the segment to
// forward mode (or move FAKEIP_NET). Then agents keep pool addresses
// that the new gate refuses, for exactly this long. An hour here would
// be an hour of broken connections after each mode change. Nothing on
// the Pi can withdraw the answers.
const fakeTTL = 60

// fakeErrEvery bounds how often a pool that fails writes to the journal.
// While the disk is full or the directory is not writable, every A query
// on the segment fails the same way. One line for each query would bury
// the journal under the one fact that it already gave.
const fakeErrEvery = time.Minute

// fakeState is the fake-IP pool of a segment (internal/fakeip). pf dns
// gives each A query on the segment an address from the pool, and does
// not forward the query. The broker maps the address back from the
// journal.
//
// The pool opens on first use, not in New. New is what -check runs.
// -check must certify the configuration, and it must create or write
// nothing. apply runs it as root before the resolver restarts. So a
// journal that it created would belong to root, and pf dns could not
// append to it. New only proves that the pool could open (checkFake).
// Run opens it before the first query. So a pool that cannot open still
// stops the unit where systemd reports it.
type fakeState struct {
	prefix  netip.Prefix
	journal string

	mu     sync.Mutex
	pool   *fakeip.Pool
	closed bool
	// lastErr is when a pool failure was last written to the journal.
	lastErr time.Time
}

// checkFake is the part of New that checks the prefix and the journal
// of the pool for all that the open will need. It touches nothing.
//
// fakeip_net and fakeip_journal come as a pair, and only on an
// address-only segment. Fake-IP answers A and nothing else. On a segment
// that forwarded every other type, a TXT or a CNAME would still carry
// the name upstream. Then the channel that fake-IP is there to close
// would stay open under a setting that says it is closed.
func (seg *Segment) checkFake() (*fakeState, error) {
	if !seg.FakeIPNet.IsValid() && seg.FakeIPJournal == "" {
		return nil, nil
	}
	if !seg.FakeIPNet.IsValid() || seg.FakeIPJournal == "" {
		return nil, fmt.Errorf("segment %q: fakeip_net and fakeip_journal go together", seg.Name)
	}
	if !seg.AddressOnly {
		return nil, fmt.Errorf("segment %q: fakeip_net without address_only", seg.Name)
	}
	if err := fakeip.CheckPrefix(seg.FakeIPNet); err != nil {
		return nil, fmt.Errorf("segment %q: fakeip_net %s: %w", seg.Name, seg.FakeIPNet, err)
	}
	if !filepath.IsAbs(seg.FakeIPJournal) {
		return nil, fmt.Errorf("segment %q: fakeip_journal %q is not an absolute path", seg.Name, seg.FakeIPJournal)
	}
	// access(2), not a trial create. The question is whether the open in
	// Run will succeed. A file create to answer it is the side effect that
	// -check must not have. access(2) answers for the real uid. That is the
	// uid of the daemon when the unit runs it, and root under the -check of
	// apply. apply creates the directory before that check. So the answer
	// to root matches what pf-dns will find, except the owner. apply sets
	// the owner in the same step.
	dir := filepath.Dir(seg.FakeIPJournal)
	if st, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("segment %q: fakeip_journal directory: %w", seg.Name, err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("segment %q: fakeip_journal directory %s is not a directory", seg.Name, dir)
	}
	if err := syscall.Access(dir, 0x2|0x1); err != nil {
		return nil, fmt.Errorf("segment %q: fakeip_journal directory %s is not writable: %w", seg.Name, dir, err)
	}
	if st, err := os.Lstat(seg.FakeIPJournal); err == nil {
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("segment %q: fakeip_journal %s is not a regular file", seg.Name, seg.FakeIPJournal)
		}
		if err := syscall.Access(seg.FakeIPJournal, 0x4|0x2); err != nil {
			return nil, fmt.Errorf("segment %q: fakeip_journal %s is not readable and writable: %w", seg.Name, seg.FakeIPJournal, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("segment %q: fakeip_journal: %w", seg.Name, err)
	}
	return &fakeState{prefix: seg.FakeIPNet, journal: seg.FakeIPJournal}, nil
}

// get is the open pool. It opens the pool on first use. Closed stays
// closed: a query that lived longer than the shutdown must not reopen a
// journal that nothing will close again.
func (f *fakeState) get() (*fakeip.Pool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, fakeip.ErrClosed
	}
	if f.pool == nil {
		p, err := fakeip.OpenPool(f.prefix, f.journal)
		if err != nil {
			return nil, err
		}
		f.pool = p
	}
	return f.pool, nil
}

func (f *fakeState) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if f.pool == nil {
		return nil
	}
	err := f.pool.Close()
	f.pool = nil
	return err
}

// logErr reports whether a pool failure at now should reach the journal.
func (f *fakeState) logErr(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.lastErr.IsZero() && now.Sub(f.lastErr) < fakeErrEvery {
		return false
	}
	f.lastErr = now
	return true
}

// openFake opens every fake-IP pool before the first query. So a journal
// that will not open fails the unit at start, and not every agent lookup
// after that.
func (s *Server) openFake() error {
	for _, seg := range s.segs {
		if seg.fake == nil {
			continue
		}
		if _, err := seg.fake.get(); err != nil {
			return fmt.Errorf("segment %q fakeip journal: %w", seg.Name, err)
		}
	}
	return nil
}

// closeFake closes the pools. Run calls it after the last query has
// returned. The journal is already on disk line by line, so this only
// releases the handle.
func (s *Server) closeFake() {
	for _, seg := range s.segs {
		if seg.fake == nil {
			continue
		}
		if err := seg.fake.close(); err != nil {
			s.logf("dns segment %q: fakeip journal close: %v", seg.Name, err)
		}
	}
}

// fakeAnswer is the fake-IP answer to an A query that passed every check
// before the cache: one A record from the pool, under the queried name,
// at fakeTTL.
//
// Nothing goes upstream, and nothing goes into the cache. The purpose is
// that the name leaves the Pi only when the broker dials it. Nothing goes
// into the nft set either. Under fakeip, the agent gate admits the full
// pool, and resolved_v4 is for real addresses.
func (s *Server) fakeAnswer(seg *Segment, hdr dnsmessage.Header, q dnsmessage.Question, name string, e ednsOPT, src netip.Addr, quiet bool, maxUDP int) []byte {
	// An address asked as a name maps back to that address: the broker
	// would dial the literal, and the direct-IP rule would never see it.
	if addressName(name) {
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeNameError, e), src, verdict{act: dnslog.ActNXDomain}, quiet, maxUDP)
	}
	now := s.cfg.Now()
	a, err := s.assignFake(seg, name, now)
	if err != nil && !a.IsValid() {
		// A name that the journal cannot carry (a space, a byte past ASCII) is
		// also not a name that a TLS client can send as SNI. So the broker can
		// never map it to an address. For this segment, the name does not
		// exist. All other errors are pool failures, and the client should
		// retry.
		if errors.Is(err, fakeip.ErrName) {
			return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeNameError, e), src, verdict{act: dnslog.ActNXDomain}, quiet, maxUDP)
		}
		if seg.fake.logErr(now) {
			s.logf("dns segment %q: fakeip assign: %v", seg.Name, err)
		}
		return s.reply(seg, hdr, q, e, empty(hdr, q, dnsmessage.RCodeServerFailure, e), src, verdict{act: dnslog.ActServfail}, quiet, maxUDP)
	}
	if err != nil && seg.fake.logErr(now) {
		// Assigned and journalled; only the compaction behind it failed.
		s.logf("dns segment %q: fakeip: %v", seg.Name, err)
	}
	b := newBuilder(hdr, q, dnsmessage.RCodeSuccess)
	if b == nil || b.StartAnswers() != nil {
		return nil
	}
	err = b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: q.Class, TTL: fakeTTL},
		dnsmessage.AResource{A: a.As4()},
	)
	if err != nil {
		return nil
	}
	msg := finish(b, e, dnsmessage.RCodeSuccess)
	if msg == nil {
		return nil
	}
	return s.reply(seg, hdr, q, e, msg, src, verdict{act: dnslog.ActResolved, answer: a.String()}, quiet, maxUDP)
}

func (s *Server) assignFake(seg *Segment, name string, now time.Time) (netip.Addr, error) {
	p, err := seg.fake.get()
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Assign(name, now)
}

// addressName reports a name that is an address, or that a resolver
// library would read as one: the netip forms, and all names whose last
// label is a number (127.1, 0x7f.1). inet_aton accepts these, and no
// TLD is a number.
func addressName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if _, err := netip.ParseAddr(name); err == nil {
		return true
	}
	last := name[strings.LastIndexByte(name, '.')+1:]
	if h, ok := strings.CutPrefix(strings.ToLower(last), "0x"); ok {
		last = h
		if last == "" {
			return true
		}
		return strings.Trim(last, "0123456789abcdef") == ""
	}
	return last != "" && strings.Trim(last, "0123456789") == ""
}
