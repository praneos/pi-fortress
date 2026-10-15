package fakeip

import (
	"container/list"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// journalMode lets pf dns write the journal and the broker read it by
// group. Set explicitly after create, because pf dns may run under a
// umask that would otherwise leave the broker locked out of it.
const journalMode = 0o640

// refreshLine is how stale the newest line of a known name may get before a
// re-assign of it writes a new line. A re-assign always refreshes the
// recency of the name in memory. The line carries that recency across a pf
// dns restart. Without a line, a restart would forget that a name that the
// agent asks for each minute is hot. It would then give its address to the
// next new name while the agent still has it cached. The result is a
// refusal, never a wrong site (the broker holds the SNI to the mapping),
// but a working connection broken for nothing. With a line on each
// re-assign, the journal grows with the query rate of the agent, not with
// its set of names. On an SD card, that is wear for no gain. One line a
// minute per name keeps recency correct to within the minute, at a write
// cost bounded by the names in use.
const refreshLine = time.Minute

// compactFactor is how many journal lines per usable address the journal
// may reach before it is rewritten with the live mappings only.
const compactFactor = 4

type entry struct {
	name string
	addr netip.Addr
	// stamp is the unix time of the newest journal line of this entry.
	stamp int64
	elem  *list.Element
}

// Pool gives out addresses and journals each assignment. It is the pf dns
// half: the only writer of the journal. Safe for concurrent Assign.
type Pool struct {
	mu     sync.Mutex
	prefix netip.Prefix
	size   uint32
	path   string
	f      *os.File
	byName map[string]*entry
	byAddr map[netip.Addr]*entry
	// lru orders the live entries by last assignment, most recent at the
	// front. A full pool reuses the back.
	lru *list.List
	// next is the lowest offset never given out. Until it reaches size, a
	// new name takes a new address, and nothing is reused.
	next  uint32
	lines int
}

// OpenPool opens or creates the journal and loads it. So a name keeps its
// address across a pf dns restart, and the cached answer of an agent still maps.
func OpenPool(prefix netip.Prefix, journal string) (*Pool, error) {
	if err := CheckPrefix(prefix); err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	f, err := os.OpenFile(journal, os.O_RDWR|os.O_APPEND|os.O_CREATE, journalMode)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(journalMode); err != nil {
		f.Close()
		return nil, err
	}
	p := &Pool{
		prefix: prefix,
		size:   usable(prefix),
		path:   journal,
		f:      f,
		byName: map[string]*entry{},
		byAddr: map[netip.Addr]*entry{},
		lru:    list.New(),
	}
	n, err := readLines(f, func(s string) {
		p.lines++
		if stamp, a, off, name, ok := parse(prefix, s); ok {
			p.load(stamp, a, off, name)
		}
	})
	if err != nil {
		f.Close()
		return nil, err
	}
	// A power cut can leave a torn last line with no newline. The next
	// append would glue onto it, and both would be lost. A close of it
	// here costs the torn line, which is lost in any case.
	if st, err := f.Stat(); err == nil && st.Size() > n {
		if _, err := f.Write([]byte{'\n'}); err != nil {
			f.Close()
			return nil, err
		}
		p.lines++
	}
	if err := p.maybeCompact(); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}

// load applies one journal line in file order. A later line for the same
// address or the same name supersedes the earlier one. Line order is
// recency order, and that is how the LRU survives a restart.
func (p *Pool) load(stamp int64, a netip.Addr, off uint32, name string) {
	if e := p.byAddr[a]; e != nil && e.name != name {
		p.drop(e)
	}
	if e := p.byName[name]; e != nil && e.addr != a {
		p.drop(e)
	}
	if e := p.byName[name]; e != nil {
		e.stamp = stamp
		p.lru.MoveToFront(e.elem)
		return
	}
	p.add(stamp, a, name)
	if off >= p.next {
		p.next = off + 1
	}
}

func (p *Pool) add(stamp int64, a netip.Addr, name string) {
	e := &entry{name: name, addr: a, stamp: stamp}
	e.elem = p.lru.PushFront(e)
	p.byName[name] = e
	p.byAddr[a] = e
}

func (p *Pool) drop(e *entry) {
	p.lru.Remove(e.elem)
	delete(p.byName, e.name)
	delete(p.byAddr, e.addr)
}

// Assign returns the address of name, and gives out a new address if name
// has none. The journal line is written before Assign returns. So when pf
// dns answers, the broker can already map the address back.
//
// A full pool reuses the least recently assigned address. That is safe,
// because the broker requires the SNI to equal the mapped name. An agent
// that still holds the old answer is refused, and never goes to the new owner.
//
// A compaction failure is returned wrapped, with the address. The address
// is assigned and journalled all the same.
func (p *Pool) Assign(name string, now time.Time) (netip.Addr, error) {
	n, err := Normalise(name)
	if err != nil {
		return netip.Addr{}, err
	}
	// An address is not a name. If it were mapped back, the broker would
	// dial the literal past the direct-IP rule. pf dns refuses it before
	// it gets here. This check holds for all other callers.
	if _, err := netip.ParseAddr(n); err == nil {
		return netip.Addr{}, ErrName
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil {
		return netip.Addr{}, ErrClosed
	}
	ts := now.Unix()
	if e := p.byName[n]; e != nil {
		p.lru.MoveToFront(e.elem)
		if ts-e.stamp < int64(refreshLine/time.Second) {
			return e.addr, nil
		}
		if err := p.write(ts, e.addr, n); err != nil {
			return netip.Addr{}, err
		}
		e.stamp = ts
		return e.addr, p.maybeCompact()
	}
	var a netip.Addr
	var old *entry
	if p.next < p.size {
		a = addrAt(p.prefix, p.next)
	} else {
		old = p.lru.Back().Value.(*entry)
		a = old.addr
	}
	// Journal first, memory second: a failed write leaves the pool as it
	// was. It does not give out an address that the broker cannot map.
	if err := p.write(ts, a, n); err != nil {
		return netip.Addr{}, err
	}
	if old != nil {
		p.drop(old)
	} else {
		p.next++
	}
	p.add(ts, a, n)
	return a, p.maybeCompact()
}

func (p *Pool) write(ts int64, a netip.Addr, name string) error {
	if _, err := p.f.Write(line(ts, a, name)); err != nil {
		return err
	}
	p.lines++
	return nil
}

// maybeCompact rewrites the journal when it holds compactFactor lines per
// usable address. It is tied to the pool size, not the live count, so a
// small working set does not rewrite the file each few minutes.
func (p *Pool) maybeCompact() error {
	if p.lines <= compactFactor*int(p.size) {
		return nil
	}
	if err := p.compact(); err != nil {
		return fmt.Errorf("fakeip: compact %s: %w", p.path, err)
	}
	return nil
}

// compact writes the live mappings to a temp file in the directory of the
// journal, least recent first, so a reload builds the same LRU again. Then
// it renames the temp file over the journal. The rename is atomic, so a
// reader sees the old file or the new one, never half of either. The Table
// of the broker notices the new inode and reloads. The temp file becomes
// the write handle of the pool. This process is the only writer, so its
// offset is the end of the file, and nothing can fail between the rename
// and the switch.
func (p *Pool) compact() error {
	tmp, err := os.CreateTemp(filepath.Dir(p.path), filepath.Base(p.path)+".tmp*")
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(journalMode); err != nil {
		return fail(err)
	}
	var buf []byte
	for el := p.lru.Back(); el != nil; el = el.Prev() {
		e := el.Value.(*entry)
		buf = append(buf, line(e.stamp, e.addr, e.name)...)
	}
	if _, err := tmp.Write(buf); err != nil {
		return fail(err)
	}
	// Synced before the rename: a power cut after the rename must find the
	// mappings on disk, not a zero-length journal in the place of the old one.
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp.Name(), p.path); err != nil {
		return fail(err)
	}
	if d, err := os.Open(filepath.Dir(p.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	p.f.Close()
	p.f = tmp
	p.lines = p.lru.Len()
	return nil
}

// Close closes the journal. Assign fails after it.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil {
		return nil
	}
	err := p.f.Close()
	p.f = nil
	return err
}
