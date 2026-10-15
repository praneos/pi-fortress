package fakeip

import (
	"io"
	"net/netip"
	"os"
	"sync"
)

// Table maps a pool address back to its name from the journal. It is the
// broker half, and never writes. Safe for concurrent Name.
type Table struct {
	prefix netip.Prefix

	mu     sync.Mutex
	path   string
	f      *os.File
	fi     os.FileInfo
	off    int64
	byAddr map[netip.Addr]string
}

// NewTable reads nothing yet. The journal may not exist until pf dns has
// answered its first query, and a broker that starts first must not fail
// because of that. The first Name loads it.
func NewTable(prefix netip.Prefix, journal string) *Table {
	return &Table{prefix: prefix.Masked(), path: journal}
}

// Contains reports whether addr is in the pool prefix at all, mapped or
// not, including the .0 and .255 that the pool never gives out. The broker
// asks this first. An address in the pool is fake, and an address with no
// mapping is refused as unmapped, never dialled as if it were real. A
// Table built on an invalid prefix contains nothing, which is fake-IP off.
func (t *Table) Contains(addr netip.Addr) bool {
	a := addr.Unmap()
	return CheckPrefix(t.prefix) == nil && a.Is4() && t.prefix.Contains(a)
}

// Name returns the name that addr was last assigned to. It reads lines
// appended since the last call. It reloads from the start when the journal
// was compacted (a new inode under the same path) or truncated.
//
// It examines the journal on each call, not only on a miss. A hit can be
// stale. When the pool is full, pf dns reuses the least recent address for
// a new name. A table that trusted its own copy would hold the SNI of the
// new owner to the old name, and refuse it. The check is one stat when
// nothing changed, compared with a TLS handshake and a DNS lookup per
// connection.
func (t *Table) Name(addr netip.Addr) (string, bool) {
	if !t.Contains(addr) {
		return "", false
	}
	if _, ok := offsetOf(t.prefix, addr); !ok {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refresh()
	n, ok := t.byAddr[addr.Unmap()]
	return n, ok
}

// refresh brings byAddr up to date with the journal on disk. An error
// leaves the last good view in place. An unreadable journal must not change
// each mapped connection into a refusal while an older view still answers.
func (t *Table) refresh() {
	fi, err := os.Stat(t.path)
	if err != nil {
		return
	}
	if t.f == nil || !os.SameFile(fi, t.fi) || fi.Size() < t.off {
		f, err := os.Open(t.path)
		if err != nil {
			return
		}
		// Stat the handle, not the path: the path may have been renamed
		// over again between the two calls, and fi must describe what
		// is being read.
		ofi, err := f.Stat()
		if err != nil {
			f.Close()
			return
		}
		if t.f != nil {
			t.f.Close()
		}
		t.f, t.fi, t.off, t.byAddr = f, ofi, 0, map[netip.Addr]string{}
		fi = ofi
	}
	if fi.Size() == t.off {
		return
	}
	n, _ := readLines(io.NewSectionReader(t.f, t.off, 1<<62), func(s string) {
		if _, a, _, name, ok := parse(t.prefix, s); ok {
			t.byAddr[a] = name
		}
	})
	t.off += n
}
