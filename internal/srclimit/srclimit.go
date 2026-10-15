// Package srclimit limits the number of connections that one source address
// holds at one time, inside the global cap of a daemon.
//
// The reason: each
// accept loop on the Pi had a global semaphore (the engine 256, pf www 64,
// pf dns TCP 64 for each segment), and no limit used the peer as key. One
// device (a prompt-injected agent that is root in its VM, a hostile box on
// the house segment) could open the full budget. It could send a byte in each
// idle window to keep it. Then all other clients on the segment got a refused
// connection until it released them. The global cap limits the memory of the
// Pi. This package limits how much of it one address can take. Thus the rest
// of the segment continues to work.
//
// The key is the IP only, never the port. A client selects a new source port
// for each connection. Thus a port in the key would make the cap apply to each
// connection, which is no cap. An agent that is root in its VM can add aliases
// on its /24 and multiply the cap for each address. The nft ct count total for
// each segment limits that. This package is the backstop in the daemon behind
// it. The nft rules count flows in the kernel. This package counts what the
// daemon really holds, which is what a slowloris uses up. Thus both stay.
package srclimit

import (
	"net"
	"net/netip"
	"sync"
)

// PerSource counts live connections for each source address. Build it with
// New. A nil *PerSource admits everything. Thus a caller that never set one
// works as it did before this package existed. Safe for concurrent use.
type PerSource struct {
	max int
	mu  sync.Mutex
	n   map[netip.Addr]int
}

// New returns a counter that admits a maximum of max concurrent connections
// for each source address. max <= 0 disables the cap: Acquire always admits.
// That is how a flag set to 0 means "no per-source limit".
func New(max int) *PerSource {
	return &PerSource{max: max, n: make(map[netip.Addr]int)}
}

// Max is the per-source cap that this counter enforces, 0 when disabled.
func (p *PerSource) Max() int {
	if p == nil || p.max < 0 {
		return 0
	}
	return p.max
}

// Acquire takes one slot for the remote address of the connection. ok is
// false when that address already holds Max slots. Then the caller closes the
// connection immediately, the same as its global-full path. When ok, the
// caller must call release when the connection ends. A second call is a
// no-op. Thus a deferred release next to an early one cannot give back a slot
// two times.
//
// Acquire admits an address that does not parse as IP:port (a unix socket, a
// test pipe), and does not count it. The cap is for network peers. To refuse
// a connection because of the print format of its address would be a worse
// failure than to not count it.
func (p *PerSource) Acquire(remote net.Addr) (release func(), ok bool) {
	if p == nil || p.max <= 0 {
		return func() {}, true
	}
	a, parsed := addrOf(remote)
	if !parsed {
		return func() {}, true
	}
	p.mu.Lock()
	if p.n[a] >= p.max {
		p.mu.Unlock()
		return nil, false
	}
	p.n[a]++
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			// Delete at zero. Do not keep a 0 entry. If not, the map grows by
			// one key for each address that ever connected. On a long uptime,
			// nothing else would limit it.
			if p.n[a] <= 1 {
				delete(p.n, a)
			} else {
				p.n[a]--
			}
			p.mu.Unlock()
		})
	}, true
}

// Count is the number of slots that addr holds now. For tests and logs.
func (p *PerSource) Count(addr netip.Addr) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n[addr.Unmap()]
}

// Len is the number of addresses that hold one or more slots. For tests.
func (p *PerSource) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.n)
}

func addrOf(remote net.Addr) (netip.Addr, bool) {
	if remote == nil {
		return netip.Addr{}, false
	}
	if v, ok := remote.(*net.TCPAddr); ok {
		a, ok := netip.AddrFromSlice(v.IP)
		return a.Unmap(), ok
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}
