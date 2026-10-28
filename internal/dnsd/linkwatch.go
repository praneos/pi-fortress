package dnsd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// A listener pinned with SO_BINDTODEVICE does not keep the interface name.
// The kernel finds the device by name one time, when the option is set, and
// keeps only its index (sk_bound_dev_if). A USB adapter that is unplugged and
// plugged back is a new device: the same name, the same address, but a new
// index. The old socket stays open and bound to the index of a device that
// does not exist now. No read on it fails, so retry never sees an error. Each
// query to the segment address on the new device gets "connection refused"
// until the process starts again.
//
// Thus to pin by name again with a timer does not help: the socket must be
// opened again. This file finds the sockets whose interface has a new index
// and closes them. retry then opens them again at once, pinned to the new
// device. Only the listeners of that segment close. The other segments keep
// their sockets and do not stop for one query.
//
// The trigger is a rtnetlink socket that gets the link and IPv4 address
// events (routeEvents). One replug gives a burst of events. The watcher waits
// linkSettle for the burst to stop, and then compares the index of each
// segment interface with the index that its listeners were pinned to. A
// sweep every pinSweep does the same check if an event was lost (the socket
// buffer overflowed) or the event socket did not open.
//
// The pin itself does not change: each socket is still bound to its address
// and pinned to the device of its segment before it serves (control,
// refusePin). A packet for the segment address that comes in on a different
// interface still gets no answer.

const (
	// rebindGap is the shortest time between two binds of one transport when
	// an event wakes retry. A flapping adapter can give many events in a
	// second. It must not make the listener close and open in a loop.
	rebindGap = time.Second
	// linkSettle is the time that the watcher waits after an event before it
	// does a sweep. Each event in that time goes into the same sweep.
	linkSettle = 200 * time.Millisecond
	// pinSweep is the time between two sweeps when there is no event.
	pinSweep = 30 * time.Second
)

// errRebind is what a listener loop returns after the watcher closed its
// socket because the interface of the segment has a new index. retry does not
// log it and does not wait rebindWait for it.
var errRebind = errors.New("interface has a new index; listener closed to bind again")

// pinTable holds the live listeners of one segment and the interface index
// that each one is pinned to.
type pinTable struct {
	mu   sync.Mutex
	live [2]*heldPin
	// kick wakes retry of a transport that waits after a failed bind. Each
	// sweep sends to it, so an address that comes back is served without the
	// rebindWait delay.
	kick [2]chan struct{}
	// served is the index of the last listener that served, for the rebind
	// line. The first transport that serves on a new index writes the line.
	// The second one finds the same index and writes nothing.
	served atomic.Int64
}

// heldPin is one live listener. index 0 means that the index was not known
// when the socket was pinned.
type heldPin struct {
	index   int
	close   func() error
	dropped atomic.Bool
}

// why gives the error that the listener loop returns for err from its socket:
// errRebind when the watcher closed the socket, else err.
func (p *heldPin) why(err error) error {
	if p.dropped.Load() {
		return errRebind
	}
	return err
}

func (pt *pinTable) kicker(network string) chan struct{} {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	t := transport(network)
	if pt.kick[t] == nil {
		pt.kick[t] = make(chan struct{}, 1)
	}
	return pt.kick[t]
}

func (pt *pinTable) kickAll() {
	for _, network := range []string{"udp", "tcp"} {
		select {
		case pt.kicker(network) <- struct{}{}:
		default:
		}
	}
}

func (pt *pinTable) hold(network string, index int, close func() error) *heldPin {
	p := &heldPin{index: index, close: close}
	pt.mu.Lock()
	pt.live[transport(network)] = p
	pt.mu.Unlock()
	return p
}

func (pt *pinTable) release(network string, p *heldPin) {
	pt.mu.Lock()
	if pt.live[transport(network)] == p {
		pt.live[transport(network)] = nil
	}
	pt.mu.Unlock()
}

// dropStale closes each live listener that is not pinned to index now, and
// gives the number that it closed. now 0 means that the interface does not
// exist at this time. Then nothing closes: a new socket cannot pin to a
// device that is not there, and the old one costs nothing until the device
// comes back. The sweep after the device comes back closes it.
func (pt *pinTable) dropStale(now int) int {
	if now == 0 {
		return 0
	}
	var stale []*heldPin
	pt.mu.Lock()
	for _, p := range pt.live {
		if p != nil && p.index != now && !p.dropped.Swap(true) {
			stale = append(stale, p)
		}
	}
	pt.mu.Unlock()
	for _, p := range stale {
		_ = p.close()
	}
	return len(stale)
}

// watched reports whether the index of the segment interface can change.
// The index of lo never changes. A server with only lo segments (the DoT stub,
// whose unit does not allow AF_NETLINK) thus opens no rtnetlink socket and does
// no lookup.
func (seg *Segment) watched() bool {
	return seg.Iface != "lo"
}

// ifIndex gives the index of the interface of seg, or 0 when the interface
// does not exist, the lookup failed, or the segment is not watched.
func (s *Server) ifIndex(seg *Segment) int {
	if !seg.watched() {
		return 0
	}
	idx, err := s.links()
	if err != nil {
		return 0
	}
	return idx[seg.Iface]
}

// hold records a listener that is bound and pinned, with the index that
// ifIndex gave just before the pin. The index can change between that lookup
// and the pin. A sweep that ran in that time did not see this listener. Thus
// hold does one check of its own after the listener is recorded. If the
// index is not the same now, it gives errRebind and retry binds again.
func (s *Server) hold(seg *Segment, network string, index int, close func() error) (*heldPin, error) {
	p := seg.pins.hold(network, index, close)
	if !seg.watched() {
		return p, nil
	}
	if idx, err := s.links(); err == nil {
		seg.pins.dropStale(idx[seg.Iface])
	}
	if p.dropped.Load() {
		seg.pins.release(network, p)
		return nil, errRebind
	}
	return p, nil
}

// noteServing writes the rebind line when a listener of seg serves on an
// index that is not the index of the last one.
func (s *Server) noteServing(seg *Segment, index int) {
	if index == 0 {
		return
	}
	old := seg.pins.served.Swap(int64(index))
	if old != 0 && old != int64(index) {
		name := seg.Name
		if name == "" {
			name = "agent"
		}
		s.logf("pf dns: %s listener rebound to %s (index %d -> %d)", name, seg.Iface, old, index)
	}
}

// sweepPins closes each listener whose interface has a new index, and wakes
// each retry that waits.
func (s *Server) sweepPins() {
	idx, err := s.links()
	if err != nil {
		return
	}
	for _, seg := range s.segs {
		if seg.watched() {
			seg.pins.dropStale(idx[seg.Iface])
			seg.pins.kickAll()
		}
	}
}

// watchesLinks reports whether a segment of s is watched.
func (s *Server) watchesLinks() bool {
	for _, seg := range s.segs {
		if seg.watched() {
			return true
		}
	}
	return false
}

// watchLinks does a sweep after each burst of link or address events, and
// every pinSweep. It stops when ctx is done. It never stops Run: without
// events, the timed sweep still finds a stale listener.
func (s *Server) watchLinks(ctx context.Context) {
	events, err := s.linkEvents(ctx)
	if err != nil {
		s.logf("pf dns: no link events (%v); interface indexes are checked every %s", err, s.pinSweep)
		events = nil
	}
	tick := time.NewTicker(s.pinSweep)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case _, ok := <-events:
			if !ok {
				if ctx.Err() == nil {
					s.logf("pf dns: link events stopped; interface indexes are checked every %s", s.pinSweep)
				}
				events = nil
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.linkSettle):
			}
			// The channel holds one signal. An event in the settle time is
			// part of this sweep.
			select {
			case <-events:
			default:
			}
		}
		s.sweepPins()
	}
}

// ifIndexes gives the index of each interface by name.
func ifIndexes() (map[string]int, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	idx := make(map[string]int, len(ifs))
	for _, ifi := range ifs {
		idx[ifi.Name] = ifi.Index
	}
	return idx, nil
}

// pinToDevice is SO_BINDTODEVICE, on a new socket before its bind. It
// needs no capability (bindToDevice gives the reason).
func pinToDevice(fd int, iface string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}

// routeEvents opens a rtnetlink socket in the link and IPv4 address groups.
// It sends on the channel when one or more messages come in. It does not read
// the messages: the sweep reads the state again. A buffer overflow (ENOBUFS)
// means that events were lost, so it also sends then. The channel closes when
// the socket fails or ctx is done. The groups need no capability, and the
// unit allows AF_NETLINK.
func routeEvents(ctx context.Context) (<-chan struct{}, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink socket: %w", err)
	}
	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: 1<<(syscall.RTNLGRP_LINK-1) | 1<<(syscall.RTNLGRP_IPV4_IFADDR-1),
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rtnetlink bind: %w", err)
	}
	// A non-blocking fd goes to the Go poller. Thus Close wakes a Read that
	// waits, which a raw Recvfrom does not do.
	f := os.NewFile(uintptr(fd), "rtnetlink")
	stop := context.AfterFunc(ctx, func() { _ = f.Close() })
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		defer func() {
			if stop() {
				_ = f.Close()
			}
		}()
		buf := make([]byte, 16<<10)
		for {
			if _, err := f.Read(buf); err != nil && !errors.Is(err, syscall.ENOBUFS) {
				return
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch, nil
}
