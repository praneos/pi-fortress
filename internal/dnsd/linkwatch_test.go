package dnsd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeLinks is the interface table and the pin for the rebind tests. The
// sockets are real loopback sockets, but the pin does not touch them. Thus
// the tests need no root, no netlink and no real interface.
type fakeLinks struct {
	mu   sync.Mutex
	idx  map[string]int
	pins map[string]int
	// refuse makes the pin of a name fail, as a pin to a device that is not
	// up yet fails.
	refuse map[string]bool
	// afterPin, when set, runs after each pin, with the lock held.
	afterPin func(iface string)
}

func (f *fakeLinks) links() (map[string]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.idx))
	for k, v := range f.idx {
		if v != 0 {
			out[k] = v
		}
	}
	return out, nil
}

func (f *fakeLinks) pin(_ int, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pins[iface]++
	if f.idx[iface] == 0 || f.refuse[iface] {
		return syscall.ENODEV
	}
	if f.afterPin != nil {
		f.afterPin(iface)
	}
	return nil
}

func (f *fakeLinks) set(iface string, idx int) {
	f.mu.Lock()
	f.idx[iface] = idx
	f.mu.Unlock()
}

func (f *fakeLinks) setRefuse(iface string, v bool) {
	f.mu.Lock()
	f.refuse[iface] = v
	f.mu.Unlock()
}

func (f *fakeLinks) pinned(iface string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pins[iface]
}

type rebindLab struct {
	srv         *Server
	links       *fakeLinks
	ev          chan struct{}
	logs        *logCapture
	house, desk string
}

// startRebindLab serves a house segment on 127.0.0.2 (interface house0,
// index 4) and a desk segment on 127.0.0.3 (desk0, index 5).
func startRebindLab(t *testing.T, tweak func(*rebindLab)) *rebindLab {
	t.Helper()
	dir := t.TempDir()
	sink := filepath.Join(dir, "blocked-domains.conf")
	if err := os.WriteFile(sink, []byte("address=/blocked.test/0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	seg := func(name, ip, iface string) Segment {
		return Segment{
			Name: name, IP: netip.MustParseAddr(ip), Iface: iface,
			Upstream: "127.0.0.1:9", SinkholeFiles: []string{sink}, NFTSet: "resolved_" + name,
		}
	}
	srv, err := New(Config{
		NFTTable: "inet fortress",
		Listen:   port,
		NFT:      discardNFT{},
		Segments: []Segment{seg("house", "127.0.0.2", "house0"), seg("desk", "127.0.0.3", "desk0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	lab := &rebindLab{
		srv: srv,
		links: &fakeLinks{
			idx:    map[string]int{"house0": 4, "desk0": 5},
			pins:   map[string]int{},
			refuse: map[string]bool{},
		},
		ev:    make(chan struct{}, 1),
		logs:  &logCapture{},
		house: net.JoinHostPort("127.0.0.2", itoa(port)),
		desk:  net.JoinHostPort("127.0.0.3", itoa(port)),
	}
	srv.logf = lab.logs.logf
	srv.links = lab.links.links
	srv.pinDev = lab.links.pin
	srv.linkEvents = func(context.Context) (<-chan struct{}, error) { return lab.ev, nil }
	srv.rebindGap = 20 * time.Millisecond
	srv.linkSettle = 5 * time.Millisecond
	srv.pinSweep = time.Hour
	if tweak != nil {
		tweak(lab)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return lab
}

func (l *rebindLab) event() {
	select {
	case l.ev <- struct{}{}:
	default:
	}
}

// answers reports whether addr answers over both UDP and TCP.
func answers(t *testing.T, addr string) bool {
	t.Helper()
	for _, network := range []string{"udp4", "tcp4"} {
		c, err := net.DialTimeout(network, addr, time.Second)
		if err != nil {
			return false
		}
		err = askConn(t, c, network == "tcp4")
		c.Close()
		if err != nil {
			return false
		}
	}
	return true
}

func (l *rebindLab) lines(sub string) []string {
	var out []string
	for _, line := range l.logs.get() {
		if strings.Contains(line, sub) {
			out = append(out, line)
		}
	}
	return out
}

// The field failure: a USB adapter that is plugged in again comes back as
// the same name with a new index. A listener pinned to the old index serves
// nothing until the process starts again. The watcher must open the
// listeners of that segment again, write one line, and not touch the
// listeners of a different segment.
func TestANewInterfaceIndexRebindsOnlyThatSegment(t *testing.T) {
	lab := startRebindLab(t, nil)
	eventually(t, "both segments answer", func() bool { return answers(t, lab.house) && answers(t, lab.desk) })
	if n := lab.links.pinned("house0"); n != 2 {
		t.Fatalf("house pinned %d sockets before the replug, want 2", n)
	}
	desk := lab.links.pinned("desk0")

	lab.links.set("house0", 7)
	lab.event()
	eventually(t, "house rebound to index 7", func() bool {
		return len(lab.lines("pf dns: house listener rebound to house0 (index 4 -> 7)")) == 1
	})
	eventually(t, "house answers after the rebind", func() bool {
		return lab.links.pinned("house0") == 4 && answers(t, lab.house)
	})
	if got := lab.lines("rebound"); len(got) != 1 {
		t.Fatalf("want one rebind line for two transports, got %q", got)
	}
	if got := lab.lines("not serving"); len(got) != 0 {
		t.Fatalf("a planned rebind logged a failure: %q", got)
	}
	if n := lab.links.pinned("desk0"); n != desk {
		t.Fatalf("desk sockets were opened again (%d -> %d pins): a house replug must not touch the desk", desk, n)
	}
	if !answers(t, lab.desk) {
		t.Fatal("desk does not answer after the house rebind")
	}
	for i, p := range lab.srv.segs[0].pins.live {
		if p == nil || p.index != 7 {
			t.Fatalf("house transport %d is not held at index 7: %+v", i, p)
		}
	}
}

// While the adapter is out, the name has no index. A new socket cannot pin
// to it, so the old listener stays as it is. When the adapter comes back
// with a new index, the listener is opened again.
func TestAGoneInterfaceIsReboundWhenItReturns(t *testing.T) {
	lab := startRebindLab(t, nil)
	eventually(t, "house answers", func() bool { return answers(t, lab.house) })

	lab.links.set("house0", 0)
	lab.event()
	time.Sleep(200 * time.Millisecond)
	if n := lab.links.pinned("house0"); n != 2 {
		t.Fatalf("house pinned %d sockets while its interface was gone, want 2 (no rebind to a missing device)", n)
	}

	lab.links.set("house0", 9)
	lab.event()
	eventually(t, "house rebound to index 9", func() bool {
		return len(lab.lines("pf dns: house listener rebound to house0 (index 4 -> 9)")) == 1 && answers(t, lab.house)
	})
}

// A rebind that cannot pin yet (the device is there, but not ready) waits
// for the next event, not for the full rebindWait.
func TestAnEventWakesARebindThatFailed(t *testing.T) {
	lab := startRebindLab(t, func(l *rebindLab) { l.srv.rebindWait = time.Hour })
	eventually(t, "house answers", func() bool { return answers(t, lab.house) })

	lab.links.setRefuse("house0", true)
	lab.links.set("house0", 7)
	lab.event()
	eventually(t, "the rebind is refused", func() bool { return len(lab.lines("refusing to serve")) >= 2 })
	if answers(t, lab.house) {
		t.Fatal("house answers with no pinned socket")
	}

	lab.links.setRefuse("house0", false)
	lab.event()
	eventually(t, "house answers after the second event", func() bool {
		return len(lab.lines("house listener rebound to house0 (index 4 -> 7)")) == 1 && answers(t, lab.house)
	})
}

// The index can change between the lookup before the bind and the pin. A
// sweep in that time does not see the new listener. The check in hold must
// find it and bind again with no event.
func TestAnIndexChangeDuringTheBindIsCaught(t *testing.T) {
	lab := startRebindLab(t, func(l *rebindLab) {
		l.links.afterPin = func(iface string) {
			if iface == "house0" {
				l.links.idx["house0"] = 7
			}
		}
	})
	eventually(t, "house answers", func() bool { return answers(t, lab.house) })
	eventually(t, "both house transports held at index 7", func() bool {
		lab.srv.segs[0].pins.mu.Lock()
		defer lab.srv.segs[0].pins.mu.Unlock()
		for _, p := range lab.srv.segs[0].pins.live {
			if p == nil || p.index != 7 {
				return false
			}
		}
		return true
	})
	if got := lab.lines("not serving"); len(got) != 0 {
		t.Fatalf("the rebind logged a failure: %q", got)
	}
}

// Without link events (the socket did not open), the timed sweep still
// finds a stale listener.
func TestTheTimedSweepRebindsWithoutEvents(t *testing.T) {
	lab := startRebindLab(t, func(l *rebindLab) {
		l.srv.linkEvents = func(context.Context) (<-chan struct{}, error) { return nil, errors.New("no netlink here") }
		l.srv.pinSweep = 50 * time.Millisecond
	})
	eventually(t, "house answers", func() bool { return answers(t, lab.house) })
	if got := lab.lines("no link events"); len(got) != 1 {
		t.Fatalf("want one line about the missing events, got %q", got)
	}
	lab.links.set("house0", 8)
	eventually(t, "house rebound by the timed sweep", func() bool {
		return len(lab.lines("house listener rebound to house0 (index 4 -> 8)")) == 1 && answers(t, lab.house)
	})
}

// A flapping adapter gives many events. Each transport binds at most once
// each rebindGap, and the listener ends on the last index.
func TestARebindIsRateLimited(t *testing.T) {
	const gap = 300 * time.Millisecond
	lab := startRebindLab(t, func(l *rebindLab) {
		l.srv.rebindGap = gap
		l.srv.linkSettle = time.Millisecond
	})
	eventually(t, "house answers", func() bool { return answers(t, lab.house) })
	start := time.Now()
	for i := 10; i < 30; i++ {
		lab.links.set("house0", i)
		lab.event()
		time.Sleep(10 * time.Millisecond)
	}
	eventually(t, "house held at index 29", func() bool {
		lab.srv.segs[0].pins.mu.Lock()
		defer lab.srv.segs[0].pins.mu.Unlock()
		for _, p := range lab.srv.segs[0].pins.live {
			if p == nil || p.index != 29 {
				return false
			}
		}
		return true
	})
	elapsed := time.Since(start)
	// Two first binds, then for each transport one bind at once and one each
	// gap after it.
	limit := 2 + 2*(2+int(elapsed/gap))
	if n := lab.links.pinned("house0"); n > limit {
		t.Fatalf("house pinned %d sockets in %s, want at most %d with a %s gap", n, elapsed, limit, gap)
	}
	if !answers(t, lab.house) {
		t.Fatal("house does not answer after the flaps")
	}
}

// The DoT stub serves only lo, and its unit does not allow AF_NETLINK. The
// index of lo never changes. Thus a server with only lo segments opens no
// event source and does no lookup of interface indexes.
func TestALoopbackOnlyServerWatchesNoLinks(t *testing.T) {
	var opened, looked atomic.Bool
	addr := serveLoopback(t, "127.0.0.1:9", func(s *Server) {
		s.pinDev = func(int, string) error { return nil }
		s.linkEvents = func(context.Context) (<-chan struct{}, error) {
			opened.Store(true)
			return nil, errors.New("not here")
		}
		s.links = func() (map[string]int, error) {
			looked.Store(true)
			return nil, errors.New("not here")
		}
	})
	if !answers(t, addr) {
		t.Fatal("loopback segment does not answer")
	}
	if opened.Load() || looked.Load() {
		t.Fatalf("lo-only server opened link events (%v) or looked up indexes (%v)", opened.Load(), looked.Load())
	}
}
