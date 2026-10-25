package dnsd

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

// hosts is what a dnsmasq address= file actually says: a name answered
// from configuration, not from upstream, and the address for the
// answer.
//
// internal/blocklist reads the same files and keeps only the names. The
// engine and the broker ask one question (is this blocked?), and every
// compiled line that they see says 0.0.0.0. A resolver cannot discard
// the address: `address=/pf-open-echo.test/192.0.2.3` is a fixture that
// the lab resolves, not a sinkhole. An answer of 0.0.0.0 for it would
// be a silent difference from the resolver that this one replaces.
type hosts struct {
	m map[string]netip.Addr
}

func newHosts() *hosts { return &hosts{m: map[string]netip.Addr{}} }

// loadHosts merges the files in order. For a name, a later file wins. A
// missing file is empty, not an error: the daemons start before the
// first apply has compiled anything.
func loadHosts(paths []string) (*hosts, error) {
	h := newHosts()
	for _, p := range paths {
		if err := h.load(p); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *hosts) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "address=/")
		if !ok {
			continue
		}
		name, val, _ := strings.Cut(rest, "/")
		// A hand-written "*.name" is the same entry as "name", as the compiled
		// lists write it. lookup then matches the name and each name under it.
		if name = strings.TrimPrefix(norm(name), "*."); name == "" {
			continue
		}
		// The code takes all values that are not IPv4 literals as the
		// sinkhole. A value that it cannot read must not become a name that
		// it forwards. That would change a malformed block into an allow,
		// and that is the wrong way for a mistake to fail.
		a, err := netip.ParseAddr(strings.TrimSpace(val))
		if err != nil || !a.Is4() {
			a = netip.AddrFrom4([4]byte{})
		}
		h.m[name] = a
	}
	return sc.Err()
}

// lookup walks the labels of the name, not the table. So a name
// matches itself or any parent, at the same cost for any list size.
// This is what address=/name/ means to dnsmasq.
func (h *hosts) lookup(name string) (netip.Addr, bool) {
	if h == nil || len(h.m) == 0 {
		return netip.Addr{}, false
	}
	name = norm(name)
	for name != "" {
		if a, ok := h.m[name]; ok {
			return a, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return netip.Addr{}, false
		}
		name = name[i+1:]
	}
	return netip.Addr{}, false
}

func (h *hosts) Len() int {
	if h == nil {
		return 0
	}
	return len(h.m)
}

func norm(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}
