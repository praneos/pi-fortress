// Package blocklist is the compiled domain block list, as the engine and
// the broker see it. It is the same dnsmasq address= file that apply
// installs for the resolver. Thus there is one list and one place that
// compiles it.
//
// The reason for it: the sinkhole in dnsmasq operates only for a client that
// asks the Pi. A client that gives its own address for a name (curl
// --resolve, /etc/hosts, a pinned SDK) never sends a query. Before this
// package, the fence had nothing that read the list at connection time.
// By design, the engine imports nothing above hello and origdst
// (engine_test.go TestImportBoundary). Thus this package imports no other
// internal package.
package blocklist

import (
	"bufio"
	"os"
	"strings"
)

type Set struct {
	names map[string]struct{}
}

// New builds a set from bare names. For tests and tools. The daemons use Load.
func New(names ...string) *Set {
	s := &Set{names: make(map[string]struct{}, len(names))}
	for _, n := range names {
		if n = norm(n); n != "" {
			s.names[n] = struct{}{}
		}
	}
	return s
}

// Load reads a dnsmasq conf of address=/name/... lines. A missing file
// is an empty set, not an error. The daemons start before the first
// apply compiles anything. At that point, the resolver also has an
// empty list.
func Load(path string) (*Set, error) {
	s := New()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, "address=/")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		if name = norm(name); name != "" {
			s.names[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.names)
}

// Has reports if name or a parent domain of it is listed. That is what
// address=/name/ means to dnsmasq. It walks the labels of the name, not
// the list. Thus a 300k-entry list costs the same for each connection as
// a 3-entry list.
func (s *Set) Has(name string) bool {
	if s == nil || len(s.names) == 0 {
		return false
	}
	name = norm(name)
	for name != "" {
		if _, ok := s.names[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}

func norm(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}
