package corepolicy

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The echo fixtures answer inside the fence. The code decides them before
// all lists. Both policy files name pf-core-echo.test today. Thus an OR
// over the files would forward it outside the lab (docs/paranoid_mode.md K11).
const (
	OpenEcho = "pf-open-echo.test"
	CoreEcho = "pf-core-echo.test"
)

// Forward is the destination oracle of paranoid mode: the names that the
// agent segment can reach at all. An allow.domains entry includes its
// subdomains. A core.hosts entry does not, unless it is written "*.name".
// The two tables never merge. A merged suffix map would let the exact core
// name api.x.ai open evil.api.x.ai (docs/paranoid_mode.md K9).
type Forward struct {
	allow  map[string]struct{}
	hosts  map[string]struct{}
	suffix map[string]struct{}
	// plain is the set of a plain segment (LoadAllow): only its own allow file.
	// The echo fixtures exist for the fence of the agent. Thus they are not
	// forwarded for that segment either.
	plain bool
}

// LoadForward reads both files. It refuses a missing or unreadable file.
// Load and LoadDomains give an empty set for an absent file. That is
// correct for a list that only decides how loud a log line is. It is wrong
// for the only control between the agent and the internet.
func LoadForward(allowPath, corePath string) (*Forward, error) {
	f := &Forward{hosts: map[string]struct{}{}, suffix: map[string]struct{}{}}
	af, err := os.Open(allowPath)
	if err != nil {
		return nil, err
	}
	af.Close()
	if f.allow, err = LoadDomains(allowPath); err != nil {
		return nil, err
	}
	cf, err := os.Open(corePath)
	if err != nil {
		return nil, err
	}
	defer cf.Close()
	sc := bufio.NewScanner(cf)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		bits := strings.Fields(strings.TrimSpace(line))
		if len(bits) == 0 {
			continue
		}
		host, suffix := hostEntry(bits[0])
		if host == "" {
			continue
		}
		// Policy.Load also lists a "*.name" entry as an exact host.
		// A deny oracle reads the star as written. Thus "*.example.com"
		// includes the subdomains but not example.com itself.
		if suffix {
			f.suffix[host] = struct{}{}
			continue
		}
		f.hosts[host] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return f, nil
}

// LoadAllow is the forward set of a paranoid plain segment. It reads one
// allow.<segment>.domains file the same way as allow.domains (a name and
// its subdomains). It has no core.hosts table and no echo fixtures. A
// missing or unreadable file is an error, for the reason that LoadForward
// gives. An empty file is not an error here. Names tells how many usable
// entries it holds. The caller decides what zero means.
func LoadAllow(path string) (*Forward, error) {
	af, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	af.Close()
	allow, err := LoadDomains(path)
	if err != nil {
		return nil, err
	}
	return &Forward{allow: allow, hosts: map[string]struct{}{}, suffix: map[string]struct{}{}, plain: true}, nil
}

// Allowed reports whether name may be forwarded. Blocklists run before
// this and still win.
func (f *Forward) Allowed(name string, lab bool) bool {
	if f == nil {
		return false
	}
	n := normHost(name)
	if !f.plain {
		switch n {
		case OpenEcho:
			return true
		case CoreEcho:
			return lab
		}
	}
	if n == "" || emptyLabel(n) {
		return false
	}
	return HostIn(n, f.allow) || f.coreListed(n)
}

// nameRe is a copy of domainRe in policycompile.ParseDomain. corepolicy
// cannot import domainRe without a cycle. If the TUI refuses a name in
// allow.domains, the resolver conf also does not carry that name.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func validName(n string) bool {
	if len(n) > 253 || !nameRe.MatchString(n) {
		return false
	}
	for label := range strings.SplitSeq(n, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

// Names is all names on the two lists, without echo fixtures and
// unparseable entries. It is a count, not an enforcement path. pf dns
// resolves through Allowed directly. Names only supplies the "paranoid=N"
// line that pf status prints (internal/dnsd Segments). A "*." line in
// allow.domains is unparseable here, because Allowed matches it against
// nothing. If Names counted it, the count would tell the operator that a
// name is open when the box refuses it.
func (f *Forward) Names() []string {
	seen := map[string]struct{}{}
	for _, table := range []map[string]struct{}{f.allow, f.hosts, f.suffix} {
		for n := range table {
			if n == "" || n == OpenEcho || n == CoreEcho || !validName(n) {
				continue
			}
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// coreListed examines the exact table at the name itself and the star
// table at each parent. This is the label walk of HostIn, split across
// the two maps that must never merge.
func (f *Forward) coreListed(name string) bool {
	if _, ok := f.hosts[name]; ok {
		return true
	}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
		if _, ok := f.suffix[name]; ok {
			return true
		}
	}
}
