// Package corepolicy loads the host and kind tables from the policy files.
// It tells if a name is allowed, and if a credential kind on that name is allowed.
// The broker, internal/fence and internal/policycompile call it.
package corepolicy

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"unicode"
)

const AllKinds = "*"

// KindCanary is the challenge credential (docs/challenge_rules.md). It is
// a usual kind, with one exception: AllKinds does not include it. Thus a
// substitution of it occurs only for a host whose line names CANARY.
const KindCanary = "CANARY"

type Policy struct {
	Hosts map[string]struct{}
	// Suffix holds the entries written as "*.host". These match all
	// subdomains. All other entries match exactly.
	Suffix map[string]struct{}
	// HostKinds holds the kinds of the exact entries. SuffixKinds holds the
	// kinds of the "*." entries. They are separate tables because a file can
	// write one name in the two forms. With one table, the two lines
	// overwrote each other. Then the kinds of a host came from the line that
	// the file listed second.
	HostKinds   map[string]map[string]struct{}
	SuffixKinds map[string]map[string]struct{}
	// HostHeaders and SuffixHeaders hold the headers that a line declared with
	// KIND:Header, in addition to DefaultHeaders. They hold them for each
	// entry and kind, in lowercase.
	HostHeaders   map[string]map[string]map[string]struct{}
	SuffixHeaders map[string]map[string]map[string]struct{}
}

func newPolicy() *Policy {
	return &Policy{
		Hosts:         map[string]struct{}{},
		Suffix:        map[string]struct{}{},
		HostKinds:     map[string]map[string]struct{}{},
		SuffixKinds:   map[string]map[string]struct{}{},
		HostHeaders:   map[string]map[string]map[string]struct{}{},
		SuffixHeaders: map[string]map[string]map[string]struct{}{},
	}
}

func Load(path string) (*Policy, error) {
	return LoadFiles(path)
}

// LoadFiles reads core.hosts files in sequence into one policy. A missing
// file is empty. The lines for the same entry add together, for kinds and
// for headers, in all positions. This is how core.hosts.local goes on top
// of the shipped core.hosts. A narrower local line must not remove the
// kinds that the shipped line binds.
func LoadFiles(paths ...string) (*Policy, error) {
	p := newPolicy()
	for _, path := range paths {
		if err := p.load(path); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Policy) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		bits := strings.Fields(strings.TrimSpace(line))
		if len(bits) == 0 {
			continue
		}
		suffix := strings.HasPrefix(bits[0], "*.")
		host := normHost(strings.TrimPrefix(bits[0], "*."))
		if host == "" {
			continue
		}
		kindsT, headersT := p.HostKinds, p.HostHeaders
		if suffix {
			p.Suffix[host] = struct{}{}
			kindsT, headersT = p.SuffixKinds, p.SuffixHeaders
		}
		p.Hosts[host] = struct{}{}
		kinds := kindsT[host]
		if kinds == nil {
			kinds = map[string]struct{}{}
			kindsT[host] = kinds
		}
		for _, b := range bits[1:] {
			kind, hdrs, err := ParseBinding(b)
			if err != nil {
				return fmt.Errorf("%s:%d: %w", path, n, err)
			}
			if kind == "" {
				continue
			}
			kinds[kind] = struct{}{}
			if len(hdrs) == 0 {
				continue
			}
			if headersT[host] == nil {
				headersT[host] = map[string]map[string]struct{}{}
			}
			set := headersT[host][kind]
			if set == nil {
				set = map[string]struct{}{}
				headersT[host][kind] = set
			}
			for _, h := range hdrs {
				set[strings.ToLower(h)] = struct{}{}
			}
		}
	}
	return sc.Err()
}

// DefaultHeaders carry all kinds that a host binds: Bearer and Basic
// Authorization, and the X-Api-Key that Anthropic reads. Lowercase.
var DefaultHeaders = []string{"authorization", "x-api-key"}

func DefaultHeader(name string) bool {
	for _, h := range DefaultHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// A line can never declare deniedHeaders to carry a credential. Logs and
// echoes usually contain these headers, or the headers control framing and
// routing. deniedPrefixes apply the same rule to a full family of headers.
var (
	deniedHeaders = map[string]struct{}{
		"user-agent": {}, "referer": {}, "origin": {},
		"host": {}, "via": {}, "forwarded": {}, "x-real-ip": {},
		"transfer-encoding": {}, "connection": {}, "keep-alive": {},
		"upgrade": {}, "te": {}, "trailer": {},
	}
	deniedPrefixes = []string{"x-forwarded-", "content-", "proxy-"}
)

// ValidHeader tells if a line can declare name as a credential header. name
// must be an RFC 9110 token that is not on the deny-list.
func ValidHeader(name string) error {
	if name == "" {
		return errors.New("empty header name")
	}
	for i := 0; i < len(name); i++ {
		if !tchar(name[i]) {
			return fmt.Errorf("header %q is not an RFC 9110 token", name)
		}
	}
	low := strings.ToLower(name)
	_, denied := deniedHeaders[low]
	for _, pre := range deniedPrefixes {
		denied = denied || strings.HasPrefix(low, pre)
	}
	if denied {
		return fmt.Errorf("header %q can never carry a credential: it is commonly logged or echoed, or it steers framing or routing", name)
	}
	return nil
}

// ParseBinding reads one kind column of a core.hosts line: KIND or
// KIND:Header[,Header...]. It skips a bare token that is not a kind (kind
// ""), as it always did. It applies the grammar to a token that declares
// headers, because that token adds locations where a credential goes.
func ParseBinding(tok string) (string, []string, error) {
	kind, list, hasHeaders := strings.Cut(tok, ":")
	if !hasHeaders {
		if validKind(kind) {
			return kind, nil, nil
		}
		return "", nil, nil
	}
	if !validKind(kind) {
		return "", nil, fmt.Errorf("%q: %q is not a credential kind", tok, kind)
	}
	var hdrs []string
	for _, h := range strings.Split(list, ",") {
		if err := ValidHeader(h); err != nil {
			return "", nil, fmt.Errorf("%q: %w", tok, err)
		}
		hdrs = append(hdrs, h)
	}
	return kind, hdrs, nil
}

func tchar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// HostIn reports whether name is listed or is a subdomain of an entry.
// It walks the labels of the name, not the table. Thus a list of a few
// thousand trusted names costs a connection no more than a list of
// eighteen names.
func HostIn(name string, table map[string]struct{}) bool {
	name = normHost(name)
	if emptyLabel(name) {
		return false
	}
	for {
		if _, ok := table[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

func LoadDomains(path string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		bits := strings.Fields(strings.TrimSpace(line))
		if len(bits) == 0 {
			continue
		}

		host := normHost(bits[0])
		if host == "" {
			continue
		}
		out[host] = struct{}{}
	}
	return out, sc.Err()
}

func (p *Policy) HostAllowed(name string) bool {
	return p != nil && p.listed(name)
}

func (p *Policy) listed(name string) bool {
	name = normHost(name)
	if name == "" || emptyLabel(name) {
		return false
	}
	if _, ok := p.Hosts[name]; ok {
		return true
	}
	return HostIn(name, p.Suffix)
}

func (p *Policy) Authority(sni, host string) bool {
	auth := tlsAuthority(sni, host)
	if auth == "" {
		return false
	}
	return p.listed(auth)
}

// HostsWithKind gives a sorted list of the exact names whose line names
// kind. The list does not include "*." entries or "*".
func (p *Policy) HostsWithKind(kind string) []string {
	var out []string
	for host, kinds := range p.HostKinds {
		if _, ok := kinds[kind]; ok {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

// KindsFor gives the kinds of the one entry that is most specific to the
// name: its own exact line, else its own "*." line, else the nearest "*."
// line above it. The alternative is to unite all entries that match. With
// that alternative, the operator cannot give one name under a wildcard
// fewer kinds than the wildcard grants. Also, a narrower line from the
// operator would then widen the host. The two methods do not depend on
// order. This method is never more permissive than the most specific line
// of the operator for the name. A line that lists no kinds is also a line.
// Thus it masks the wildcard, and the lookup does not continue to the
// wildcard.
func (p *Policy) KindsFor(sni string) []string {
	host, suffix, ok := p.entry(sni)
	if !ok {
		return nil
	}
	if suffix {
		return kindList(p.SuffixKinds[host])
	}
	return kindList(p.HostKinds[host])
}

// HeadersFor uses the entry that KindsFor reads for sni. It maps each
// header that this entry declares in addition to DefaultHeaders, in
// lowercase, to the kinds that the header carries there. Thus HeadersFor
// does not accept a wildcard header for a name whose own line does not
// declare that header.
func (p *Policy) HeadersFor(sni string) map[string][]string {
	host, suffix, ok := p.entry(sni)
	if !ok {
		return nil
	}
	byKind := p.HostHeaders[host]
	if suffix {
		byKind = p.SuffixHeaders[host]
	}
	var out map[string][]string
	for kind, hdrs := range byKind {
		for h := range hdrs {
			if out == nil {
				out = map[string][]string{}
			}
			out[h] = append(out[h], kind)
		}
	}
	return out
}

// entry is the one line that is most specific to sni (KindsFor).
func (p *Policy) entry(sni string) (string, bool, bool) {
	auth := normHost(sni)
	if auth == "" || emptyLabel(auth) {
		return "", false, false
	}
	if _, ok := p.HostKinds[auth]; ok {
		return auth, false, true
	}
	// A "*." entry covers its own apex and all names under it. Hosts and
	// listed() already do the same.
	name := auth
	for {
		if _, ok := p.SuffixKinds[name]; ok {
			return name, true, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false, false
		}
		name = name[i+1:]
	}
}

func kindList(kinds map[string]struct{}) []string {
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	return out
}

func KindAllowed(kind string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if a == kind || (a == AllKinds && kind != KindCanary) {
			return true
		}
	}
	return false
}

func tlsAuthority(sni, hostHeader string) string {
	sniN := normHost(sni)
	if sniN == "" {
		return ""
	}
	hdr := strings.TrimSpace(hostHeader)
	if strings.Contains(hdr, "%") {
		return ""
	}
	if h, _, err := net.SplitHostPort(hdr); err == nil {
		hdr = h
	}
	hdr = normHost(hdr)
	// The code refuses a Host that is not a name. It does not match it label by
	// label. "0::.api.anthropic.com" fails SplitHostPort, and HostIn found
	// api.anthropic.com in it (FuzzAuthority).
	if hdr != "" && !validName(hdr) {
		return ""
	}
	if hdr != "" && hdr != sniN && !HostIn(hdr, map[string]struct{}{sniN: {}}) {
		return ""
	}
	return sniN
}

// normHost lowercases a name and removes the space around it and its
// trailing dots. It trims dots and spaces together, so the result is a
// fixed point. HostIn normalizes again a name that Allowed already
// normalized. A trim that changed "githuB.Com ." to "github.com " let the
// second pass match github.com, where the first pass had seen a different
// name (FuzzForwardAllowed found this).
func normHost(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimRightFunc(name, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
}

// emptyLabel reports a leading dot or a run of dots. The label walk would
// cut "x..a.com" to ".a.com" and then to "a.com". It would then read the
// name as a subdomain of each entry at or below the empty label.
func emptyLabel(name string) bool {
	return strings.HasPrefix(name, ".") || strings.Contains(name, "..")
}

func validKind(token string) bool {
	if token == AllKinds {
		return true
	}
	if token == "" {
		return false
	}
	r := []rune(token)
	if r[0] < 'A' || r[0] > 'Z' {
		return false
	}
	for _, c := range token {
		if !(unicode.IsUpper(c) || unicode.IsDigit(c) || c == '_') {
			return false
		}
	}
	return true
}
