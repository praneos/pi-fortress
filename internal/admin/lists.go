package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pi-fortress/internal/fetch"
	"pi-fortress/internal/policycompile"
)

var (
	// AgentLists carries dns_types.allow after the lists of the policed tier.
	// The list belongs to the resolver, not to the compiler. Thus policycompile
	// has no row for it.
	AgentLists = append(listNames(policycompile.SegmentFor(policycompile.DenyByDefault)), DNSTypesList)
	HouseLists = listNames(policycompile.SegmentFor(policycompile.AllowByDefault))
	errList    = errors.New("unknown list")
	errToken   = errors.New("invalid token")
)

// kindDNSTypes is the token kind of dns_types.allow: a full "name TYPE..."
// line, not one word.
const kindDNSTypes = "dns_types"

func listNames(seg policycompile.SegmentPolicy) []string {
	lists := seg.Lists()
	out := make([]string, 0, len(lists))
	for _, l := range lists {
		out = append(out, l.Name)
	}
	return out
}

// listKind walks the policed tier for a list and says how its tokens parse.
// direct_ip.allow also holds addresses. Its suffix tells its purpose, not
// its contents. That is why the table gives the answer, and not the name.
func listKind(name string) (string, bool) {
	if name == DNSTypesList {
		return kindDNSTypes, true
	}
	for _, seg := range policycompile.Segments {
		for _, l := range seg.Lists() {
			if l.Name == name {
				return l.Kind, true
			}
		}
	}
	return "", false
}

func knownList(name string) bool {
	_, ok := listKind(name)
	return ok
}

func ValidateToken(list, value string) (string, error) {
	kind, known := listKind(list)
	if !known {
		kind = "domains"
		if strings.HasSuffix(list, ".ips") {
			kind = "ips"
		}
	}
	var got string
	var ok bool
	switch kind {
	// A full line, and the one kind that gives the reason for a refusal. A type
	// with a spelling error is the typo that this list on the seat must catch.
	case kindDNSTypes:
		got, err := CheckDNSTypesLine(value)
		if err != nil {
			return "", fmt.Errorf("%w: %v", errToken, err)
		}
		return got, nil
	// An allow list undoes a drop, so it takes /24 at widest.
	case "allow_ips":
		got, ok = policycompile.ParseAllowIPv4(value)
	case "ssh_ips":
		got, ok = policycompile.ParseSSHIPv4(value)
	case "host_ips":
		got, ok = policycompile.ParseHostIPv4(value)
	case "endpoints":
		got, ok = policycompile.ParseEndpoint(value)
	case "ips":
		got, ok = policycompile.ParseIPv4(value)
	default:
		got, ok = policycompile.ParseDomain(value)
	}
	if !ok {
		return "", errToken
	}
	return got, nil
}

func (c *Config) listPath(name string) string { return filepath.Join(c.PolicyDir, name) }

// List returns the tokens of one overlay. It drops comments and blank lines.
func (c *Config) List(name string) ([]string, error) {
	if !knownList(name) {
		return nil, errList
	}
	lines, err := readLines(c.listPath(name))
	if err != nil {
		return nil, err
	}
	items := []string{}
	for _, line := range lines {
		if tok := policycompile.StripLine(line); tok != "" {
			items = append(items, tok)
		}
	}
	return items, nil
}

func (c *Config) ListAdd(name, value string) error {
	return c.listEdit(name, value, addToken)
}

func (c *Config) ListRemove(name, value string) error {
	// The check refuses a hand-edited dns_types.allow line, but the line is
	// still a row on the screen. The operator deletes it to fix it. Thus this
	// one list removes, by its text, a line that it would not add.
	if name == DNSTypesList {
		if _, err := CheckDNSTypesLine(value); err != nil {
			tok := policycompile.StripLine(value)
			if tok == "" {
				return errToken
			}
			return c.withEditLock(func() error {
				lines, err := readLines(c.listPath(name))
				if err != nil {
					return err
				}
				return writeLines(c.listPath(name), removeToken(lines, tok, lineKey(kindDNSTypes)))
			})
		}
	}
	return c.listEdit(name, value, removeToken)
}

// addToken appends after the last live token, not at the end of the file.
// Thus a trailing note block stays at the bottom. A token that is present
// only as a comment is a candidate, not an entry. The code does not touch
// it and adds a live line.
func addToken(lines []string, tok string, key func(string) string) []string {
	last := -1
	for i, l := range lines {
		switch key(l) {
		case tok:
			return lines
		case "":
		default:
			last = i
		}
	}
	if last < 0 {
		return append(lines, tok)
	}
	return slices.Insert(lines, last+1, tok)
}

func removeToken(lines []string, tok string, key func(string) string) []string {
	return slices.DeleteFunc(lines, func(l string) bool { return key(l) == tok })
}

// lineKey is the form of a file line that the code compares to a token. For
// a one-word list, that is the line without its comment. People write a
// dns_types.allow line by hand as often as the seat writes it. Thus
// "Example.com  txt" must match the "example.com TXT" that the check gives
// back. If not, a delete of the row on the screen would delete nothing.
func lineKey(kind string) func(string) string {
	return func(l string) string {
		tok := policycompile.StripLine(l)
		if kind == kindDNSTypes && tok != "" {
			if canon, err := CheckDNSTypesLine(tok); err == nil {
				return canon
			}
		}
		return tok
	}
}

// listEdit writes the file again, one line at a time. Comments, blank lines
// and the order of all lines that the edit does not touch stay the same.
func (c *Config) listEdit(name, value string, fn func([]string, string, func(string) string) []string) error {
	kind, known := listKind(name)
	if !known {
		return errList
	}
	tok, err := ValidateToken(name, value)
	if err != nil {
		return err
	}
	return c.withEditLock(func() error {
		lines, err := readLines(c.listPath(name))
		if err != nil {
			return err
		}
		return writeLines(c.listPath(name), fn(lines, tok, lineKey(kind)))
	})
}

// FetchReport returns the lines of generated/fetch.report.
func (c *Config) FetchReport() []string {
	return c.FetchStatus().Lines
}

// StaleAfter is the age at which a blocklist is no longer current. The
// refresh timer runs daily. Thus an age of more than three days means that
// three runs in a row did not occur at all: a dead timer or a box that was
// off. That is a different fault from a feed that answered badly and says
// so.
const StaleAfter = 72 * time.Hour

// FetchStatus is the data that the Feeds screen and the title bar need to
// say whether the blocklist is current. The report alone cannot do this.
// Each run writes it again, and it has no date. Thus a report full of OK
// lines reads the same whether it was written an hour ago or in March. The
// mtime of the file is the missing half.
type FetchStatus struct {
	Lines []string
	When  time.Time
	Age   time.Duration
	// Ran is false when no fetch has ever written a report.
	Ran   bool
	Fail  int
	Stale int
	// Truncated counts the lists that their cap in sources.json cut.
	Truncated int
}

func (c *Config) FetchStatus() FetchStatus {
	path := filepath.Join(c.PolicyDir, "generated", "fetch.report")
	var st FetchStatus
	// The code reports a report that cannot be read as no report at all. The
	// caller is a status line, and Ran below says so.
	lines, _ := readLines(path)
	for _, l := range lines {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		st.Lines = append(st.Lines, l)
		switch verb, _, _ := strings.Cut(l, " "); verb {
		case "FAIL":
			st.Fail++
		case "STALE":
			st.Stale++
		case "TRUNCATED":
			st.Truncated++
		}
	}
	if fi, err := os.Stat(path); err == nil {
		st.When = fi.ModTime()
		st.Ran = true
		st.Age = c.now().Sub(st.When)
	}
	return st
}

// Warning is the one line that an operator must see from all screens, or ""
// when the blocklist is current. The line names a feed that fell back to its
// last copy as such, not as an error. The lists are intact, but they are not
// from today. An operator who cannot see the difference will eventually
// ignore both.
func (s FetchStatus) Warning() string {
	switch {
	case !s.Ran:
		return "feeds: never fetched; blocklist is whatever shipped"
	case s.Fail > 0 && s.Stale > 0:
		return fmt.Sprintf("feeds: %d failed, %d serving the last good copy (fetched %s)", s.Fail, s.Stale, fetch.Ago(s.Age))
	case s.Fail > 0:
		return fmt.Sprintf("feeds: %d failed with nothing to fall back on (fetched %s)", s.Fail, fetch.Ago(s.Age))
	case s.Stale > 0:
		return fmt.Sprintf("feeds: %d serving the last good copy (fetched %s)", s.Stale, fetch.Ago(s.Age))
	case s.Truncated > 0:
		return fmt.Sprintf("feeds: %d lists cut to their cap in sources.json (fetched %s)", s.Truncated, fetch.Ago(s.Age))
	case s.Age > StaleAfter:
		return fmt.Sprintf("feeds: last fetched %s; the refresh timer is not running", fetch.Ago(s.Age))
	}
	return ""
}
