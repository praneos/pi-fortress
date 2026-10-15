// Package nftsets carries the address sets of the resolver across a ruleset
// reload.
//
// `nft -f` replaces the full table. Thus resolved_v4 and its sibling sets
// for each segment come back empty. The agent VM asks the Pi for each lookup,
// so it sees no problem. A client with its own cache (systemd-resolved on
// the desk, any phone) answers from that cache and does not ask again. Thus
// the gate drops its connections until the cached TTL expires. The desk
// showed this on 2026-09-22. The code captures the elements before the load.
// After the load, it adds them again with the remaining time of each timeout.
// Thus the answers of this box stay valid for exactly the same time as
// before, and never a second longer.
//
// The parse is here and not in apply.sh, because the bugs would be in the
// element format of nft: an optional timeout for each element, and an
// optional expires, both in a unit syntax that the Go parser does not read.
package nftsets

import (
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// carried names the sets with elements that the resolver fills: resolved_v4
// of the agent, the set of the house, and one resolved_<segment>_v4 for each
// plain segment. No other set is carried. A compiled set (blacklist_v4,
// direct_ip_v4, ssh_allow_v4) comes back full from the new ruleset. If the
// code added the old elements again, it would put back exactly what the
// operator just removed from the compile.
var carried = regexp.MustCompile(`^(resolved_v4|resolved_[a-z0-9_]+_v4)$`)

// setHead matches the `set <name> {` line of an nft listing.
var setHead = regexp.MustCompile(`(?m)^[ \t]*set[ \t]+([A-Za-z0-9_]+)[ \t]*\{`)

// Element is one address and the remaining life that nft gives for it in the set.
type Element struct {
	Addr      string
	Remaining time.Duration
}

// Set is the elements of one set, under the name of the set that they came
// from. The name stays with them, because the answers of a segment must
// never go into the set of a different segment. That is the reason for one
// set for each segment, and not one shared set (internal/render/ruleset.go,
// the comment above the house set and the one above the per-segment set).
type Set struct {
	Name     string
	Elements []Element
}

// Carried reports if this package moves the set with this name.
func Carried(name string) bool { return carried.MatchString(name) }

// SetNames gets the set names from `nft list sets table inet fortress`, in
// the order that the listing printed them. In some nft versions, that listing
// also has elements, not only declarations. This is not important here: the
// code reads only the head lines.
func SetNames(out string) []string {
	m := setHead.FindAllStringSubmatch(out, -1)
	names := make([]string, 0, len(m))
	for _, g := range m {
		names = append(names, g[1])
	}
	return names
}

// ParseDuration reads the nft format of a duration: a sequence of
// <number><unit> pairs, most significant first, as in `1d2h3m4s`, `2h`,
// `1h58m12s` or `500ms`. time.ParseDuration cannot read it. Go has no day
// or week unit, and nft prints days when an element has more than 24h left.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	units := []struct {
		name string
		d    time.Duration
	}{
		// Longest first: `ms` must win over `m`. If not, 500ms reads as
		// eight minutes and an element lives longer than its answer.
		{"ms", time.Millisecond},
		{"us", time.Microsecond},
		{"ns", time.Nanosecond},
		{"w", 7 * 24 * time.Hour},
		{"d", 24 * time.Hour},
		{"h", time.Hour},
		{"m", time.Minute},
		{"s", time.Second},
	}
	var total time.Duration
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i {
			return 0, fmt.Errorf("duration %q: no number at %q", s, s[i:])
		}
		n, err := strconv.ParseInt(s[i:j], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("duration %q: %w", s, err)
		}
		k := j
		for k < len(s) && s[k] >= 'a' && s[k] <= 'z' {
			k++
		}
		unit := s[j:k]
		var mul time.Duration
		for _, u := range units {
			if unit == u.name {
				mul = u.d
				break
			}
		}
		if mul == 0 {
			return 0, fmt.Errorf("duration %q: unknown unit %q", s, unit)
		}
		total += time.Duration(n) * mul
		i = k
	}
	return total, nil
}

// ParseSet reads one `nft list set inet <table> <name>` listing: the timeout
// of the set, and each element with its remaining time.
//
// ParseSet keeps an element only when nft gives its remaining time:
// `expires` if it is there, and if not, the `timeout` of the element. It
// drops an element with neither. It does not guess. An add again would have
// to make up a life. A bare add gets the full 2h of the set. That is the
// "resolved once, allowed forever" that the gate must prevent. For the same
// reason, ParseSet clamps each remaining time to the declared timeout of the
// set. For all listings, no carried element can live longer than an
// address that the resolver gives today.
func ParseSet(out string) (Set, error) {
	var s Set
	if m := setHead.FindStringSubmatch(out); m != nil {
		s.Name = m[1]
	}
	setTimeout := time.Duration(0)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "timeout" {
			if d, err := ParseDuration(f[1]); err == nil {
				setTimeout = d
			}
			break
		}
	}
	body, ok := elementsBody(out)
	if !ok {
		// An empty set prints no elements line. This is not an error: all
		// sets are like this immediately after a reload.
		return s, nil
	}
	for _, item := range strings.Split(body, ",") {
		f := strings.Fields(item)
		if len(f) == 0 {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil || !addr.Is4() {
			// Garbage, or an IPv6 element in a set that the gate fills
			// only with v4. Skip it. It is not fatal: one unreadable element
			// must not make the full segment lose its set.
			continue
		}
		var expires, timeout time.Duration
		var haveExpires, haveTimeout bool
		for i := 1; i+1 < len(f); i++ {
			d, err := ParseDuration(f[i+1])
			if err != nil {
				continue
			}
			switch f[i] {
			case "expires":
				expires, haveExpires = d, true
			case "timeout":
				timeout, haveTimeout = d, true
			}
		}
		left := expires
		if !haveExpires {
			if !haveTimeout {
				continue
			}
			left = timeout
		}
		if setTimeout > 0 && left > setTimeout {
			left = setTimeout
		}
		if left < time.Second {
			// Under a second, there is nothing to carry. A sub-second
			// remaining time would round to `timeout 0s`. nft reads that
			// as no timeout.
			continue
		}
		s.Elements = append(s.Elements, Element{Addr: addr.String(), Remaining: left})
	}
	return s, nil
}

// elementsBody returns the text between `elements = {` and its closing
// brace. It skips quoted text. Thus a comment with a brace cannot make
// the list shorter.
func elementsBody(out string) (string, bool) {
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return "", false
	}
	rest := out[i+len("elements = {"):]
	inQuote := false
	for j := 0; j < len(rest); j++ {
		switch rest[j] {
		case '\\':
			j++
		case '"':
			inQuote = !inQuote
		case '}':
			if !inQuote {
				return rest[:j], true
			}
		}
	}
	// No closing brace: a truncated listing. Use what is there, not
	// nothing. Each element in it must still parse independently.
	return rest, true
}

// Format writes the carry file: one `<set> <address> <seconds>` row for
// each element under a `saved <unix>` header. Restore runs after the load
// and must subtract the time of the reload from each remaining time. The
// carry must not give an element a longer life than it had at capture.
func Format(w io.Writer, savedAt time.Time, sets []Set) error {
	if _, err := fmt.Fprintf(w, "# pi-fortress resolved-address sets, carried across a ruleset reload\nsaved %d\n", savedAt.Unix()); err != nil {
		return err
	}
	var b strings.Builder
	for _, s := range sets {
		if !Carried(s.Name) {
			continue
		}
		for _, e := range s.Elements {
			fmt.Fprintf(&b, "%s %s %d\n", s.Name, e.Addr, int64(e.Remaining/time.Second))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Parse reads back what Format wrote. It makes each remaining time shorter
// by the time since the capture. It drops an element with a life that
// expired between, so that element never gets to the kernel.
//
// If the clock went backwards, the elapsed time is negative. Parse uses
// zero. Thus the worst result of a clock jump is that an element keeps the
// life it already had, never more.
func Parse(r io.Reader, now time.Time) ([]Set, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var savedAt time.Time
	byName := map[string]*Set{}
	var order []string
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if f[0] == "saved" && len(f) == 2 {
			sec, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("carry line %d: %w", n+1, err)
			}
			savedAt = time.Unix(sec, 0)
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("carry line %d: want '<set> <address> <seconds>', got %q", n+1, line)
		}
		if !Carried(f[0]) {
			// The save half writes the file a few seconds earlier, and root
			// reads it. But a set name goes from it to `nft add element`.
			// Thus the code also checks it here and does not trust it.
			return nil, fmt.Errorf("carry line %d: %q is not a resolved-address set", n+1, f[0])
		}
		addr, err := netip.ParseAddr(f[1])
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("carry line %d: %q is not an IPv4 address", n+1, f[1])
		}
		sec, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("carry line %d: %w", n+1, err)
		}
		left := time.Duration(sec) * time.Second
		if !savedAt.IsZero() {
			if gone := now.Sub(savedAt); gone > 0 {
				left -= gone
			}
		}
		if left < time.Second {
			continue
		}
		s := byName[f[0]]
		if s == nil {
			s = &Set{Name: f[0]}
			byName[f[0]] = s
			order = append(order, f[0])
		}
		s.Elements = append(s.Elements, Element{Addr: addr.String(), Remaining: left.Round(time.Second)})
	}
	sets := make([]Set, 0, len(order))
	for _, name := range order {
		sets = append(sets, *byName[name])
	}
	return sets, nil
}

// batch is the number of elements in one `add element` statement. The full
// script is one nft transaction in all cases. This only keeps one statement
// short enough to read in a journal when it fails.
const batch = 256

// Script builds the nft input that adds the carried elements again. Only the
// sets named in keep (the sets that the new ruleset still has) get a
// statement. Thus Script discards the elements for a segment that the
// operator just deleted. It returns the script and the number of elements
// that it adds.
func Script(table string, sets []Set, keep map[string]bool) (string, int) {
	var b strings.Builder
	n := 0
	for _, s := range sets {
		if !Carried(s.Name) || !keep[s.Name] {
			continue
		}
		for i := 0; i < len(s.Elements); i += batch {
			j := i + batch
			if j > len(s.Elements) {
				j = len(s.Elements)
			}
			fmt.Fprintf(&b, "add element %s %s { ", table, s.Name)
			for k, e := range s.Elements[i:j] {
				if k > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "%s timeout %ds", e.Addr, int64(e.Remaining/time.Second))
				n++
			}
			b.WriteString(" }\n")
		}
	}
	return b.String(), n
}
