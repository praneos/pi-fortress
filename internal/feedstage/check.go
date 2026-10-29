package feedstage

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"pi-fortress/internal/policycompile"
)

// Kind is the grammar of one staged list.
type Kind int

const (
	// KindIPs is an IPv4 address or prefix, as policycompile.ParseIPv4
	// writes it.
	KindIPs Kind = iota
	// KindBlockDomains is a name, or an IPv4 address as a name list can
	// hold one (policycompile kind "block_domains").
	KindBlockDomains
	// KindNames is a name only (policycompile kind "names"), the house.
	KindNames
)

func (k Kind) String() string {
	switch k {
	case KindIPs:
		return "an IPv4 address or prefix"
	case KindBlockDomains:
		return "a domain or an IPv4 address"
	}
	return "a domain"
}

// lineMax is the longest line of the kind: "255.255.255.0/24" for an
// address, 253 for a name.
func (k Kind) lineMax() int {
	if k == KindIPs {
		return len("255.255.255.255/32")
	}
	return 253
}

// mapLineMax is the longest line of feeds.map: a name, a TAB and a feed id.
const mapLineMax = 253 + 1 + 64

// byteCap is the most bytes that lines lines of lineMax bytes each, with
// their newlines, can have. Root reads no more of a staged file than a
// file that can pass, and never more than hard.
func byteCap(lines, lineMax int, hard int64) int64 {
	n := int64(lines) * int64(lineMax+1)
	if n < 0 || n > hard {
		return hard
	}
	return n
}

// countLines counts the lines of a text that ends with a newline. It
// makes no copy, so a check can refuse a file over its line cap before it
// splits the file.
func countLines(text []byte) int {
	return bytes.Count(text, []byte{'\n'})
}

// allowed says if c can be in a line of the kind. The parser gives the
// final answer. This check comes first, so that a control byte, a space
// or a byte of a different encoding gets a clear reason.
func (k Kind) allowed(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c == '.':
		return true
	case k == KindIPs:
		return c == '/'
	}
	return c >= 'a' && c <= 'z' || c == '-'
}

// CheckLine says why line is not a staged line of the kind, or "". A line
// passes only when the parser of pf compile accepts it and gives back the
// same bytes. Thus each line is in the one form that pf fetch writes.
func CheckLine(k Kind, line string) string {
	if line == "" {
		return "empty line"
	}
	if len(line) > k.lineMax() {
		return fmt.Sprintf("longer than %d bytes", k.lineMax())
	}
	for i := 0; i < len(line); i++ {
		if !k.allowed(line[i]) {
			return fmt.Sprintf("byte 0x%02x at %d is not allowed", line[i], i+1)
		}
	}
	var got string
	var ok bool
	switch k {
	case KindIPs:
		got, ok = policycompile.ParseIPv4(line)
	case KindBlockDomains:
		got, ok = policycompile.ParseToken("block_domains", line)
	default:
		got, ok = policycompile.ParseToken("names", line)
	}
	if !ok {
		return "not " + k.String()
	}
	if got != line {
		return "not in canonical form"
	}
	// pf fetch never keeps a name under .local or .localhost.
	if k != KindIPs && (strings.HasSuffix(line, ".local") || strings.HasSuffix(line, ".localhost")) {
		return "a .local or .localhost name"
	}
	return ""
}

// CheckList checks a staged list and gives its lines. The text is empty
// (an empty list) or ends with a newline. max caps the number of lines; a
// text over the cap is refused before it is split. A line that repeats is
// refused: pf fetch writes each entry once.
func CheckList(k Kind, text []byte, max int) ([]string, error) {
	if len(text) == 0 {
		return nil, nil
	}
	if text[len(text)-1] != '\n' {
		return nil, fmt.Errorf("no newline at the end")
	}
	if n := countLines(text); n > max {
		return nil, fmt.Errorf("%d lines, more than the cap of %d", n, max)
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	seen := make(map[string]struct{}, len(lines))
	for i, l := range lines {
		if why := CheckLine(k, l); why != "" {
			return nil, fmt.Errorf("line %d: %s", i+1, why)
		}
		if _, dup := seen[l]; dup {
			return nil, fmt.Errorf("line %d: repeats an earlier line", i+1)
		}
		seen[l] = struct{}{}
	}
	return lines, nil
}

// CheckMap checks a staged feeds.map: "<item>\t<feed id>" lines. Each item
// is in items (the staged lists). Each id is a feed of ids. An item can
// repeat only with the same id: pf fetch writes an item once for each list
// that has it. max caps the lines; a text over the cap is refused before
// it is split.
func CheckMap(text []byte, items map[string]struct{}, ids map[string]bool, max int) error {
	if len(text) == 0 {
		return nil
	}
	if text[len(text)-1] != '\n' {
		return fmt.Errorf("no newline at the end")
	}
	if n := countLines(text); n > max {
		return fmt.Errorf("%d lines, more than the %d entries of the lists", n, max)
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	feedOf := make(map[string]string, len(lines))
	for i, l := range lines {
		item, id, ok := strings.Cut(l, "\t")
		if !ok || strings.Contains(id, "\t") {
			return fmt.Errorf("line %d: not one item, one TAB and one feed id", i+1)
		}
		if _, ok := items[item]; !ok {
			return fmt.Errorf("line %d: the item is in no staged list", i+1)
		}
		if !ValidFeedID(id) || !ids[id] {
			return fmt.Errorf("line %d: not a feed id of sources.json", i+1)
		}
		if was, dup := feedOf[item]; dup && was != id {
			return fmt.Errorf("line %d: the item names a second feed", i+1)
		}
		feedOf[item] = id
	}
	return nil
}

// reportVerbs are the first words of the lines of a fetch report.
var reportVerbs = map[string]bool{
	"OK": true, "STALE": true, "FAIL": true, "SKIP": true,
	"WARN": true, "TRUNCATED": true, "REDIRECT": true,
}

const (
	reportLineMax = 512
	reportLines   = 4000
)

// FilterReport gives the lines of a staged report that root keeps. The
// report is text for the operator, and part of it comes from the feed
// servers (a redirect URL, the text of a TLS error). Each byte outside
// 0x20 to 0x7e becomes '?'. A line is cut at 512 bytes. A line whose first
// word is not a report verb goes, and so do the lines after the first
// 4000. Root does not refuse a set for its report: the report carries the
// reason of a failure.
func FilterReport(text []byte) []string {
	var out []string
	for line := range strings.SplitSeq(string(text), "\n") {
		if len(out) == reportLines {
			break
		}
		l := strings.TrimRight(Clean(line), " ")
		verb, _, _ := strings.Cut(l, " ")
		if !reportVerbs[verb] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// Clean is the byte filter of a report line: each byte outside 0x20 to
// 0x7e becomes '?', and the text is cut at 512 bytes. Each text that root
// prints from an import goes through it.
func Clean(s string) string {
	b := []byte(s)
	if len(b) > reportLineMax {
		b = b[:reportLineMax]
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// sample gives the first name of a staged domain list that is not an
// address. The lab and status.sh use it to check the sinkhole.
func sample(domains []string) string {
	for _, d := range domains {
		if _, err := netip.ParseAddr(d); err != nil {
			return d
		}
	}
	return ""
}

func lines(items []string) []byte {
	if len(items) == 0 {
		return nil
	}
	return []byte(strings.Join(items, "\n") + "\n")
}
