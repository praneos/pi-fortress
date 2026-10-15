// Package dnslog is the query log of the resolver: one row for each DNS
// transaction, written as JSON.
//
// Before, it used the dnsmasq format: a query line and a reply line for
// each transaction. The reader paired them by name, because the reply had
// no source, no qtype and no id. That shape and its pairing were removed
// with the flag that could still select dnsmasq as the resolver. Refer to
// the Event doc below.
package dnslog

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Event is one completed DNS transaction: the question, the client that
// asked it, and the verdict, in one row.
//
// The two-line format above this cannot show that. A reply line has no
// source, no qtype and no query id. Thus a reader that pairs it to a query
// can pair only on the name. Two clients that ask the same name at the same
// time are one name in its table. A query with a reply that never arrives
// stays held until a cap or a flush changes it into a row. That row tells
// that the name was not resolved, but it was. One row for each transaction
// removes the pairing. It does not improve it.
//
// JSON also quotes and escapes. Thus the Valid rule above does not apply
// here. That rule drops a record with whitespace in it, because the text
// format would read it back as a different record. A name that the old
// format could not log correctly, this format can.
type Event struct {
	T      string `json:"t"`                // base.ISO, UTC
	Src    string `json:"src"`              // client address, no port
	Name   string `json:"name,omitempty"`   // as asked, trailing dot stripped
	QType  string `json:"qtype,omitempty"`  // "A", "AAAA", "TYPE65"
	Act    string `json:"act"`              // the verdict; one of the Act constants
	Answer string `json:"answer,omitempty"` // first address, for the operator
	Seg    string `json:"seg,omitempty"`    // "" is the agent segment
	N      int    `json:"n,omitempty"`      // ActSuppressed only: queries counted
	Listed bool   `json:"listed,omitempty"` // ActSuppressed only: the sinkhole-list bucket
	// Candidate is for ActSuppressed only: the bucket for tunnel-shaped
	// queries (a TXT or NULL, or a label of 16 or more). It is separate,
	// so short names cannot use the rows that the tunnel heuristic reads.
	Candidate bool `json:"candidate,omitempty"`
	// Rule is the key rule in a refused name (key_prefixes.rules), or
	// "placeholder". Name is then only the zone that it was for.
	Rule string `json:"rule,omitempty"`
}

// The verdicts. The text format wrote these as a verb and an answer field
// together. "config NAME is 0.0.0.0" meant blocked. The reader had to know
// that "config" plus an unspecified address was policy, and "config" plus
// a real address was a fixture. Here the row gives the verdict, and the
// address is only the address.
const (
	// ActResolved is an answer that came back with data in it, from
	// upstream, the cache or a configured fixture.
	ActResolved = "resolved"
	// ActBlocked is the sinkhole or paranoid mode: a name that the box
	// decided not to resolve. The answer is the unspecified address.
	// The gate and the operator both need this row.
	ActBlocked = "blocked"
	// ActFiltered is policy that suppresses a query and does not answer
	// it: a type that is always filtered (AAAA, HTTPS, SVCB), or a query
	// for a listed name with a type that the sinkhole has no record of.
	// No address was returned, so there is no contact to block. That
	// is why it is not ActBlocked.
	ActFiltered = "filtered"
	// ActNodata is an ordinary empty answer: the name exists and has
	// no data of the requested type. Policy did not act.
	ActNodata = "nodata"
	// ActNXDomain is a name error, from upstream or from the
	// domain-needed and bogus-priv rules. Those never leave the box.
	ActNXDomain = "nxdomain"
	// ActServfail is a failure to make an answer: the upstream did not
	// reply, its answer did not parse, or the gate set refused the
	// addresses in it.
	ActServfail = "servfail"
	// ActRefused is a query that this resolver does not implement, or one
	// that the upstream answered with REFUSED. The text format had no word
	// for it: the reply line was not written. Thus a refusal looked like a
	// query with an answer that had not arrived yet.
	//
	// Only the refusals after the resolver admits the query use this. The
	// refusals decided before that still return and log nothing: a
	// non-query opcode, a second question, a malformed question, or an
	// EDNS version that this resolver does not support.
	ActRefused = "refused"
	// ActDropped is a query that got no response. The text format left a
	// query line with nothing after it. The reader could not tell that
	// apart from a reply that it had not read yet.
	ActDropped = "dropped"
	// ActSuppressed is the summary of the resolver that counts the
	// queries from one source that its log budget dropped. It has N and
	// Listed, and no Name or QType.
	ActSuppressed = "suppressed"
)

// clean changes a field to valid UTF-8. encoding/json does this silently
// on output: it puts U+FFFD for each byte sequence that is not valid
// UTF-8. Without clean, a row would not read back the same. The
// round-trip property of this format would then apply only to
// well-formed input. A DNS name is bytes, not UTF-8, and a client selects
// them. Thus the code cannot assume UTF-8. When clean does the change
// openly, what the code writes is what parses back.
func clean(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// EventLine renders ev as its one line in a JSONL log. Unlike Line,
// it has no validity rule that drops a record. A field with
// whitespace, quotes or backslashes does a round trip with no change.
func EventLine(ev Event) string {
	ev.Src, ev.Name, ev.QType = clean(ev.Src), clean(ev.Name), clean(ev.QType)
	ev.Act, ev.Answer, ev.Seg = clean(ev.Act), clean(ev.Answer), clean(ev.Seg)
	ev.T, ev.Rule = clean(ev.T), clean(ev.Rule)
	b, err := json.Marshal(ev)
	if err != nil {
		// Event holds nothing that json cannot marshal, so this code
		// does not run. To drop the line is still better than a panic in
		// a resolver.
		return ""
	}
	return string(b)
}

// ParseEvent reads a JSONL row. Its only strict shape rule is that a row
// with no verdict is not an event. A reader that accepted one would count
// it under the meaning of its zero value.
func ParseEvent(line string) (Event, bool) {
	var ev Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return Event{}, false
	}
	if ev.Act == "" {
		return Event{}, false
	}
	return ev, true
}

// Reader changes a log into Events. It is all that a reader needs: give
// it lines, and flush it at the end of a pass.
//
// It holds nothing between lines. Before, it did. The dnsmasq log used a
// query line and a reply line for one transaction, with no source, qtype
// or id on the reply. Thus a reader had to pair them by name and guess
// which client asked. That pairing state was removed with the format that
// needed it. A row is a transaction. A reader that holds nothing cannot
// give a row to the wrong client.
//
// A Reader is not safe for concurrent use. It is for one pass over one
// file.
type Reader struct{}

// Feed returns the events that line completes: one for a row, none for
// all other lines. Feed skips a line that the parser refuses. It does not
// fail the pass. A log can still hold text lines written before the
// cutover. One unreadable line must not cause the loss of the rest.
func (r *Reader) Feed(line string) []Event {
	line = strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(line, "{") {
		return nil
	}
	if ev, ok := ParseEvent(line); ok {
		return []Event{ev}
	}
	return nil
}

// ActOf maps an answer to a verdict. The answer is the first address or,
// when there is none, the rcode. It is for a writer that has only the
// answer (a forwarder or the cache). Thus it is a guess. That is why the
// verdict is a separate field on the row. A reader does not calculate it
// again here.
//
// One guess is important: an upstream that really answers 0.0.0.0 reads
// as blocked, because the sinkhole answers with the same address. A writer
// that knows the verdict for certain (the sinkhole, the filters and
// paranoid mode all do) gives the verdict and does not call this.
func ActOf(answer string) string {
	switch answer {
	case "NXDOMAIN":
		// Upstream name errors and the NXDOMAIN of the sinkhole are one
		// answer here. The reader always selected NXDOMAIN for this, so
		// that a typo does not count as a block.
		return ActNXDomain
	case "SERVFAIL", "FORMERR", "NOTIMP":
		// A FORMERR or NOTIMP from upstream is a failure to make an answer
		// to a question that this resolver built. It is not a verdict on it.
		return ActServfail
	case "REFUSED":
		return ActRefused
	case "NODATA":
		return ActNodata
	case "0.0.0.0", "::":
		return ActBlocked
	}
	// All other rcodes. The resolver writes them as RCODE<n>. An answer
	// with an address in it never starts with a letter.
	if strings.HasPrefix(answer, "RCODE") {
		return ActServfail
	}
	return ActResolved
}

// Flush reports what the reader still holds. That is nothing. Flush
// stays, so that a caller cannot forget it, and so that the code states
// the property and does not assume it.
func (r *Reader) Flush() []Event { return nil }
