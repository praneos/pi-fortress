package fence

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// onePass is more than the search of one full scan: the stream holds at
// most about maxHold and one window, and a read adds to that.
const onePass = maxHold + 2*window

// budgetRead streams body through a token stream in reads of n bytes.
// After each read, the search must be in the budget, with one full scan
// more at most. Thus a stream without the budget fails fast, and the test
// does not wait for minutes. low is the least credit after a read.
func budgetRead(t *testing.T, ts *tokenSet, body string, n int) (s *tokenStream, out []byte, low int64, err error) {
	t.Helper()
	s = newTokenStream(&stepReader{src: []byte(body), n: n}, ts, false)
	low = scanSlack
	p := make([]byte, 32<<10)
	for {
		k, err := s.Read(p)
		out = append(out, p[:k]...)
		if lim := scanPerByte*s.in + scanSlack + onePass; s.work > lim {
			t.Fatalf("reads of %d: %d bytes of search after %d body bytes, budget %d", n, s.work, s.in, lim)
		}
		low = min(low, s.credit)
		if err == io.EOF {
			return s, out, low, nil
		}
		if err != nil {
			return s, out, low, err
		}
	}
}

// A body with a prefix every few bytes, in reads of one byte, makes the
// stream search about one window again for each byte. The stream stops at
// its work budget with ErrScanBudget, long before the end of the body.
// Each byte that went out before the stop is a scanned byte of the body.
// After the stop, each read gives the same error.
func TestStreamStopsAtScanBudget(t *testing.T) {
	ts := benchTokenSet(t)
	for _, body := range []string{
		strings.Repeat("ghp_", 16<<10),
		strings.Repeat("ghp_x-", 11<<10),
	} {
		s, out, _, err := budgetRead(t, ts, body, 1)
		if !errors.Is(err, ErrScanBudget) {
			t.Fatalf("%.12q: err %v after %d of %d bytes, want ErrScanBudget", body, err, s.in, len(body))
		}
		if s.in > int64(len(body)/4) {
			t.Fatalf("%.12q: stop after %d of %d bytes", body, s.in, len(body))
		}
		if !strings.HasPrefix(body, string(out)) || int64(len(out)) > s.in {
			t.Fatalf("%.12q: %d bytes out of %d in are not the head of the body", body, len(out), s.in)
		}
		if n, err := s.Read(make([]byte, 16)); n != 0 || !errors.Is(err, ErrScanBudget) {
			t.Fatalf("%.12q: read after the stop: %d, %v", body, n, err)
		}
	}
}

// Ordinary bodies stay far from the budget, also in reads of one byte:
// JSON with a token in it here and there or in each 150 bytes, prefixes
// that do not complete a token, long tokens, and a body that is only
// tokens in reads of a TCP segment. None uses more than half of the
// credit, and its strip is the strip of the buffered path.
func TestScanBudgetLeavesOrdinaryBodies(t *testing.T) {
	ts := benchTokenSet(t)
	ant := "sk-ant-api03-" + strings.Repeat("Ab3", 31) + "xyzAA"
	cut := func(s string) string { return s[:32<<10] }
	for _, c := range []struct {
		name string
		body string
		n    int
	}{
		{"json", cut(benchTokenBody()), 1},
		{"json, dense tokens", cut(strings.Repeat(`{"k":"`+ant+`","v":"some text here and more"},`, 300)), 1},
		{"prefix noise", cut(benchPrefixNoiseBody()), 1},
		{"long tokens", cut(strings.Repeat("ghp_"+strings.Repeat("a", 3500)+" ", 10)), 1},
		{"only tokens", strings.Repeat("ghp_"+strings.Repeat("A", 36)+" ", 3000), 1448},
		{"only prefixes", strings.Repeat("ghp_", 32<<10), 1448},
	} {
		_, out, low, err := budgetRead(t, ts, c.body, c.n)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if low < scanSlack/2 {
			t.Fatalf("%s: the credit went down to %d of %d", c.name, low, scanSlack)
		}
		if want := ts.replace([]byte(c.body), stripRepl); string(out) != string(want) {
			t.Fatalf("%s: stream and buffered disagree (%d vs %d bytes)", c.name, len(out), len(want))
		}
	}
}
