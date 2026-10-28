package fence

import (
	"bufio"
	"bytes"
	"io"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/tokenrules"
)

// leadCase is the prefix of a rule with a lead (a leading \b in
// key_prefixes.rules) after a word byte, and directly after that prefix, the
// token of a different rule. The lead of the first rule fails, so the
// buffered path does not match it. It strips the token after it.
type leadCase struct {
	name string
	// head is the prefix of the rule with a lead. Word bytes make it
	// tokenrules.LeadMax bytes long when it is shorter. Then the token starts
	// LeadMax bytes after the prefix, and a cut of the stream at the token
	// keeps the prefix as the first byte of the context.
	head, tok string
}

// leadCases is each rule with a lead, followed by the token of each other
// rule.
func leadCases(t *testing.T) []leadCase {
	t.Helper()
	shapes := keyShapes()
	tokOf := map[string]string{}
	for _, s := range shapes {
		tokOf[s.rule] = s.make(0)
	}
	seen := map[string]bool{}
	var out []leadCase
	for _, r := range loadShippedRules(t).Rules {
		if !strings.HasPrefix(r.Expr, `\b`) || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		head := tokOf[r.Name][:len(r.Head())]
		if len(head) < tokenrules.LeadMax {
			head += strings.Repeat("B", tokenrules.LeadMax-len(head))
		}
		// Each token is 60 bytes longer than its minimum. Thus the run after
		// the prefix is long enough for the rule of that prefix too.
		for _, s := range shapes {
			if s.rule != r.Name {
				out = append(out, leadCase{r.Name + "+" + s.rule, head, s.make(60)})
			}
		}
	}
	if len(seen) < 6 || len(out) < 100 {
		t.Fatalf("%d rules with a lead, %d cases: the rules file changed", len(seen), len(out))
	}
	return out
}

// leadBody is c at offset at, after a word byte, and enough text after it
// to move the window of the stream past the token.
func leadBody(c leadCase, at int) string {
	return "x " + strings.Repeat("B", at-2) + c.head + c.tok + "!" + strings.Repeat("q", window+300) + " y"
}

// readSizes is a list of read sizes for chunkReader: first bytes in one
// read, then reads of step bytes up to n bytes in total.
func readSizes(first, step, n int) []int {
	out := []int{first}
	for i := first; i < n; i += step {
		out = append(out, step)
	}
	return out
}

// cutReader gives src with a read boundary at each offset in cuts, an
// ascending list. Between cuts, a read gives as much as p holds.
type cutReader struct {
	src  []byte
	pos  int
	cuts []int
}

func (r *cutReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.src) {
		return 0, io.EOF
	}
	for len(r.cuts) > 0 && r.cuts[0] <= r.pos {
		r.cuts = r.cuts[1:]
	}
	end := len(r.src)
	if len(r.cuts) > 0 {
		end = r.cuts[0]
	}
	n := copy(p, r.src[r.pos:end])
	r.pos += n
	return n, nil
}

// The stream takes the start of the body as the start of the text, and no
// other byte. It keeps tokenrules.LeadMax bytes of context after each cut.
// When a cut falls LeadMax bytes after the prefix of a rule with a lead,
// that prefix is the first byte that the stream holds. The regexp must not
// take that byte as the start of the text: a match from there is not a
// match of the body, and it must not cover the token after the prefix.
// The cut falls there when the window of the stream moves past the prefix
// and the next prefix is LeadMax bytes after it. The first reads of a
// streamed body are 32 KiB, so that position is fixed. With small reads,
// each position gets that cut. For each rule with a lead and each other
// token, at each position across the window start and the 32 KiB read
// boundary, and for reads of 1, 7 and random sizes, the stream gives the
// bytes of the buffered path.
func TestStreamLeadAtWindowStart(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	ts := tokensFor(ctx.TokenRE)
	rng := rand.New(rand.NewPCG(11, 12))
	cases := leadCases(t)

	// The token stream alone, in the reads of the head of a streamed body
	// (32 KiB), with the prefix at each position across the start of the
	// last window of the first read and across the end of that read.
	const read = 32 << 10
	at := []int{read - tokenrules.LeadMax - 1, read - 1, read, read + 1}
	for p := read - window - tokenrules.LeadMax - 2; p <= read-window+1; p++ {
		at = append(at, p)
	}
	for _, c := range cases {
		for _, p := range at {
			body := []byte(leadBody(c, p))
			want := ts.replace(body, stripRepl)
			got, err := io.ReadAll(newTokenStream(&chunkReader{src: body, sizes: []int{read, read}}, ts, false))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s at %d: stream and buffered disagree (%d vs %d bytes)", c.name, p, len(got), len(want))
			}
		}
	}

	// The full path, at the first and the last position where the cut of
	// the first read keeps the prefix as the first byte of the context.
	for _, c := range cases {
		for _, p := range []int{read - window - tokenrules.LeadMax, read - window - 1} {
			want, got, werr, gerr := bothPaths(t, ctx, pol, leadBody(c, p), rng)
			if werr != nil || gerr != nil {
				t.Fatalf("%s at %d: %v / %v", c.name, p, werr, gerr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s at %d: stream and buffered disagree (%d vs %d bytes)", c.name, p, len(got), len(want))
			}
		}
	}

	// The full path after the first streamHead bytes, in chunks of 1 and 7
	// bytes. The chunked reader gives all the chunks that it has in one
	// read. Thus the wire comes in reads of one byte where the window of
	// the stream moves past the prefix, and each chunk there is one read
	// of the stream.
	for _, c := range cases {
		const p = streamHead + 100
		inner := leadBody(c, p)
		buf := parseReq(t, postReq("example.com", inner))
		if _, _, err := DecideStream(*ctx, buf, pol, labSlots()); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want, err := io.ReadAll(buf.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{1, 7} {
			head := streamHead + 40 + n
			wire := []byte("POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
				strconv.FormatInt(int64(head), 16) + "\r\n" + inner[:head] + "\r\n")
			var cuts []int
			for i := head; i < len(inner); i += n {
				if i >= p+window-2*tokenrules.LeadMax && i < p+window+3*tokenrules.LeadMax {
					cuts = append(cuts, len(wire))
				}
				j := min(i+n, len(inner))
				wire = append(wire, strconv.FormatInt(int64(j-i), 16)+"\r\n"+inner[i:j]+"\r\n"...)
			}
			wire = append(wire, "0\r\n\r\n"...)
			req, err := httpwire.ReadRequest(bufio.NewReaderSize(&cutReader{src: wire, cuts: cuts}, 64<<10))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := DecideStream(*ctx, req, pol, labSlots()); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			got, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s in chunks of %d: stream and buffered disagree (%d vs %d bytes)", c.name, n, len(got), len(want))
			}
		}
	}

	// The token stream alone, in reads of 1 byte, of 7 bytes at each
	// alignment, and of random sizes. The reads of 1 and 7 bytes start
	// before the window of the stream moves past the prefix.
	const p = 100
	for _, c := range cases {
		body := []byte(leadBody(c, p))
		want := ts.replace(body, stripRepl)
		first := p + window - 2*tokenrules.LeadMax
		splits := [][]int{readSizes(first, 1, len(body))}
		for off := range 7 {
			splits = append(splits, readSizes(first-off, 7, len(body)))
		}
		var random []int
		for i := 0; i < len(body); i += random[len(random)-1] {
			random = append(random, 1+rng.IntN(1+rng.IntN(2000)))
		}
		splits = append(splits, random)
		for i, sizes := range splits {
			got, err := io.ReadAll(newTokenStream(&chunkReader{src: body, sizes: sizes}, ts, false))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s, split %d: stream and buffered disagree (%d vs %d bytes)", c.name, i, len(got), len(want))
			}
		}
	}
}

// inner finds the same matches as re at each position after the start of
// the text, with the same groups in the same order. Thus token and
// ruleName read a match of inner as a match of re. At the start of a text,
// inner does not take a prefix as a token with a lead.
func TestInnerSameAfterStart(t *testing.T) {
	rng := rand.New(rand.NewPCG(13, 14))
	data := make([]byte, 32)
	for i, ts := range skipSets(t) {
		if !slices.Equal(ts.inner.SubexpNames(), ts.re.SubexpNames()) {
			t.Fatalf("set %d: groups %q, want %q", i, ts.inner.SubexpNames(), ts.re.SubexpNames())
		}
		if strings.Contains(ts.re.String(), `\A`) == (ts.inner == ts.re) {
			t.Fatalf("set %d: inner was not made for %q", i, ts.re.String())
		}
		for range 300 {
			for k := range data {
				data[k] = byte(rng.Uint32())
			}
			// '#' is a lead byte that no prefix starts with. Thus a match at
			// 0 cannot use \A.
			b := append([]byte("#"), skipBody(data)...)
			b = b[:min(len(b), 600)]
			if want, got := ts.re.FindAllSubmatchIndex(b, -1), ts.inner.FindAllSubmatchIndex(b, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("set %d, %q: inner %v, re %v", i, b, got, want)
			}
		}
	}
	// A rule whose rows all have a lead matches its own token at the start
	// of the text with re, and not with inner.
	ts := skipSets(t)[0]
	lead := map[string]bool{}
	for _, r := range loadShippedRules(t).Rules {
		has := strings.HasPrefix(r.Expr, `\b`)
		if v, ok := lead[r.Name]; ok {
			has = has && v
		}
		lead[r.Name] = has
	}
	n := 0
	for _, s := range keyShapes() {
		if !lead[s.rule] {
			continue
		}
		n++
		b := []byte(s.make(10))
		if !ts.re.Match(b) || ts.inner.Match(b) {
			t.Fatalf("%s at the start of the text: re %v, inner %v", s.rule, ts.re.Match(b), ts.inner.Match(b))
		}
	}
	if n < 6 {
		t.Fatalf("%d rules with only a lead: the rules file changed", n)
	}
}
