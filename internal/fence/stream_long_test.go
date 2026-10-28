package fence

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
)

// bothPaths runs inner through the buffered path and, chunked at splits
// rng picks, through the stream.
func bothPaths(t *testing.T, ctx *Ctx, pol *corepolicy.Policy, inner string, rng *rand.Rand) (want, got []byte, werr, gerr error) {
	t.Helper()
	buf := parseReq(t, postReq("example.com", inner))
	if _, _, werr = DecideStream(*ctx, buf, pol, labSlots()); werr == nil {
		want, werr = io.ReadAll(buf.Body)
	}
	var sb strings.Builder
	for rest := inner; len(rest) > 0; {
		k := min(1+rng.IntN(3000), len(rest))
		sb.WriteString(strconv.FormatInt(int64(k), 16) + "\r\n" + rest[:k] + "\r\n")
		rest = rest[k:]
	}
	req := parseReq(t, "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"+sb.String()+"0\r\n\r\n")
	if _, _, gerr = DecideStream(*ctx, req, pol, labSlots()); gerr == nil {
		got, gerr = io.ReadAll(req.Body)
	}
	return want, got, werr, gerr
}

// A {20,} rule can match past window, but tokenSet.span stops the match
// there on both paths. The fence strips the head, and the tail goes out:
// the same bytes on each side of one megabyte. The tail is not a
// credential. A prefix inside it either is in the merged window, so the
// match continues over it, or follows a word byte and fails its own \b.
// A run with a prefix in each window is one match. When that match is
// longer than maxHold, the strip goes on to the end of the run, on both
// paths (cover). The stream holds at most maxHold of such a run, also when
// the run starts the body.
func TestStreamLongTokenMatchesBuffered(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	ts := tokensFor(ctx.TokenRE)
	rng := rand.New(rand.NewPCG(3, 4))
	oat, run := "sk-ant-oat01-", func(n int) string { return strings.Repeat("B", n) }
	for i, c := range []struct {
		tok string
		// long says that the match is longer than maxHold.
		long bool
	}{
		{oat + run(window), false},
		{oat + run(5000), false},
		{oat + run(maxHold+5000), false},
		{"glpat-" + run(100_000), false},
		{oat + run(4084) + "ghp_" + run(36), false},
		{oat + run(6000) + "glpat-" + run(30), false},
		{strings.Repeat(oat+run(4000), 10), true},
		{strings.Repeat(oat+run(4000), 6) + run(9000), true},
		{strings.Repeat("glpat-"+run(4000), 12), true},
	} {
		tok := c.tok
		for _, inner := range []string{
			strings.Repeat("z", 3000) + " " + tok + " " + strings.Repeat("q", 3000),
			tok + " " + strings.Repeat("q", 3000),
		} {
			want, got, werr, gerr := bothPaths(t, ctx, pol, inner, rng)
			if werr != nil || gerr != nil {
				t.Fatalf("case %d: %v / %v", i, werr, gerr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("case %d: stream and buffered disagree (%d vs %d bytes)", i, len(got), len(want))
			}
			if bytes.Contains(want, []byte(tok[:40])) {
				t.Fatalf("case %d: token head not stripped", i)
			}
			if c.long && bytes.Contains(want, []byte("B")) {
				t.Fatalf("case %d: a part of a token longer than maxHold went out", i)
			}
		}

		big := strings.Repeat("z", maxBodyBuf) + " " + tok + " "
		req := parseReq(t, postReq("example.com", big))
		if _, st, err := DecideStream(*ctx, req, pol, labSlots()); err != nil || st == nil {
			t.Fatalf("case %d: fixed-length body did not stream: %v", i, err)
		}
		padded, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if ref := stripRef(ts, ts.matches([]byte(big)), []byte(big), true); !bytes.Equal(padded, ref) {
			t.Fatalf("case %d: padded stream differs from the buffered matches", i)
		}
	}

	ph := "a pf_0123456789abcdef_" + strings.Repeat("K", maxHold+100) + " b"
	_, _, werr, gerr := bothPaths(t, ctx, pol, ph, rng)
	var ref *RefusedError
	if !errors.As(werr, &ref) || !errors.Is(gerr, ErrPlaceholderInStream) {
		t.Fatalf("overlong placeholder kind: buffered %v, stream %v", werr, gerr)
	}
}

// FuzzStreamLongToken: a prefix-rule token of any length up to 64 KiB, with
// any content spliced into it, leaves the stream exactly as it leaves the
// buffered path, refusal also. With bit 0x40 of which, the token starts
// the body. With bit 0x80, the start of the token comes again before each
// window ends. Thus the windows merge, and the match can be longer than
// maxHold.
func FuzzStreamLongToken(f *testing.F) {
	f.Add(uint16(5000), uint8(0), uint16(4084), "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", uint64(1))
	f.Add(uint16(20000), uint8(1), uint16(9000), "glpat-", uint64(2))
	f.Add(uint16(4076), uint8(2), uint16(4070), " ", uint64(3))
	f.Add(uint16(17000), uint8(0), uint16(4100), "-sk-ant-ort01-", uint64(4))
	f.Add(uint16(6000), uint8(1), uint16(5000), "pf_0123456789abcdef_CLAUDE_OAT", uint64(5))
	f.Add(uint16(40000), uint8(0xc2), uint16(100), "", uint64(6))
	f.Add(uint16(30000), uint8(0x80), uint16(3000), " ", uint64(7))
	ctx, pol := streamRules(f)
	ctx.SNI = "example.com"
	prefixes := []string{"sk-ant-oat01-", "sk-ant-ort01-", "glpat-"}
	f.Fuzz(func(t *testing.T, n uint16, which uint8, at uint16, mid string, seed uint64) {
		if len(mid) > 256 {
			return
		}
		body := strings.Repeat("B", 20+int(n))
		pos := int(at) % len(body)
		tok := prefixes[int(which)%len(prefixes)] + body[:pos] + mid + body[pos:]
		if which&0x80 != 0 {
			unit := tok[:min(len(tok), window-16)]
			tok = strings.Repeat(unit, 1+len(tok)/len(unit))
		}
		inner := "x " + tok + " y"
		if which&0x40 != 0 {
			inner = tok + " y"
		}
		want, got, werr, gerr := bothPaths(t, ctx, pol, inner, rand.New(rand.NewPCG(seed, seed^0x9e37)))
		if werr != nil {
			if gerr == nil {
				t.Fatalf("buffered refused (%v), stream did not", werr)
			}
			return
		}
		if gerr != nil {
			t.Fatalf("stream failed (%v), buffered did not", gerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("stream and buffered disagree (%d vs %d bytes)", len(got), len(want))
		}
	})
}
