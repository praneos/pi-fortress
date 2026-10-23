package fence

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"pi-fortress/internal/secrets"
)

// chunkReader gives out src in the given piece sizes. Thus a test selects
// exactly where the read boundaries fall.
type chunkReader struct {
	src   []byte
	sizes []int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.src) == 0 {
		return 0, io.EOF
	}
	n := len(c.src)
	if len(c.sizes) > 0 {
		n, c.sizes = min(c.sizes[0], n), c.sizes[1:]
	}
	n = copy(p, c.src[:n])
	c.src = c.src[n:]
	return n, nil
}

// A placeholder split across reads at every byte is still the read that
// fails, and nothing emitted before it is any part of one.
func TestPlaceholderGuardStraddle(t *testing.T) {
	ph := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	body := strings.Repeat("x", 100) + " " + ph + " " + strings.Repeat("y", 100)
	for cut := 90; cut < 100+len(ph)+3; cut++ {
		g := newPlaceholderGuard(&chunkReader{src: []byte(body), sizes: []int{cut}})
		out, err := io.ReadAll(g)
		if !errors.Is(err, ErrPlaceholderInStream) {
			t.Fatalf("cut %d: err %v", cut, err)
		}
		if bytes.Contains(out, []byte("pf_")) || len(out) > 101 {
			t.Fatalf("cut %d: emitted %q", cut, out)
		}
		if !bytes.HasPrefix([]byte(body), out) {
			t.Fatalf("cut %d: emitted %q, not a prefix", cut, out)
		}
	}
}

// The guard passes the shapes that the buffered path passes, whole and
// without a change, for all read boundaries. It stops a shape that the buffered path takes.
func TestPlaceholderGuardPassesDecoys(t *testing.T) {
	decoys := []string{
		"pf_",
		"pf_zz",
		"pf_b0b1b2b3b4b5b6b7",
		"pf_b0b1b2b3b4b5b6b7_",
		"pf_p",
		"pf_b0b1b2b3b4b5b6bX_KIND",
	}
	for _, d := range decoys {
		body := []byte(strings.Repeat("a ", 50) + d + strings.Repeat(" b", 50))
		for _, sizes := range [][]int{nil, {1}, {7, 3, 1}, {len(body) - 1}} {
			g := newPlaceholderGuard(&chunkReader{src: body, sizes: sizes})
			out, err := io.ReadAll(g)
			if err != nil || !bytes.Equal(out, body) {
				t.Fatalf("%q sizes %v: %v %q", d, sizes, err, out)
			}
		}
	}
	// The buffered path reads each of these as a placeholder at the very end.
	for _, ph := range []string{
		secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT"),
		"pf_b0b1b2b3b4b5b6b7_Kind",
		"pf_b0b1b2b3b4b5b6b7_KINDx",
	} {
		tail := []byte("payload " + ph)
		g := newPlaceholderGuard(&chunkReader{src: tail, sizes: []int{1}})
		out, err := io.ReadAll(g)
		if !errors.Is(err, ErrPlaceholderInStream) || bytes.Contains(out, []byte("pf_")) {
			t.Fatalf("tail placeholder %q: %v %q", ph, err, out)
		}
	}
}

// A chain of placeholder shapes is one kind run, and it stays in the hold.
// The guard does not cut inside it, so a stop never leaves a whole
// placeholder at the far end. In the hold, maxHold still limits it.
func TestPlaceholderGuardHoldsAChainOfDecoysBounded(t *testing.T) {
	decoy := "pf_0000000000000000_A"
	body := []byte(strings.Repeat(decoy, maxHold/len(decoy)+2) + "x")
	sizes := make([]int, len(body)/7+1)
	for i := range sizes {
		sizes[i] = 7
	}
	g := newPlaceholderGuard(&chunkReader{src: body, sizes: sizes})
	out, err := io.ReadAll(g)
	if !errors.Is(err, ErrPlaceholderInStream) {
		t.Fatalf("a %d-byte chain was held to EOF: %v", len(body), err)
	}
	if spans := secrets.FindPlaceholderSpans(out); len(spans) != 0 {
		t.Fatalf("emitted a placeholder: %q", out)
	}
}

// For all read boundaries: a body with no placeholder passes whole and
// without a change. A body with a placeholder fails with the sentinel,
// after it emitted only a prefix that stops before the first placeholder
// and holds no complete placeholder. The one exception is the maxHold
// limit, which can stop a kind run longer than any real placeholder.
func FuzzPlaceholderGuard(f *testing.F) {
	ph := secrets.Placeholder("b0b1b2b3b4b5b6b7", "CLAUDE_OAT")
	f.Add("hello "+ph+" world", []byte{3, 9, 1})
	f.Add("pf_b0b1b2b3b4b5b6b7_KINDx pf_zz", []byte{1})
	f.Add(strings.Repeat("A", 40)+ph, []byte{40, 1, 1})
	f.Fuzz(func(t *testing.T, body string, cuts []byte) {
		sizes := make([]int, 0, len(cuts))
		for _, c := range cuts {
			sizes = append(sizes, int(c)+1)
		}
		g := newPlaceholderGuard(&chunkReader{src: []byte(body), sizes: sizes})
		out, err := io.ReadAll(g)
		spans := secrets.FindPlaceholderSpans([]byte(body))
		if err == nil {
			if out := string(out); out != body || len(spans) > 0 {
				t.Fatalf("passed %q as %q, spans %v", body, out, spans)
			}
			return
		}
		if !errors.Is(err, ErrPlaceholderInStream) || !strings.HasPrefix(body, string(out)) {
			t.Fatalf("%v %q of %q", err, out, body)
		}
		if len(secrets.FindPlaceholderSpans(out)) > 0 {
			t.Fatalf("emitted a placeholder: %q", out)
		}
		if len(spans) > 0 && len(out) > spans[0][0] {
			t.Fatalf("emitted past the first placeholder: %d > %d in %q", len(out), spans[0][0], body)
		}
		if len(spans) == 0 && len(body) <= maxHold {
			t.Fatalf("stopped a body with no placeholder: %q", body)
		}
	})
}

// The guard holds a chain of placeholder-shaped runs, each one cancelled
// only by the "p" of the next, that ends at an open candidate. It found
// the start of the chain with a new scan of the buffer from its first byte
// one time per run. Thus each pass cost the buffer times the chain, and the
// agent sets the chain. One backward pass needs no allocation for any
// length of the chain. Each rescan allocated its span list.
func TestPlaceholderGuardChainIsLinear(t *testing.T) {
	run := "pf_b0b1b2b3b4b5b6b7_A"
	allocs := func(k int) float64 {
		src := []byte(strings.Repeat("x", 32<<10) + strings.Repeat(run, k) + "pf_b0")
		g := newPlaceholderGuard(nil)
		buf := make([]byte, 0, len(src))
		g.Out = make([]byte, 0, len(src))
		var held int
		n := testing.AllocsPerRun(20, func() {
			g.Buf = append(buf[:0], src...)
			g.Out, g.EOF, g.err = g.Out[:0], false, nil
			g.scan()
			held = len(g.Buf)
		})
		if g.err != nil || held != len(run)*k+len("pf_b0") {
			t.Fatalf("k=%d: err %v, held %d", k, g.err, held)
		}
		return n
	}
	short, long := allocs(4), allocs(600)
	if long > short {
		t.Fatalf("a pass over a 600-run chain allocated %v times, a 4-run one %v: the chain is rescanned per run", long, short)
	}
}
