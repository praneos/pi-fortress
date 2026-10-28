package fence

import (
	"bytes"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/tokenrules"
)

func streamRules(t testing.TB) (*Ctx, *corepolicy.Policy) {
	t.Helper()
	re, err := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	if err != nil {
		t.Fatal(err)
	}
	return &Ctx{TokenRE: re}, pol
}

// ghp is a token that the secrets store never saw. Nothing in slots
// matches it, so only the prefix rules can catch it.
const ghp = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

func streamOut(t *testing.T, raw string) (string, *StreamStrips) {
	t.Helper()
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	req := parseReq(t, raw)
	_, stream, err := DecideStream(*ctx, req, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if stream == nil {
		t.Fatal("body must stream")
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), stream
}

// The gap that this closes: a token that the store does not hold went
// directly out in a streamed body, because the scrub covered only the stored live values.
func TestStreamStripsUnstoredToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  func(body string) string
	}{
		{"chunked", func(b string) string {
			return "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(b)
		}},
		{"over the buffer limit", func(b string) string { return postReq("example.com", b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := jsonBody((1<<20)+4096, ghp)
			out, stream := streamOut(t, tc.raw(body))
			if strings.Contains(out, ghp) {
				t.Fatal("an unstored token survived the streamed body")
			}
			if !strings.Contains(out, StripRepl) {
				t.Fatal("nothing was written in its place")
			}
			var got []string
			for _, ev := range stream.Events() {
				got = append(got, ev.Rule)
			}
			if len(got) != 1 || got[0] != "github_classic" {
				t.Fatalf("events %v, want the rule that fired", got)
			}
		})
	}
}

// A Content-Length body must leave at the length its header promises.
func TestStreamTokenStripPreservesLength(t *testing.T) {
	body := jsonBody((1<<20)+4096, ghp)
	raw := postReq("example.com", body)
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	req := parseReq(t, raw)
	if _, _, err := DecideStream(*ctx, req, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(out)) != req.ContentLength {
		t.Fatalf("wrote %d bytes for Content-Length %d", len(out), req.ContentLength)
	}
	if strings.Contains(string(out), ghp) {
		t.Fatal("token survived")
	}
}

// The main problem of a stream: the reads do not fall on token boundaries.
// The fence must still strip a token split across two reads as a whole.
// The stream must not have emitted the half that arrived first.
func TestStreamTokenAcrossReadBoundaries(t *testing.T) {
	for _, base := range []int{8 << 10, 32 << 10} {
		for _, off := range []int{-41, -40, -39, -20, -2, -1, 0, 1, 2, 39, 41} {
			at := base + off
			t.Run(strconv.Itoa(at), func(t *testing.T) {
				body := strings.Repeat("x", at) + " " + ghp + " " + strings.Repeat("y", 40<<10)
				raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
				out, _ := streamOut(t, raw)
				if strings.Contains(out, ghp) {
					t.Fatal("token survived whole")
				}
				// A partial strip is the dangerous failure: the head is
				// replaced, and the remainder of the credential goes out
				// as ordinary bytes.
				for n := 8; n < len(ghp); n++ {
					if strings.Contains(out, ghp[n:]) {
						t.Fatalf("%d-byte tail of the token leaked", len(ghp)-n)
					}
				}
			})
		}
	}
}

// The stream sees the body in the pieces that the wire delivers. The answer
// must not depend on the position of the cuts. Random bodies, random token
// positions, random chunk sizes: the test compares each with the buffered
// path.
func TestStreamAgreesWithBufferedOnRandomSplits(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"
	filler := []byte(" abcdefghijklmnopqrstuvwxyz0123456789.,{}\"':")
	for i := 0; i < 200; i++ {
		n := 4096 + rng.IntN(64<<10)
		b := make([]byte, n)
		for j := range b {
			b[j] = filler[rng.IntN(len(filler))]
		}
		for _, tok := range []string{ghp, liveOAT(), "AKIA" + strings.Repeat("Q", 16)} {
			at := rng.IntN(n - len(tok) - 2)
			copy(b[at:], " "+tok+" ")
		}
		inner := string(b)

		buf := parseReq(t, postReq("example.com", inner))
		if _, _, err := DecideStream(*ctx, buf, pol, labSlots()); err != nil {
			t.Fatal(err)
		}
		want, err := io.ReadAll(buf.Body)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		for rest := inner; len(rest) > 0; {
			k := min(1+rng.IntN(2048), len(rest))
			sb.WriteString(strconv.FormatInt(int64(k), 16) + "\r\n" + rest[:k] + "\r\n")
			rest = rest[k:]
		}
		raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + sb.String() + "0\r\n\r\n"
		req := parseReq(t, raw)
		if _, _, err := DecideStream(*ctx, req, pol, labSlots()); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: stream and buffered disagree (%d vs %d bytes)", i, len(got), len(want))
		}
	}
}

// A token that ends exactly at the end of the body has no next byte for
// the trailing word boundary to read. EOF must settle it.
func TestStreamTokenAtEOF(t *testing.T) {
	body := strings.Repeat("x", 200<<10) + " " + ghp
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	out, _ := streamOut(t, raw)
	if strings.Contains(out, ghp) {
		t.Fatal("a token at the end of the body survived")
	}
}

// The stream must give the same bytes as the buffered path. If not, the
// fence means two different things on each side of one megabyte.
func TestStreamMatchesBufferedResult(t *testing.T) {
	inner := strings.Repeat("z", 300<<10) + " " + ghp + "-tail-" + liveOAT() + strings.Repeat("q", 100)
	ctx, pol := streamRules(t)
	ctx.SNI = "example.com"

	buf := parseReq(t, postReq("example.com", inner))
	if _, _, err := DecideStream(*ctx, buf, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(buf.Body)
	if err != nil {
		t.Fatal(err)
	}

	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(inner)
	got, _ := streamOut(t, raw)
	if got != string(want) {
		t.Fatalf("stream and buffered disagree: %d vs %d bytes", len(got), len(want))
	}
	if bytes.Contains(want, []byte(ghp)) || strings.Contains(got, ghp) {
		t.Fatal("neither path stripped the token")
	}
}

// A core host has the rules of the kinds that it carries removed from its
// token set, on a stream as in a buffer. A token with the shape of its own
// kind passes, and a foreign kind in the same body still strips.
func TestStreamKeepsTheHostsOwnKind(t *testing.T) {
	ctx, pol := streamRules(t)
	ctx.SNI = "api.anthropic.com"
	ctx.StripCore = true
	re, err := tokenrules.LoadTokenRules(benchRoot() + "/vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Rules = re
	own := "sk-ant-oat01-" + strings.Repeat("D", 64)
	body := jsonBody(300<<10, own) + " " + ghp
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	if _, _, err := DecideStream(*ctx, req, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), own) {
		t.Fatal("the host's own kind was stripped by the token pass")
	}
	if strings.Contains(string(out), ghp) {
		t.Fatal("a GitHub token rode a core-host body out")
	}
}

// With no rules configured, there is no token pass. Only the scrubber acts
// on the body.
func TestStreamWithoutRulesIsUnchanged(t *testing.T) {
	body := jsonBody(300<<10, ghp)
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	if _, _, err := DecideStream(Ctx{SNI: "example.com"}, req, nil, labSlots()); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), ghp) {
		t.Fatal("a token was stripped with no rules loaded")
	}
}
