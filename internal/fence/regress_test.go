package fence

import (
	"bufio"
	"bytes"
	"testing"

	"pi-fortress/internal/httpwire"
)

// A rewritten request must always satisfy this: it parses again. The
// fence terminates TLS on both hops. If the next hop frames a request from
// the fence differently than the fence did, that is a smuggling desync,
// and the fence would be its cause.
//
// These are the table-driven form of the FuzzDecideAnyRequest property.
// The fuzzer found the repeated Content-Length case after ~700k executions.
// As a plain test, it runs in microseconds on each `go test ./...`.
func TestRewrittenRequestParsesAgain(t *testing.T) {
	re, pol := testPolicy(t)
	cases := []struct {
		name string
		raw  string
		sni  string
	}{
		{
			// The regression. Two identical Content-Length fields parsed
			// before, because the parser refused only a pair that disagreed.
			// The code kept both fields, SetBody rewrote the first in place,
			// and the request went out with "Content-Length: 0" and "Content-Length: 1".
			name: "repeated content-length",
			raw:  "0 0 0\r\nContent-Length:1\r\nContent-Length:1\r\n\r\n",
			sni:  "0",
		},
		{
			name: "declared body longer than the bytes present",
			raw:  "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 64\r\n\r\nshort",
			sni:  "example.com",
		},
		{
			name: "no host header",
			raw:  "GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
			sni:  "example.com",
		},
		{
			name: "header with no space after the colon",
			raw:  "POST /x HTTP/1.1\r\nHost:example.com\r\nContent-Length:4\r\n\r\nabcd",
			sni:  "example.com",
		},
		{
			name: "core host, secret in the body",
			raw:  "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 44\r\n\r\n{\"k\":\"pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\"}xx",
			sni:  "api.anthropic.com",
		},
		{
			name: "chunked body",
			raw:  "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
			sni:  "example.com",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(c.raw))))
			if err != nil {
				// A refusal at the door is a correct result. The property is
				// only about what the fence agrees to emit.
				return
			}
			if _, _, err := DecideStream(Ctx{SNI: c.sni, TokenRE: re}, req, pol, labSlots()); err != nil {
				return
			}
			var out bytes.Buffer
			if _, err := req.WriteTo(&out); err != nil {
				return
			}
			wire := append([]byte(nil), out.Bytes()...)
			if _, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader(wire))); err != nil {
				t.Fatalf("rewritten request unparseable: %v\nin =%q\nout=%q", err, c.raw, wire)
			}
		})
	}
}

// tokenCache is a process-global sync.Map keyed on the compiled regexp
// pointer, with no eviction and no limit. That is correct only because the
// rules are compiled one time at daemon start. A load per request would add
// a permanent entry per load. This exhausted the memory of the fuzz workers
// before the loads moved out of f.Fuzz.
//
// This test guards the property that is important in production: traffic
// does not grow the cache. It is also the test that fails on the day that
// someone adds hot-reload of key_prefixes.rules without a limit on the
// cache.
func TestDecideStreamDoesNotGrowTokenCache(t *testing.T) {
	re, pol := testPolicy(t)
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nabcde"

	// Prime it, so the count below excludes the one legitimate entry.
	req, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	before := tokenCacheLen()

	for i := 0; i < 500; i++ {
		req, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(raw))))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, labSlots()); err != nil {
			t.Fatal(err)
		}
	}
	if after := tokenCacheLen(); after != before {
		t.Fatalf("tokenCache grew from %d to %d over 500 requests on one rule set", before, after)
	}
}

// Two compiles of the same rules give two cache entries, because the key
// is the regexp pointer, not the pattern. This is recorded on purpose: it
// is why a per-execution load leaks. A person who changes the keying must
// change this test on purpose.
func TestTokenCacheKeysOnPointerNotPattern(t *testing.T) {
	reA, _ := testPolicy(t)
	reB, _ := testPolicy(t)
	if reA == reB {
		t.Skip("loader returned a shared regexp; pointer keying is moot")
	}
	if tokensFor(reA) == tokensFor(reB) {
		t.Fatal("two separately compiled rule sets shared a tokenSet; the cache is no longer pointer-keyed")
	}
}

func tokenCacheLen() int {
	n := 0
	tokenCache.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
