package fence

import (
	"bufio"
	"bytes"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/tokenrules"
)

func benchRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func benchRE(b *testing.B) *regexp.Regexp {
	re, err := tokenrules.LoadTokenRE(filepath.Join(benchRoot(), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		b.Fatal(err)
	}
	return re
}

// Loaded one time per fuzz target, never inside f.Fuzz. Two file reads per
// execution cost more than the code under test. Throughput drops by about
// thirty times, and workers stall so long that the engine kills them as
// hung. This shows as "fuzzing process hung or terminated unexpectedly",
// not as an assertion.
func testPolicy(tb testing.TB) (*regexp.Regexp, *corepolicy.Policy) {
	tb.Helper()
	re, err := tokenrules.LoadTokenRE(filepath.Join(benchRoot(), "vm", "policy", "key_prefixes.rules"))
	if err != nil {
		tb.Fatal(err)
	}
	pol, err := corepolicy.Load(filepath.Join(benchRoot(), "vm", "policy", "core.hosts"))
	if err != nil {
		tb.Fatal(err)
	}
	return re, pol
}

func benchPol(b *testing.B) *corepolicy.Policy {
	p, err := corepolicy.Load(filepath.Join(benchRoot(), "vm", "policy", "core.hosts"))
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func benchReq(b *testing.B, raw string) *httpwire.Request {
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		b.Fatal(err)
	}
	return req
}

func jsonBody(n int, ph string) string {
	var sb strings.Builder
	sb.WriteString(`{"model":"claude","messages":[`)
	i := 0
	for sb.Len() < n-200 {
		sb.WriteString(`{"role":"user","content":"line ` + strconv.Itoa(i) + ` of some perfectly ordinary text with numbers 12345 and words"},`)
		i++
	}
	sb.WriteString(`{"role":"user","content":"x"}],"token":"` + ph + `"}`)
	return sb.String()
}

func headersReq(host string, auth string) string {
	return "GET /v1/messages HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: claude-code/1.0\r\nAccept: application/json\r\nAccept-Encoding: gzip\r\nX-Api-Key: " + auth + "\r\nAuthorization: Bearer " + auth + "\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nX-Request-Id: 0123456789abcdef\r\nConnection: keep-alive\r\n\r\n"
}

// postReq carries an opaque bearer, not a placeholder. A placeholder for a
// kind that the host cannot carry is now a refusal. The body tests below
// are about what occurs to a body, not about that.
func postReq(host, body string) string {
	return postAuth(host, "Bearer session-abc", body)
}

// postReqPH is postReq with the claude placeholder, for the hosts that
// may carry it.
func postReqPH(host, body string) string {
	return postAuth(host, "Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT", body)
}

func postAuth(host, auth, body string) string {
	return "POST /v1/messages HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: " + auth + "\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func runDecide(b *testing.B, sni, raw string) {
	re, pol, slots := benchRE(b), benchPol(b), labSlots()
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		req := benchReq(b, raw)
		if _, err := Decide(Ctx{SNI: sni, TokenRE: re}, req, pol, slots); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecideCoreHeaders(b *testing.B) {
	runDecide(b, "api.anthropic.com", headersReq("api.anthropic.com", "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"))
}

// A foreign host carries no kind, so a placeholder there is a refusal. The
// headers carry an opaque value, as postReq does.
func BenchmarkDecideForeignHeaders(b *testing.B) {
	runDecide(b, "example.com", headersReq("example.com", "session-abc"))
}

// The placeholder is in the Authorization header, where the host may carry
// it. A placeholder in this body is a refusal (CauseOutsideHeader).
func BenchmarkDecideCoreBody64K(b *testing.B) {
	runDecide(b, "api.anthropic.com", postReqPH("api.anthropic.com", jsonBody(64<<10, "nothing")))
}

func BenchmarkDecideForeignBody1MClean(b *testing.B) {
	runDecide(b, "example.com", postReq("example.com", jsonBody(1<<20, "nothing")))
}

func BenchmarkDecideForeignBody1MLeak(b *testing.B) {
	runDecide(b, "example.com", postReq("example.com", jsonBody(1<<20, "sk-ant-oat01-"+strings.Repeat("A", 64))))
}

func BenchmarkClassifyHeader(b *testing.B) {
	re := benchRE(b)
	slots := labSlots()
	sc := &scanner{inject: true, kinds: []string{"CLAUDE_OAT"}, idx: secrets.NewIndex(slots), tokens: tokensFor(re)}
	text := []byte("Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT")
	b.ReportAllocs()
	for b.Loop() {
		sc.classify(text)
	}
}

var _ = bytes.Compare

// benchStream measures the streamed request-body pipeline. It compares the
// live value scrubber alone, which is what shipped, with the scrubber plus
// the token pass above it.
func benchStream(b *testing.B, body string, withTokens bool) {
	ts := tokensFor(benchRE(b))
	pairs := [][2][]byte{{[]byte(liveOAT()), padRepl(len(liveOAT()))}}
	sink := make([]byte, 32*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		var r io.Reader = httpwire.NewScrubber(strings.NewReader(body), pairs)
		if withTokens {
			r = newTokenStream(r, ts, true)
		}
		for {
			if _, err := r.Read(sink); err != nil {
				break
			}
		}
	}
}

// A megabyte of ordinary JSON with no credential and no literal prefix
// in it. All large uploads are this case.
func benchCleanBody() string { return jsonBody(1<<20, "nothing-to-see-here") }

// The same body with sixteen live tokens scattered through it.
func benchTokenBody() string {
	parts := strings.SplitAfter(jsonBody(1<<20, "x"), "},")
	for i := 0; i < len(parts) && i < 16*64; i += 64 {
		parts[i] += ` "k":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", `
	}
	return strings.Join(parts, "")
}

// All rule prefixes are present, but none completes a token. The prefilter
// opens a window at each hit, and the regexp runs for nothing.
func benchPrefixNoiseBody() string {
	var sb strings.Builder
	for sb.Len() < (1<<20)-8192 {
		sb.WriteString(` "a":"ghp_short", "b":"sk-nope", "c":"AKIA!", "d":"npm_x", `)
	}
	return sb.String()
}

func BenchmarkStreamCleanScrubOnly(b *testing.B)  { benchStream(b, benchCleanBody(), false) }
func BenchmarkStreamCleanWithTokens(b *testing.B) { benchStream(b, benchCleanBody(), true) }
func BenchmarkStreamTokensScrubOnly(b *testing.B) { benchStream(b, benchTokenBody(), false) }
func BenchmarkStreamTokensWithTokens(b *testing.B) {
	benchStream(b, benchTokenBody(), true)
}
func BenchmarkStreamPrefixNoiseScrubOnly(b *testing.B) {
	benchStream(b, benchPrefixNoiseBody(), false)
}
func BenchmarkStreamPrefixNoiseWithTokens(b *testing.B) {
	benchStream(b, benchPrefixNoiseBody(), true)
}

// A megabyte of near-misses through the buffered path. The prefilter
// opens a window at each hit. Thus a body designed to cost CPU lands
// here.
func BenchmarkDecideForeignBody1MNoise(b *testing.B) {
	runDecide(b, "example.com", postReq("example.com", benchPrefixNoiseBody()))
}

// A megabyte of one prefix in one letter case (benchOneCaseBody) through
// the buffered path.
func BenchmarkDecideForeignBody1MOneCase(b *testing.B) {
	runDecide(b, "example.com", postReq("example.com", benchOneCaseBody()))
}

// A megabyte that is one run of token bytes with a rule prefix every four
// bytes. Each prefix opens a window, and all of them end where the run
// ends.
func benchPrefixRunBody() string { return strings.Repeat("ghp_", (1<<20)/4) }

// The same, cut into runs that are shorter than maxHold. Thus the stream
// holds each run and does not strip it as one long token.
func benchPrefixRunsBody() string {
	run := strings.Repeat("ghp_", (maxHold-64)/4) + " "
	return strings.Repeat(run, (1<<20)/len(run))
}

// A megabyte of one prefix in upper case, each hit too short to open a
// window. The anchor byte of the folded search ('k' of akia) is then in
// the body in one case only.
func benchOneCaseBody() string { return strings.Repeat("AKIA ", (1<<20)/5) }

// benchTokenReads measures the token stream alone in reads of n bytes.
func benchTokenReads(b *testing.B, body string, n int) {
	ts := tokensFor(benchRE(b))
	sink := make([]byte, 32<<10)
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		s := newTokenStream(&stepReader{src: []byte(body), n: n}, ts, true)
		for {
			_, err := s.Read(sink)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// benchTokenReplace measures the buffered path: one replace of body.
func benchTokenReplace(b *testing.B, body string) {
	ts := tokensFor(benchRE(b))
	src := []byte(body)
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		ts.replace(src, stripRepl)
	}
}

func BenchmarkTokenPrefixRunReads16K(b *testing.B) { benchTokenReads(b, benchPrefixRunBody(), 16<<10) }
func BenchmarkTokenPrefixRunsReads16K(b *testing.B) {
	benchTokenReads(b, benchPrefixRunsBody(), 16<<10)
}
func BenchmarkTokenCleanReads16K(b *testing.B)     { benchTokenReads(b, benchCleanBody(), 16<<10) }
func BenchmarkTokenTokensReads16K(b *testing.B)    { benchTokenReads(b, benchTokenBody(), 16<<10) }
func BenchmarkTokenPrefixRunReplace(b *testing.B)  { benchTokenReplace(b, benchPrefixRunBody()) }
func BenchmarkTokenPrefixRunsReplace(b *testing.B) { benchTokenReplace(b, benchPrefixRunsBody()) }
func BenchmarkTokenCleanReplace(b *testing.B)      { benchTokenReplace(b, benchCleanBody()) }
func BenchmarkTokenTokensReplace(b *testing.B)     { benchTokenReplace(b, benchTokenBody()) }
func BenchmarkTokenOneCaseReads16K(b *testing.B)   { benchTokenReads(b, benchOneCaseBody(), 16<<10) }
func BenchmarkTokenOneCaseReplace(b *testing.B)    { benchTokenReplace(b, benchOneCaseBody()) }
