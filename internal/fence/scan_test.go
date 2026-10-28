package fence

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/tokenrules"
)

func chunked(s string) string {
	var sb strings.Builder
	for len(s) > 0 {
		n := min(8192, len(s))
		sb.WriteString(strconv.FormatInt(int64(n), 16) + "\r\n" + s[:n] + "\r\n")
		s = s[n:]
	}
	return sb.String() + "0\r\n\r\n"
}

func liveOAT() string { return "sk-ant-oat01-" + strings.Repeat("A", 64) }

func TestLargeBufferedBodyStripped(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	body := jsonBody(300<<10, liveOAT())
	req := parseReq(t, postReq("example.com", body))
	strips, stream, err := DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if stream != nil {
		t.Fatal("buffered body must not stream")
	}
	if len(strips) == 0 {
		t.Fatal("no strip event for a live token in a 300 KiB body")
	}
	out, _ := io.ReadAll(req.Body)
	if bytes.Contains(out, []byte(liveOAT())) || !bytes.Contains(out, stripRepl) {
		t.Fatal("live token survived the buffered strip")
	}
	if req.ContentLength != int64(len(out)) {
		t.Fatalf("cl %d != %d", req.ContentLength, len(out))
	}
}

func TestChunkedBodyStreamScrubbed(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	body := jsonBody(300<<10, liveOAT())
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	_, stream, err := DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if stream == nil {
		t.Fatal("chunked body must stream through the scrubber")
	}
	out, _ := io.ReadAll(req.Body)
	if bytes.Contains(out, []byte(liveOAT())) || !bytes.Contains(out, stripRepl) {
		t.Fatal("live token survived the stream scrub")
	}
	if len(out) != len(body)-len(liveOAT())+len(stripRepl) {
		t.Fatalf("chunked scrub length %d, want %d", len(out), len(body)-len(liveOAT())+len(stripRepl))
	}
	ev := stream.Events()
	if len(ev) != 1 || ev[0].Where != "body" || !strings.HasPrefix(ev[0].Rule, "secret:") {
		t.Fatalf("events %+v", ev)
	}
}

func TestLargeCLBodyStreamPreservesLength(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	body := jsonBody((1<<20)+4096, liveOAT())
	req := parseReq(t, postReq("example.com", body))
	_, stream, err := DecideStream(Ctx{SNI: "example.com", TokenRE: re}, req, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if stream == nil {
		t.Fatal("body over the buffer limit must stream")
	}
	out, _ := io.ReadAll(req.Body)
	if int64(len(out)) != req.ContentLength || len(out) != len(body) {
		t.Fatalf("len %d cl %d body %d", len(out), req.ContentLength, len(body))
	}
	if bytes.Contains(out, []byte(liveOAT())) {
		t.Fatal("live token survived")
	}
	if len(stream.Events()) != 1 {
		t.Fatalf("events %+v", stream.Events())
	}
}

// The fence refuses a placeholder of a kind that the host carries in a
// request body, and does not substitute it: the model behind
// api.anthropic.com can print a credential from its prompt back reversed, past all literal scrubs.
func TestCoreBodyPlaceholderRefused(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	ph := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	req := parseReq(t, postReqPH("api.anthropic.com", jsonBody(200<<10, ph)))
	_, _, err := DecideStream(Ctx{SNI: "api.anthropic.com", TokenRE: re}, req, pol, labSlots())
	var ref *RefusedError
	if !errors.As(err, &ref) || len(ref.Refusals) != 1 || ref.Refusals[0].Cause != CauseOutsideHeader || ref.Refusals[0].Where != "body" {
		t.Fatalf("a core body placeholder: %v", err)
	}
}

func TestTokenPrefilterAgreesWithRegexp(t *testing.T) {
	re, err := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	if err != nil {
		t.Fatal(err)
	}
	ts := tokensFor(re)
	if !ts.complete || len(ts.prefixes) < 10 {
		t.Fatalf("prefilter not built: complete=%v prefixes=%d", ts.complete, len(ts.prefixes))
	}
	for _, c := range []string{
		"nothing here",
		"ghp_" + strings.Repeat("A", 36),
		"x ghp_" + strings.Repeat("A", 35) + " y",
		"AKIA" + strings.Repeat("Q", 16),
		"sk-ant-oat01-" + strings.Repeat("A", 64),
		"sk-" + strings.Repeat("a", 48),
		"sk_live_" + strings.Repeat("a", 24),
		"glpat-" + strings.Repeat("a", 20),
		strings.Repeat("harmless text with ghp and sk and AKIA words ", 50),
	} {
		b := []byte(c)
		if got, want := ts.match(b), re.Match(b); got != want {
			t.Fatalf("%q: prefiltered %v regexp %v", c, got, want)
		}
		if got, want := string(ts.replace(b, stripRepl)), re.ReplaceAllString(c, StripRepl); got != want {
			t.Fatalf("%q: replace %q want %q", c, got, want)
		}
	}
	if _, _, ok := literalPrefixes(`(?P<a>\bghp_x)|(?P<b>[A-Z]{4})`); ok {
		t.Fatal("branch without literal must disable the prefilter")
	}
}

func TestTokenWindowsMatchWholeTextRegexp(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	ts := tokensFor(re)
	filler := strings.Repeat("plain text, numbers 42, sk and gh as words. ", 400)
	toks := []string{"ghp_" + strings.Repeat("A", 36), "AKIA" + strings.Repeat("Q", 16), "sk-ant-oat01-" + strings.Repeat("Z", 70), "glpat-" + strings.Repeat("g", 25)}
	text := filler + toks[0] + filler + " " + toks[1] + "x" + filler + toks[2] + "\n" + toks[3] + filler + toks[0] + toks[0]
	b := []byte(text)
	want := re.FindAllSubmatchIndex(b, -1)
	got := ts.matches(b)
	if len(got) != len(want) {
		t.Fatalf("matches %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
			t.Fatalf("match %d: %v want %v", i, got[i][:2], want[i][:2])
		}
	}
	if string(ts.replace(b, stripRepl)) != re.ReplaceAllString(text, StripRepl) {
		t.Fatal("windowed replace differs from regexp ReplaceAll")
	}
	if len(ts.rules(b)) != len(want) {
		t.Fatal("rules count")
	}
}

// A chunked core body streams through the scrub. A live value of a
// different kind strips, and the header still gets its credential.
func TestChunkedCoreBodyStripsInStream(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	ph := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	foreignLive := "lab_fence_github"
	body := jsonBody(300<<10, "x") + `{"also":"` + foreignLive + `"}`
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + ph + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	_, stream, err := DecideStream(Ctx{SNI: "api.anthropic.com", TokenRE: re}, req, pol, labSlots())
	if err != nil {
		t.Fatal(err)
	}
	if stream == nil {
		t.Fatal("chunked body must stream")
	}
	out, _ := io.ReadAll(req.Body)
	if bytes.Contains(out, []byte(foreignLive)) || !bytes.Contains(out, stripRepl) {
		t.Fatal("a live value of a kind this host may not carry survived")
	}
	if req.Get("Authorization") != "Bearer "+liveOAT() {
		t.Fatal("header inject broken")
	}
	ev := stream.Events()
	if len(ev) != 1 || ev[0].Rule != "secret:"+secrets.EnvKey("a1b2c3d4e5f67890", "GITHUB_TOKEN") {
		t.Fatalf("events %+v", ev)
	}
}

// The fence never substitutes into a streamed body. Thus each placeholder
// in one -- also of a kind that the host carries -- is one that the buffered
// path refuses. The copy stops at it, and nothing from the placeholder on goes out.
func TestChunkedBodyPlaceholderStops(t *testing.T) {
	re, pol := testPolicy(t)
	cases := map[string]struct{ sni, ph string }{
		"own kind on core":     {"api.anthropic.com", "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"},
		"foreign kind on core": {"api.anthropic.com", "pf_a1b2c3d4e5f67890_GITHUB_TOKEN"},
		"unknown slot on core": {"api.anthropic.com", "pf_ffffffffffffffff_CLAUDE_OAT"},
		"uppercase slot hex":   {"api.anthropic.com", "pf_B0B1B2B3B4B5B6B7_CLAUDE_OAT"},
		"any on foreign host":  {"example.com", "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"},
	}
	for name, c := range cases {
		body := jsonBody(200<<10, "x") + strings.Repeat("f", 100<<10) + " " + c.ph + " " + strings.Repeat("t", 1000)
		raw := "POST /v1/messages HTTP/1.1\r\nHost: " + c.sni + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
		req := parseReq(t, raw)
		_, stream, err := DecideStream(Ctx{SNI: c.sni, TokenRE: re}, req, pol, labSlots())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if stream == nil {
			t.Fatalf("%s: chunked body must stream", name)
		}
		out, err := io.ReadAll(req.Body)
		if !errors.Is(err, ErrPlaceholderInStream) {
			t.Fatalf("%s: err %v", name, err)
		}
		if bytes.Contains(out, []byte("pf_")) || bytes.Contains(out, []byte("ttt")) || bytes.Contains(out, []byte(liveOAT())) {
			t.Fatalf("%s: emitted past the placeholder or a live value", name)
		}
	}
}

// OnInject reports each slot that the fence writes into the request: here
// the header. It reports nothing for the streamed body, which the fence never writes into.
func TestOnInjectReportsWrittenSlots(t *testing.T) {
	re, _ := tokenrules.LoadTokenRE(benchRoot() + "/vm/policy/key_prefixes.rules")
	pol, _ := corepolicy.Load(benchRoot() + "/vm/policy/core.hosts")
	ph := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
	body := jsonBody(300<<10, "x")
	raw := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer " + ph + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(body)
	req := parseReq(t, raw)
	var used []string
	ctx := Ctx{SNI: "api.anthropic.com", TokenRE: re, OnInject: func(slot string) { used = append(used, slot) }}
	if _, _, err := DecideStream(ctx, req, pol, labSlots()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatal(err)
	}
	if len(used) != 1 || used[0] != "b0b1b2b3b4b5b6b7" {
		t.Fatalf("header inject reported %v", used)
	}
}
