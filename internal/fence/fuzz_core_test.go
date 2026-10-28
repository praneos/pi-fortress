package fence

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"pi-fortress/internal/httpwire"
	"pi-fortress/internal/placeholder"
)

// FuzzCoreInjects: on a core host, the allowed placeholder comes out as its
// live value in a header, and a live value of a different kind strips. The
// fence refuses the same placeholder in the URL or the body at the start,
// or ends the copy in a chunked body. Its live value never gets to the wire.
func FuzzCoreInjects(f *testing.F) {
	f.Add("/v1/messages", "Bearer ", `{"model":"x"}`, uint16(2), false)
	f.Add("/v1/messages?k=", "", `{"a":"b"}`, uint16(9), true)
	f.Add("/v1/messages", "basic \t", `{"model":"x"}`, uint16(4), false)
	f.Add("/v1/messages", "Basic eDo=", `{}`, uint16(5), true)
	f.Add("/v1/messages", "Bearer ", `{"model":"x"}`, uint16(1), true)
	re, pol := testPolicy(f)
	f.Fuzz(func(t *testing.T, target, hdr, body string, where uint16, chunkedBody bool) {
		if target == "" || strings.ContainsAny(target, " \r\n") || strings.ContainsAny(hdr, "\r\n") {
			return
		}
		phOK := "pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT"
		// No placeholder of a foreign kind here. One anywhere in the
		// request refuses the full request, so it would end each case
		// before the substitution that this fuzzer tests.
		// TestKindIsolationSameBlob tests that half. A live value of a
		// foreign kind is still in, because it strips and does not refuse.
		liveOther := "lab_fence_github"
		// 0: also in the URL; 1: also in the body; 2: the header only.
		mode := where % 3
		// A placeholder followed by a lowercase letter is not a placeholder
		// (regexp boundary rule), so frame the inserted one with spaces.
		pos := int(where) % (len(body) + 1)
		ins := " "
		if mode == 1 {
			ins = " " + phOK + " "
		}
		body = body[:pos] + ins + body[pos:] + " " + liveOther + " " + canaryLive
		hdr += phOK
		if mode == 0 {
			target += phOK
		}
		raw := fuzzPost(target, "api.anthropic.com", "Authorization", hdr, body, chunkedBody)
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		// The fence buffers the body of a refresh request and each body of a
		// known size up to maxBodyBuf (plan). It refuses a placeholder in a
		// buffered body at the start. In a streamed body, the copy ends at
		// the placeholder.
		buffered := IsOAuthPath(req.Target) || (!req.Chunked && req.ContentLength >= 0 && req.ContentLength <= maxBodyBuf)
		_, _, err = DecideStream(Ctx{SNI: "api.anthropic.com", TokenRE: re}, req, pol, canarySlots())
		if mode == 0 || (mode == 1 && buffered) {
			var ref *RefusedError
			if !errors.As(err, &ref) {
				t.Fatalf("a placeholder outside the header was not refused: %v\nraw=%q", err, raw)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode == 1 {
			out, err := io.ReadAll(req.Body)
			if !errors.Is(err, ErrPlaceholderInStream) || bytes.Contains(out, []byte(liveOAT())) || forwardsPlaceholder(out) {
				t.Fatalf("a chunked body placeholder: %v\nraw=%q\nout=%q", err, raw, out)
			}
			return
		}
		o := decodedWire(t, req, raw)
		if bytes.Contains(o, []byte(canaryLive)) {
			t.Fatalf("canary leaked\nraw=%q\nout=%q", raw, o)
		}
		if bytes.Contains(o, []byte(phOK)) {
			t.Fatalf("allowed placeholder survived\nraw=%q\nout=%q", raw, o)
		}
		if !bytes.Contains(o, []byte(liveOAT())) {
			t.Fatalf("live value missing from the header\nraw=%q\nout=%q", raw, o)
		}
		if bytes.Contains(o, []byte(liveOther)) {
			t.Fatalf("live value of a disallowed kind leaked\nraw=%q\nout=%q", raw, o)
		}
	})
}

// FuzzDecideAnyRequest: the fence rewrites all input that parses as a
// request without a panic, and the result parses again. The fence never
// changes the Host of a request that it forwards: the origin routes by
// that Host, and the broker decided on it (FuzzParanoidHostDecision). The
// same applies to Connection and Upgrade: the broker decided on a
// WebSocket from them.
func FuzzDecideAnyRequest(f *testing.F) {
	f.Add([]byte("GET /x HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer pf_b0b1b2b3b4b5b6b7_CLAUDE_OAT\r\n\r\n"), "api.anthropic.com")
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd"), "example.com")
	f.Add([]byte("GET /o/r.git/info/refs HTTP/1.1\r\nHost: github.com\r\nAuthorization: Basic eC1hY2Nlc3MtdG9rZW46cGZfYTFiMmMzZDRlNWY2Nzg5MF9HSVRIVUJfVE9LRU4=\r\n\r\n"), "github.com")
	f.Add([]byte("POST /o/r.git/git-receive-pack HTTP/1.1\r\nHost: evil.example\r\nAuthorization: basic\t cGZfYTFiMmMzZDRlNWY2Nzg5MF9HSVRIVUJfVE9LRU46eA\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"), "evil.example")
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: pf-core-echo.test\r\nX-A: pf_d0d1d2d3d4d5d6d7_CANARY\r\nContent-Length: 22\r\n\r\ncanary-live-7f3a9c2e51"), "pf-core-echo.test")
	f.Add([]byte("GET / HTTP/1.1\r\nHost: lab_fence_github.pf-core-echo.test\r\nAuthorization: Bearer pf_a1b2c3d4e5f67890_GITHUB_TOKEN\r\n\r\n"), "pf-core-echo.test")
	f.Add([]byte("GET / HTTP/1.1\r\nHost: canary-live-7f3a9c2e51.evil.example:443\r\n\r\n"), "evil.example")
	f.Add([]byte("GET / HTTP/1.1\r\nHost: pf-core-echo.test\r\nUpgrade: websocket\r\nConnection: Upgrade, lab_fence_github\r\n\r\n"), "pf-core-echo.test")
	f.Add([]byte("GET / HTTP/1.1\r\nHost: evil.example\r\nUpgrade: canary-live-7f3a9c2e51\r\nConnection: Upgrade\r\n\r\n"), "evil.example")
	re, pol := testPolicy(f)
	f.Fuzz(func(t *testing.T, raw []byte, sni string) {
		req, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		kept := map[string][]string{}
		for _, name := range []string{"Host", "Connection", "Upgrade"} {
			kept[name] = slices.Clone(req.Values(name))
		}
		if _, _, err := DecideStream(Ctx{SNI: sni, TokenRE: re}, req, pol, canarySlots()); err != nil {
			return
		}
		for name, was := range kept {
			if got := req.Values(name); !slices.Equal(got, was) {
				t.Fatalf("the fence changed %s %q to %q\nin=%q", name, was, got, raw)
			}
		}
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			return
		}
		// The shipped policy binds CANARY to no host. Its live value never
		// goes out, for any host.
		if bytes.Contains(out.Bytes(), []byte(canaryLive)) {
			t.Fatalf("canary on the wire\nin=%q\nout=%q", raw, out.Bytes())
		}
		again, err := httpwire.ReadRequest(bufio.NewReader(&out))
		if err != nil {
			t.Fatalf("rewritten request unparseable: %v\nin=%q\nout=%q", err, raw, out.Bytes())
		}
		_, _ = io.Copy(io.Discard, again.Body)
	})
}

// decodedWire writes the rewritten request, parses it back, and returns
// the head plus the decoded body. Thus chunk boundaries cannot hide or
// split a value.
func decodedWire(t *testing.T, req *httpwire.Request, raw string) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	wire := out.Bytes()
	again, err := httpwire.ReadRequest(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatalf("rewritten request unparseable: %v\nraw=%q\nout=%q", err, raw, wire)
	}
	body, err := io.ReadAll(again.Body)
	if err != nil {
		t.Fatalf("rewritten body unreadable: %v\nraw=%q\nout=%q", err, raw, wire)
	}
	if !again.Chunked && again.ContentLength != int64(len(body)) {
		t.Fatalf("content-length %d but body %d\nraw=%q\nout=%q", again.ContentLength, len(body), raw, wire)
	}
	var head bytes.Buffer
	head.WriteString(again.Method + " " + again.Target + "\n")
	for _, f := range again.Fields {
		head.WriteString(f.Name + ": " + f.Value + "\n")
	}
	return append(head.Bytes(), body...)
}

// FuzzStreamNeverForwardsPlaceholder: a placeholder that the stream cannot
// substitute never gets to the wire, for any location and any body framing.
// The read that would emit it fails instead.
func FuzzStreamNeverForwardsPlaceholder(f *testing.F) {
	f.Add(`{"model":"x"}`, uint16(2), true, uint8(0))
	f.Add(strings.Repeat("z", 1<<20+16), uint16(9), false, uint8(1))
	re, pol := testPolicy(f)
	bad := []string{"pf_a1b2c3d4e5f67890_GITHUB_TOKEN", "pf_ffffffffffffffff_CLAUDE_OAT", "pf_ffffffffffffffff_CLAUDE_ORT"}
	f.Fuzz(func(t *testing.T, body string, where uint16, chunkedBody bool, which uint8) {
		ph := bad[int(which)%len(bad)]
		pos := int(where) % (len(body) + 1)
		body = body[:pos] + " " + ph + " " + body[pos:]
		if !chunkedBody && len(body) <= maxBodyBuf {
			body += strings.Repeat("p", maxBodyBuf+1-len(body))
		}
		raw := fuzzPost("/v1/messages", "api.anthropic.com", "X-Fuzz", "v", body, chunkedBody)
		req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		_, stream, err := DecideStream(Ctx{SNI: "api.anthropic.com", TokenRE: re}, req, pol, labSlots())
		if err != nil {
			t.Fatal(err)
		}
		if stream == nil {
			t.Fatal("body must stream")
		}
		out, err := io.ReadAll(req.Body)
		if !errors.Is(err, ErrPlaceholderInStream) {
			t.Fatalf("err %v\nout=%q", err, out)
		}
		if forwardsPlaceholder(out) {
			t.Fatalf("placeholder forwarded\nout=%q", out)
		}
	})
}

// forwardsPlaceholder reports a placeholder in out, with the scanner that
// the stream guard uses. A test for the bytes "pf_" also finds StripRepl
// ("pf_stripped"), which the fence writes in place of each live value
// that it strips. That marker is not a placeholder.
func forwardsPlaceholder(out []byte) bool {
	return len(placeholder.FindPlaceholderSpans(out)) > 0
}
