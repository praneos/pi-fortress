package fence

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"strconv"
	"strings"
	"testing"
)

// gzipBytes and zlibBytes make the request bodies that these tests send.
// These are the only two codings that the fence undoes (docs/fence.md
// 5.3b), alone and stacked.
func gzipBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodedPost(host, contentEncoding string, body []byte) string {
	var enc string
	if contentEncoding != "" {
		enc = "Content-Encoding: " + contentEncoding + "\r\n"
	}
	return "POST /x HTTP/1.1\r\nHost: " + host + "\r\n" + enc +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
}

// A live token of a supported format, hidden inside a gzip-compressed
// body, got to the origin before, without a strip and without a log (the
// gap that docs/fence.md 5.3 named). Now it refuses the full request: the
// outgoing bytes are compressed, and the fence never encodes again what
// it edits.
func TestGzipRequestBodyLiveTokenRefused(t *testing.T) {
	tok := "ghp_" + strings.Repeat("A", 36)
	raw := encodedPost("example.com", "gzip", gzipBytes(t, []byte(`{"note":"`+tok+`"}`)))
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseEncodedBodyToken || rs[0].Where != "body" {
		t.Fatalf("%+v", rs)
	}
}

// A stored live value, not only a shape that the prefix rules know, gets
// the same refusal: the scan walks idx.Lives the same way as the strip
// pass of a buffered body. The shape of this OAT also matches the
// anthropic_oat prefix rule. Thus it gets two refusals here, exactly as
// strips() of a buffered plaintext body would report two events for it -- one per matcher.
func TestGzipRequestBodyStoredLiveValueRefused(t *testing.T) {
	oat := "sk-ant-oat01-" + strings.Repeat("A", 64) // labSlots' slot b live value
	raw := encodedPost("example.com", "gzip", gzipBytes(t, []byte(`{"leak":"`+oat+`"}`)))
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	foundSlot := false
	for _, r := range rs {
		if r.Cause != CauseEncodedBodyToken || r.Where != "body" {
			t.Fatalf("%+v", rs)
		}
		foundSlot = foundSlot || (r.Slot == "b0b1b2b3b4b5b6b7" && r.Kind == "CLAUDE_OAT")
	}
	if !foundSlot {
		t.Fatalf("%+v", rs)
	}
}

// The fence forwards a clean gzip body exactly as the agent sent it. The
// decode is only for the scan, and nothing here is ever encoded again.
func TestGzipRequestBodyCleanForwardedByteIdentical(t *testing.T) {
	raw := encodedPost("example.com", "gzip", gzipBytes(t, []byte(`{"note":"nothing to see"}`)))
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != raw {
		t.Fatalf("body rewritten:\ngot  %q\nwant %q", out.String(), raw)
	}
}

// A placeholder decoded from a gzip body falls under the placeholder-
// outside-header rule (5.2b), the same as a placeholder in a buffered
// plaintext body. The fence never substitutes into a body other than the
// body of the refresh token, and never encodes again here in any case.
// Thus no placement is safe.
func TestPlaceholderInsideGzipBodyRefused(t *testing.T) {
	body := gzipBytes(t, []byte(`{"note":"pf_a1b2c3d4e5f67890_GITHUB_TOKEN"}`))
	raw := encodedPost("api.github.com", "gzip", body)
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "api.github.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseOutsideHeader || rs[0].Slot != "a1b2c3d4e5f67890" || rs[0].Kind != "GITHUB_TOKEN" || rs[0].Where != "body" {
		t.Fatalf("%+v", rs)
	}
}

// stdlib does not undo the br coding, so the scan cannot read through it.
// The fence refuses it and does not forward it opaque. The response side
// (5.3b) is different: it has no choice after the head is on the wire.
func TestUnsupportedRequestEncodingRefused(t *testing.T) {
	raw := encodedPost("example.com", "br", []byte("opaque brotli bytes"))
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseEncodedBody || rs[0].Where != "body" {
		t.Fatalf("%+v", rs)
	}
}

// A decoded size past maxDecodedBody ends the request, as the inflate limit
// of the response side ends a reply. The fence refuses a compression bomb,
// and does not expand it into memory.
func TestGzipRequestBodyBombRefused(t *testing.T) {
	raw := encodedPost("example.com", "gzip", gzipBytes(t, make([]byte, maxDecodedBody+1)))
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseEncodedBody {
		t.Fatalf("%+v", rs)
	}
}

// The fence undoes stacked codings in reverse order of application. Here
// gzip was applied, then deflate over the gzip bytes, as
// "Content-Encoding: gzip, deflate" says.
func TestStackedGzipDeflateRequestBody(t *testing.T) {
	plain := []byte(`{"note":"nothing to see"}`)
	stacked := zlibBytes(t, gzipBytes(t, plain))
	t.Run("clean forwards unchanged", func(t *testing.T) {
		raw := encodedPost("example.com", "gzip, deflate", stacked)
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if _, err := req.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		if out.String() != raw {
			t.Fatalf("body rewritten:\ngot  %q\nwant %q", out.String(), raw)
		}
	})
	t.Run("token behind both layers refuses", func(t *testing.T) {
		tok := "ghp_" + strings.Repeat("B", 36)
		hidden := zlibBytes(t, gzipBytes(t, []byte(`{"note":"`+tok+`"}`)))
		raw := encodedPost("example.com", "gzip, deflate", hidden)
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
		rs := refusalsOf(t, err)
		if len(rs) != 1 || rs[0].Cause != CauseEncodedBodyToken {
			t.Fatalf("%+v", rs)
		}
	})
	t.Run("past the layer limit refuses", func(t *testing.T) {
		raw := encodedPost("example.com", "gzip, deflate, gzip", stacked)
		req := parseReq(t, raw)
		_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
		rs := refusalsOf(t, err)
		if len(rs) != 1 || rs[0].Cause != CauseEncodedBody {
			t.Fatalf("%+v", rs)
		}
	})
}

// A body too large to buffer at the start also cannot be decoded. Thus the
// fence refuses it, and does not stream it through unscanned.
func TestOversizedEncodedBodyRefused(t *testing.T) {
	body := gzipBytes(t, bytes.Repeat([]byte("a"), 64))
	pad := make([]byte, maxBodyBuf-len(body)+1)
	for i := range pad {
		pad[i] = 'x'
	}
	raw := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)+len(pad)) + "\r\n\r\n" + string(body) + string(pad)
	req := parseReq(t, raw)
	_, err := Decide(Ctx{SNI: "example.com", TokenRE: mustRE(t)}, req, loadPol(t), labSlots())
	rs := refusalsOf(t, err)
	if len(rs) != 1 || rs[0].Cause != CauseEncodedBody {
		t.Fatalf("%+v", rs)
	}
}
