package broker

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/preamble"
)

func gzipReqBody(t *testing.T, p string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := io.WriteString(w, p); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipPost(host string, body []byte) string {
	return "POST /x HTTP/1.1\r\nHost: " + host + "\r\nContent-Encoding: gzip\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
}

// Before, a raw token of a supported format hidden in a gzip-compressed
// request body reached the origin unstripped and unlogged (docs/fence.md
// 5.3, the gap that this closes). Now the broker never dials the origin
// at all: the single §5.2b refusal, and a strip.jsonl row so that
// `pf alert` posts it.
func TestGzipRequestBodyTokenRefusedEndToEnd(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	b.Logs = &jsonl.Writer{StripPath: filepath.Join(dir, "strip.jsonl")}
	var dialed bool
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) { dialed = true })
	tok := "ghp_" + strings.Repeat("A", 36)
	body := gzipReqBody(t, `{"note":"`+tok+`"}`)
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	resp := roundtrip(t, b, p, gzipPost("example.com", body))
	if resp != RefusedBody {
		t.Fatalf("body %q", resp)
	}
	if dialed {
		t.Fatal("the origin was dialed for a request that should have been refused before it went out")
	}
	rows, _ := os.ReadFile(b.Logs.StripPath)
	if !strings.Contains(string(rows), `"cause":"encoded_body_token"`) {
		t.Fatalf("no strip row for the decoded hit: %q", rows)
	}
}

// A clean gzip body reaches the origin exactly as the agent sent it. The
// broker decodes only for the scan, and this path never re-encodes.
func TestGzipRequestBodyCleanForwardedByteIdenticalEndToEnd(t *testing.T) {
	b, _ := testBroker(t)
	body := gzipReqBody(t, `{"note":"nothing to see"}`)
	var gotBody []byte
	var gotEncoding string
	fakeUpstream(t, b, func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	})
	p := preamble.Preamble{SNI: "example.com", OrigDst: netip.MustParseAddrPort("93.184.216.34:443")}
	resp, _ := roundtripStream(t, b, p, gzipPost("example.com", body))
	if resp.Code != 200 {
		t.Fatalf("code %d", resp.Code)
	}
	if gotEncoding != "gzip" || !bytes.Equal(gotBody, body) {
		t.Fatalf("origin saw Content-Encoding %q and %d bytes, want gzip and the original %d compressed bytes unchanged", gotEncoding, len(gotBody), len(body))
	}
}
