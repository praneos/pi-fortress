package httpwire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func readReq(raw string) (*Request, error) {
	return ReadRequest(bufio.NewReader(strings.NewReader(raw)))
}

func readResp(raw string) (*Response, error) {
	return ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false)
}

func TestDuplicateSingletonsRejected(t *testing.T) {
	for _, name := range []string{"Host", "Authorization", "Cookie", "host", "HOST"} {
		raw := "GET / HTTP/1.1\r\n" + name + ": a\r\n" + strings.ToLower(name) + ": b\r\n\r\n"
		if _, err := readReq(raw); !errors.Is(err, ErrDupHeader) {
			t.Fatalf("%s twice: err=%v", name, err)
		}
	}
	req, err := readReq("GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\nAccept-Encoding: br\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Values("accept-encoding"); len(got) != 2 || got[0] != "gzip" || got[1] != "br" {
		t.Fatalf("values %v", got)
	}
}

func TestRequestSetIndexRewritesThatField(t *testing.T) {
	req, err := readReq("GET / HTTP/1.1\r\nX-A: one\r\nX-A: two\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	req.SetIndex(1, "TWO")
	var out bytes.Buffer
	if _, err := req.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "GET / HTTP/1.1\r\nX-A: one\r\nX-A: TWO\r\n\r\n" {
		t.Fatalf("%q", out.String())
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestHeaderLineCappedBeforeAllocation(t *testing.T) {
	line := "X-Long: " + strings.Repeat("a", 1<<20) + "\r\n"
	src := &countingReader{r: strings.NewReader("GET / HTTP/1.1\r\n" + line + "\r\n")}
	_, err := ReadRequest(bufio.NewReader(src))
	if !errors.Is(err, ErrHeaderLimit) {
		t.Fatalf("err=%v", err)
	}
	if src.n > maxLineBytes+8192 {
		t.Fatalf("read %d bytes of a line that should stop near %d", src.n, maxLineBytes)
	}
	src = &countingReader{r: strings.NewReader("HTTP/1.1 200 OK\r\n" + line + "\r\n")}
	if _, err := ReadResponseHead(bufio.NewReader(src), false); !errors.Is(err, ErrHeaderLimit) {
		t.Fatalf("response err=%v", err)
	}
	if src.n > maxLineBytes+8192 {
		t.Fatalf("response read %d bytes", src.n)
	}
}

func TestResponseContentLengthMustAgree(t *testing.T) {
	if _, err := readResp("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err=%v", err)
	}
	resp, err := readResp("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok")
	if err != nil || resp.ContentLength != 2 {
		t.Fatalf("%v %+v", err, resp)
	}
}

// A request must not repeat Content-Length at all, also with the same
// value. The rewrite could emit a disagreeing pair because both fields
// were kept. SetBody updates the first in place and leaves the second.
// Thus "Content-Length:1" twice left as "Content-Length: 0" plus
// "Content-Length:1", and the next hop could frame the body differently
// from the fence. FuzzDecideAnyRequest found this.
func TestRequestContentLengthMayNotRepeat(t *testing.T) {
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
	} {
		if _, err := readReq(raw); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%q: err=%v", raw, err)
		}
	}
	if _, err := readReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx"); err != nil {
		t.Fatalf("a single Content-Length was refused: %v", err)
	}
}

// The response side deliberately still accepts an identical repeat. A
// response comes from the server that we chose to connect to, not from
// the agent. Its writer rewrites each Content-Length field, not only the
// first. Thus it cannot produce a disagreeing pair.
func TestResponseStillAcceptsIdenticalRepeat(t *testing.T) {
	resp, err := readResp("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok")
	if err != nil || resp.ContentLength != 2 {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestTransferEncodingMustBeChunked(t *testing.T) {
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		if _, err := readReq(raw); !errors.Is(err, ErrTransferEnc) {
			t.Fatalf("%q: err=%v", raw, err)
		}
	}
	for _, raw := range []string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		if _, err := readResp(raw); !errors.Is(err, ErrTransferEnc) {
			t.Fatalf("%q: err=%v", raw, err)
		}
	}
	if req, err := readReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked \r\n\r\n2\r\nok\r\n0\r\n\r\n"); err != nil || !req.Chunked {
		t.Fatalf("%v %+v", err, req)
	}
}

func TestInterimResponsesSkipped(t *testing.T) {
	raw := "HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	resp, err := ReadResponse(bufio.NewReader(strings.NewReader(raw)), 1<<20, false)
	if err != nil || resp.Code != 200 || string(resp.Body) != "ok" {
		t.Fatalf("%v %+v", err, resp)
	}
	if _, err := readResp("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"); !errors.Is(err, ErrUpgrade) {
		t.Fatalf("101 err=%v", err)
	}
	upgrade := "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: k\r\n\r\n\x81\x02hi"
	br := bufio.NewReader(strings.NewReader(upgrade))
	up, err := ReadUpgradeResponseHead(br)
	if err != nil || up.Code != 101 || up.Get("Sec-WebSocket-Accept") != "k" {
		t.Fatalf("asked-for 101: %v %+v", err, up)
	}
	if !up.NoBody || up.Stream != nil {
		t.Fatalf("101 claimed a body: nobody=%v stream=%v", up.NoBody, up.Stream)
	}
	if rest, _ := io.ReadAll(br); string(rest) != "\x81\x02hi" {
		t.Fatalf("bytes past the 101 lost: %q", rest)
	}
	if _, err := ReadUpgradeResponseHead(bufio.NewReader(strings.NewReader("HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno"))); err != nil {
		t.Fatalf("non-101 err=%v", err)
	}
	many := strings.Repeat("HTTP/1.1 103 Early Hints\r\n\r\n", maxInterim+1) + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	if _, err := readResp(many); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("interim flood err=%v", err)
	}
}

func TestResponseHeaderCountCapped(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	for i := 0; i <= maxRespHeaders; i++ {
		sb.WriteString("X-N: v\r\n")
	}
	sb.WriteString("Content-Length: 0\r\n\r\n")
	if _, err := readResp(sb.String()); !errors.Is(err, ErrTooManyHdr) {
		t.Fatalf("err=%v", err)
	}
	if _, err := readResp("HTTP/1.1 200 OK\r\n bad: fold\r\n\r\n"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("obs-fold err=%v", err)
	}
}

func TestChunkedTrailerBlockCapped(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("2\r\nok\r\n0\r\n")
	for sb.Len() < maxHeaderBytes+4096 {
		sb.WriteString("X-T: " + strings.Repeat("t", 1000) + "\r\n")
	}
	sb.WriteString("\r\n")
	_, err := io.ReadAll(newChunkedReader(bufio.NewReader(strings.NewReader(sb.String()))))
	if !errors.Is(err, ErrHeaderLimit) {
		t.Fatalf("err=%v", err)
	}
	got, err := io.ReadAll(newChunkedReader(bufio.NewReader(strings.NewReader("2\r\nok\r\n0\r\nX-T: a\r\n\r\n"))))
	if err != nil || string(got) != "ok" {
		t.Fatalf("%v %q", err, got)
	}
}

type endless struct{}

func (endless) Read(p []byte) (int, error) { return len(p), nil }

// Buffer refuses an oversized body after it reads at most one byte past
// the bound, whatever the origin declared. Thus a body of unknown length
// never costs more than max to find out.
func TestBufferReadsAtMostOnePastTheBound(t *testing.T) {
	const max = 1 << 10
	for name, cl := range map[string]int64{"close-delimited": -1, "declared small": 10} {
		t.Run(name, func(t *testing.T) {
			src := &countingReader{r: endless{}}
			resp := &Response{ContentLength: cl, Stream: src}
			if err := resp.Buffer(max); !errors.Is(err, ErrBodyLimit) {
				t.Fatalf("err=%v", err)
			}
			if src.n > max+1 {
				t.Fatalf("read %d bytes for a bound of %d", src.n, max)
			}
			if resp.Body != nil {
				t.Fatal("body kept after the limit")
			}
		})
	}
	t.Run("declared large", func(t *testing.T) {
		src := &countingReader{r: endless{}}
		resp := &Response{ContentLength: 50 << 20, Stream: src}
		if err := resp.Buffer(max); !errors.Is(err, ErrBodyLimit) {
			t.Fatalf("err=%v", err)
		}
		if src.n != 0 {
			t.Fatalf("read %d bytes of a body declared over the bound", src.n)
		}
	})
}

// The parser refuses a control byte at any location in the request head.
// HTAB and obs-text are not control bytes and still pass.
func TestRequestControlBytesRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"bare cr smuggles te": "POST / HTTP/1.1\r\nHost: a\r\nX-A: b\rTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
		"nul in value":        "POST / HTTP/1.1\r\nHost: a\r\nX-A: b\x00c\r\n\r\n",
		"nul in name":         "POST / HTTP/1.1\r\nHost: a\r\nX-A\x00: b\r\n\r\n",
		"del in value":        "GET / HTTP/1.1\r\nHost: a\r\nX-A: b\x7f\r\n\r\n",
		"bare cr in target":   "GET /a\rX: 1 HTTP/1.1\r\nHost: a\r\n\r\n",
		"nul in method":       "G\x00ET / HTTP/1.1\r\nHost: a\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadRequest(bufio.NewReader(strings.NewReader(raw))); !errors.Is(err, ErrBadRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for name, raw := range map[string]string{
		"htab in value":     "GET / HTTP/1.1\r\nHost: a\r\nX-A: b\tc\r\n\r\n",
		"obs-text in value": "GET / HTTP/1.1\r\nHost: a\r\nX-A: caf\xc3\xa9\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			var out bytes.Buffer
			if _, err := req.WriteTo(&out); err != nil || out.String() != raw {
				t.Fatalf("forwarded %q err=%v", out.String(), err)
			}
		})
	}
}

// A control byte in the head from an origin changes to a space. This
// occurs where WriteHead streams it and where WriteTo buffers it. Thus
// the client of the agent cannot read a header that this parser never
// saw. The bare-CR case is the important one: Python's http.client
// splits there, and the scrub uses Content-Encoding to decide on gzip.
func TestResponseControlBytesBlanked(t *testing.T) {
	for name, tc := range map[string]struct {
		raw, head string
		ctls      int
	}{
		"bare cr hides a header": {"HTTP/1.1 200 OK\r\nX-A: b\rContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 200 OK\r\nX-A: b Content-Encoding: gzip\r\n", 1},
		"nul and del in a value": {"HTTP/1.1 200 OK\r\nX-A: b\x00c\x7f\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 200 OK\r\nX-A: b c \r\n", 2},
		"cr in the reason":       {"HTTP/1.1 200 O\rK\x01\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 200 O K \r\n", 2},
		"esc in a value":         {"HTTP/1.1 200 OK\r\nX-A: \x1b[31mred\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 200 OK\r\nX-A:  [31mred\r\n", 1},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := ReadResponseHead(bufio.NewReader(strings.NewReader(tc.raw)), false)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if resp.CTLs != tc.ctls {
				t.Fatalf("CTLs=%d want %d", resp.CTLs, tc.ctls)
			}
			if resp.Get("Content-Encoding") != "" {
				t.Fatalf("the hidden header became a field: %q", resp.Get("Content-Encoding"))
			}
			var streamed bytes.Buffer
			if err := resp.WriteHead(&streamed, false); err != nil {
				t.Fatal(err)
			}
			if err := resp.Buffer(1 << 10); err != nil {
				t.Fatal(err)
			}
			var buffered bytes.Buffer
			if _, err := resp.WriteTo(&buffered); err != nil {
				t.Fatal(err)
			}
			for what, out := range map[string]string{"WriteHead": streamed.String(), "WriteTo": buffered.String()} {
				if !strings.HasPrefix(out, tc.head) {
					t.Fatalf("%s wrote %q, want it to start %q", what, out, tc.head)
				}
				if hasCTL(strings.ReplaceAll(out, "\r\n", "")) {
					t.Fatalf("%s forwarded a control byte: %q", what, out)
				}
			}
		})
	}
	// HTAB and obs-text are not control bytes: they go forward unchanged.
	raw := "HTTP/1.1 200 OK\r\nX-A: b\tcaf\xc3\xa9\r\nContent-Length: 0\r\n\r\n"
	resp, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false)
	if err != nil || resp.CTLs != 0 {
		t.Fatalf("err=%v CTLs=%d", err, resp.CTLs)
	}
	var out bytes.Buffer
	if _, err := resp.WriteTo(&out); err != nil || out.String() != raw {
		t.Fatalf("forwarded %q err=%v", out.String(), err)
	}
}

// A response header name has no repair. If blanked, "X\rContent-Encoding"
// would still be one name here and two lines to a client that splits
// before the colon. A name must be a token (an inner space is tolerated,
// as the net/http client tolerates it), or the response is refused.
func TestResponseFieldNameMustBeAToken(t *testing.T) {
	for name, h := range map[string]string{
		"bare cr in name": "X\rContent-Encoding: gzip",
		"nul in name":     "X-A\x00: b",
		"separator":       "X(A): b",
		"obs-text":        "Caf\xc3\xa9: b",
		"leading space":   " X-A: b",
		"space before :":  "X-A : b",
		"empty name":      ": b",
	} {
		t.Run(name, func(t *testing.T) {
			raw := "HTTP/1.1 200 OK\r\n" + h + "\r\nContent-Length: 0\r\n\r\n"
			if _, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false); !errors.Is(err, ErrBadRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	raw := "HTTP/1.1 200 OK\r\nX Legacy Name: b\r\nContent-Length: 0\r\n\r\n"
	if _, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false); err != nil {
		t.Fatalf("an inner space, which net/http tolerates, was refused: %v", err)
	}
}

// TestStatusLineValidated: strconv.Atoi is not the status-code grammar
// (it takes a sign, leading zeros or any digit count), and the protocol
// token was not checked. Code decides whether a body follows (204, 304,
// 1xx), so both are framing inputs.
func TestStatusLineValidated(t *testing.T) {
	for name, raw := range map[string]string{
		"negative code":      "HTTP/1.1 -10 x\r\n\r\n",
		"four digit code":    "HTTP/1.1 0200 OK\r\nContent-Length: 1\r\n\r\na",
		"two digit code":     "HTTP/1.1 20 OK\r\nContent-Length: 1\r\n\r\na",
		"five digit code":    "HTTP/1.1 99999 OK\r\nContent-Length: 1\r\n\r\na",
		"bad protocol":       "XYZ 200 OK\r\nContent-Length: 1\r\n\r\na",
		"lowercase protocol": "http/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readResp(raw); !errors.Is(err, ErrBadRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	resp, err := readResp("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
	if err != nil || resp.Code != 200 || resp.Proto != "HTTP/1.1" {
		t.Fatalf("%v %+v", err, resp)
	}
	resp, err = readResp("HTTP/1.0 204 No Content\r\n\r\n")
	if err != nil || resp.Code != 204 {
		t.Fatalf("%v %+v", err, resp)
	}
}

// The target of CONNECT is host:port and nothing else. The fence
// classifies policy on the target and forwards it verbatim.
func TestConnectAuthority(t *testing.T) {
	for _, target := range []string{"a.example:443", "192.0.2.1:8443", "a_b.example:1"} {
		raw := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
		if _, err := ReadRequest(bufio.NewReader(strings.NewReader(raw))); err != nil {
			t.Fatalf("%q: %v", target, err)
		}
	}
	for _, target := range []string{"a.example:443:9", "a.example:x", "a.example:", ":443", "a.example", "u@a.example:443", "[::1]:443", "a.example:443/x", "a.example:123456", "a%41.example:443"} {
		raw := "CONNECT " + target + " HTTP/1.1\r\nHost: a.example\r\n\r\n"
		if _, err := ReadRequest(bufio.NewReader(strings.NewReader(raw))); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%q: err=%v", target, err)
		}
	}
}
