package httpwire

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestChunkedEdgeBytesPinned pins which bytes the chunk extension and the
// trailer block accept.
func TestChunkedEdgeBytesPinned(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"ext_tab", "1;a=\tb\r\na\r\n0\r\n\r\n", true},
		{"ext_del", "1;a=\x7f\r\na\r\n0\r\n\r\n", false},
		{"ext_nul", "1;\x00\r\na\r\n0\r\n\r\n", false},
		{"ext_high_byte", "1;\xc3\xa9\r\na\r\n0\r\n\r\n", true},
		{"trailer_ok", "0\r\nX-A: b\r\n\r\n", true},
		{"trailer_value_tab", "0\r\nX-A: b\tc\r\n\r\n", true},
		{"trailer_value_empty", "0\r\nX-A:\r\n\r\n", true},
		{"trailer_value_del", "0\r\nX-A: b\x7f\r\n\r\n", false},
		{"trailer_value_high_byte", "0\r\nX-A: \xc3\xa9\r\n\r\n", true},
		{"trailer_name_empty", "0\r\n: b\r\n\r\n", false},
		{"trailer_name_leading_space", "0\r\n X-A: b\r\n\r\n", false},
		{"trailer_name_trailing_space", "0\r\nX-A : b\r\n\r\n", false},
		{"trailer_name_slash", "0\r\nX/A: b\r\n\r\n", false},
		{"trailer_name_tchars", "0\r\n!#$%&'*+-.^_`|~09az: b\r\n\r\n", true},
		{"trailer_no_colon", "0\r\nXA\r\n\r\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := io.ReadAll(newChunkedReader(bufio.NewReader(strings.NewReader(c.raw))))
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && err != ErrBadRequest {
				t.Fatalf("got %q, %v; want ErrBadRequest", b, err)
			}
		})
	}
}

// TestTrailerFollowsNetHTTP pins the two trailer rules of net/http, in a
// request and in a response. A Trailer field must not name
// Content-Length, Transfer-Encoding or Trailer. The trailer block, with
// the empty line that ends it, must fit in 4096 bytes. At each edge,
// httpwire and net/http give the same answer.
func TestTrailerFollowsNetHTTP(t *testing.T) {
	// block is a trailer block of exactly n bytes: one field and the empty
	// line.
	block := func(n int) string {
		return "X: " + strings.Repeat("a", n-7) + "\r\n\r\n"
	}
	cases := []struct {
		name, head, body string
		ok               bool
	}{
		{"names_content_length", "Trailer: Content-Length\r\n", "0\r\n\r\n", false},
		{"names_transfer_encoding", "Trailer: x, transfer-encoding\r\n", "0\r\n\r\n", false},
		{"names_trailer", "Trailer: X-Sum,TRAILER\r\n", "0\r\n\r\n", false},
		{"names_other_fields", "Trailer: X-Sum, X-Len\r\n", "0\r\nX-Sum: 1\r\nX-Len: 2\r\n\r\n", true},
		{"block_4096", "", "0\r\n" + block(4096), true},
		{"block_4097", "", "0\r\n" + block(4097), false},
		{"block_5000", "", "0\r\n" + block(5000), false},
		{"block_800_lines", "", "0\r\n" + strings.Repeat("X: a\r\n", 800) + "\r\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n" + c.head + "\r\n" + c.body
			resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" + c.head + "\r\n" + c.body
			hwReq, goReq := wholeRequest(req)
			hwResp, goResp := wholeResponse(resp)
			if hwReq != c.ok || goReq != c.ok || hwResp != c.ok || goResp != c.ok {
				t.Fatalf("want %v; request: httpwire %v, net/http %v; response: httpwire %v, net/http %v",
					c.ok, hwReq, goReq, hwResp, goResp)
			}
		})
	}
}

// wholeRequest reports whether httpwire and net/http each read the head
// and the full body of raw with no error.
func wholeRequest(raw string) (hw, gh bool) {
	if r, err := ReadRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
		_, err = io.ReadAll(r.Body)
		hw = err == nil
	}
	if r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
		_, err = io.ReadAll(r.Body)
		gh = err == nil
	}
	return hw, gh
}

// wholeResponse is wholeRequest for a response.
func wholeResponse(raw string) (hw, gh bool) {
	if r, err := ReadResponseHead(bufio.NewReader(strings.NewReader(raw)), false); err == nil {
		_, err = io.ReadAll(r.Stream)
		hw = err == nil
	}
	if r, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil); err == nil {
		_, err = io.ReadAll(r.Body)
		gh = err == nil
	}
	return hw, gh
}
