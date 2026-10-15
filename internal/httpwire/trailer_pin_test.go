package httpwire

import (
	"bufio"
	"io"
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
