package fence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// nestedJSON is a JSON string of about n bytes that noteJSONBody unescapes
// in each of its jsonRounds rounds. Each round gives back nearly all of it.
func nestedJSON(n int) []byte {
	s := strings.Repeat("A", n)
	for range jsonRounds {
		b, _ := json.Marshal(s + `\`)
		s = string(b)
	}
	return []byte(s)
}

// The scan of a buffered body takes from Ctx.Reserve what it makes past
// the bytes on the wire: each decoded byte, and each unescaped JSON
// string. A gzip body of 16 KiB decodes to 8 MiB, and four rounds of
// nested escapes make that 32 MiB more. Before, only the 16 KiB took from
// the budget, and the fence held about 115 MiB for that one request. A few
// such requests at the same time took the broker past its memory limit.
func TestBufferedBodyScanTakesBudget(t *testing.T) {
	for _, c := range []struct {
		name, enc string
		body      []byte
		min       int64
	}{
		{"gzip", "gzip", gzipBytes(t, nestedJSON(maxDecodedBody-64)), (jsonRounds + 1) * (maxDecodedBody - 64)},
		{"deflate", "deflate", zlibBytes(t, make([]byte, maxDecodedBody-64)), maxDecodedBody - 64},
		{"plain", "", nestedJSON(maxBodyBuf - 64), (jsonRounds + 1) * (maxBodyBuf - 64)},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := parseReq(t, encodedPost("example.com", c.enc, c.body))
			var reserved int64
			ctx := Ctx{SNI: "example.com", TokenRE: mustRE(t), Reserve: func(n int64) bool { reserved += n; return true }}
			if _, err := Decide(ctx, req, loadPol(t), labSlots()); err != nil {
				t.Fatal(err)
			}
			if reserved < c.min {
				t.Fatalf("wire %d B: reserved %d B, want at least %d B", len(c.body), reserved, c.min)
			}
		})
	}
}

// When the budget has no room for the decode or the unescape, the request
// gets ErrBufferBudget: the busy answer, not a refusal of the body. The
// same body in a budget with room goes through.
func TestBufferedBodyScanOverBudget(t *testing.T) {
	for _, c := range []struct {
		name, enc string
		body      []byte
	}{
		{"decode", "gzip", gzipBytes(t, make([]byte, maxDecodedBody-64))},
		{"unescape", "", nestedJSON(maxBodyBuf / 2)},
	} {
		t.Run(c.name, func(t *testing.T) {
			left := int64(maxBodyBuf)
			ctx := Ctx{SNI: "example.com", TokenRE: mustRE(t), Reserve: func(n int64) bool {
				if n > left {
					return false
				}
				left -= n
				return true
			}}
			_, err := Decide(ctx, parseReq(t, encodedPost("example.com", c.enc, c.body)), loadPol(t), labSlots())
			if !errors.Is(err, ErrBufferBudget) {
				t.Fatalf("err %v, want ErrBufferBudget", err)
			}
			ctx.Reserve = func(int64) bool { return true }
			if _, err := Decide(ctx, parseReq(t, encodedPost("example.com", c.enc, c.body)), loadPol(t), labSlots()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
